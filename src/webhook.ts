import type { IncomingMessage, ServerResponse } from "node:http";
import { getWecomRuntime } from "./runtime.js";
import { wecomClient, type SimpleWecomMessage } from "./client.js";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { verifySignature, decryptMessage, calculateSignature } from "./crypto.js";
import { parseWeComMessage, formatMessageForClawdbot } from "./message-parser.js";
import { XMLParser } from "fast-xml-parser";
import { parseMultipart } from "./multipart.js";
import { wecomOfficialAPI } from "./official-api.js";
import { recognizeVoice } from "./tencent-asr.js";
import { runInSessionContext } from "./session-context.js";

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

/**
 * HTTP webhook handler for WeCom messages
 * Returns true if the request was handled, false otherwise
 */
export async function handleWecomWebhookRequest(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const url = new URL(req.url ?? "/", "http://localhost");

  // Only handle /wecom/message path
  if (url.pathname !== "/plugins/wecom/message") {
    return false;
  }

  const runtime = getWecomRuntime();
  const cfg = await runtime.config.loadConfig();
  const wecom = cfg.channels?.["wecom"];

  if (!wecom) {
    res.statusCode = 500;
    res.end("WeCom channel not configured");
    return true;
  }

  const config = wecom as any;
  const accountId = "default"; // TODO: support multiple accounts

  // ===== GET request: URL verification (for WeCom initial setup) =====
  if (req.method === "GET") {
    const msgSignature = url.searchParams.get("msg_signature");
    const timestamp = url.searchParams.get("timestamp");
    const nonce = url.searchParams.get("nonce");
    const echostr = url.searchParams.get("echostr");

    const token = config.token;

    if (!token) {
      res.statusCode = 500;
      res.end("Token not configured");
      return true;
    }

    if (!msgSignature || !timestamp || !nonce || !echostr) {
      res.statusCode = 400;
      res.end("Missing required parameters");
      return true;
    }

    try {
      // Verify signature
      const expectedSignature = calculateSignature(token, timestamp, nonce, echostr);
      if (expectedSignature !== msgSignature) {
        res.statusCode = 403;
        res.end("Invalid signature");
        return true;
      }

      // Decrypt echostr and return
      const encodingAESKey = config.encodingAESKey;
      const corpid = config.corpid;

      if (!encodingAESKey || !corpid) {
        res.statusCode = 500;
        res.end("encodingAESKey or corpid not configured");
        return true;
      }

      const decryptedEchoStr = decryptMessage(encodingAESKey, echostr, corpid);
      res.statusCode = 200;
      res.setHeader("Content-Type", "text/plain");
      res.end(decryptedEchoStr);
    } catch (error) {
      console.error("WeChat verification failed:", error);
      res.statusCode = 500;
      res.end(String(error));
    }
    return true;
  }

  // ===== POST request: receive messages =====
  if (req.method !== "POST") {
    res.statusCode = 405;
    res.end("Method Not Allowed");
    return true;
  }

  try {
    const contentType = req.headers["content-type"] || "";

    // Detect if this is an encrypted WeCom message (XML format)
    const isEncryptedWeComMessage =
      contentType.includes("text/xml") ||
      contentType.includes("application/xml") ||
      url.searchParams.has("msg_signature");

    if (isEncryptedWeComMessage) {
      // ===== Handle encrypted WeCom message =====
      await handleEncryptedWeComMessage(req, res, url, config, accountId, cfg);
    } else {
      // ===== Handle legacy JSON/Multipart format (backwards compatible) =====
      await handleLegacyMessage(req, res, contentType, config, accountId, cfg);
    }
  } catch (e) {
    console.error("WeCom handler error:", e);
    if (!res.writableEnded) {
      res.statusCode = 500;
      res.end(String(e));
    }
  }

  return true;
}

/**
 * Handle encrypted WeCom message
 */
async function handleEncryptedWeComMessage(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  config: any,
  accountId: string,
  cfg: any,
) {
  // 1. Get verification parameters
  const msgSignature = url.searchParams.get("msg_signature");
  const timestamp = url.searchParams.get("timestamp");
  const nonce = url.searchParams.get("nonce");

  const token = config.token;
  const encodingAESKey = config.encodingAESKey;
  const corpid = config.corpid;

  if (!token || !encodingAESKey || !corpid) {
    res.statusCode = 500;
    res.end("Token, encodingAESKey or corpid not configured");
    return;
  }

  if (!msgSignature || !timestamp || !nonce) {
    res.statusCode = 400;
    res.end("Missing signature parameters");
    return;
  }

  // 2. Read request body (XML)
  const rawBody = await readBody(req);
  const xmlString = rawBody.toString("utf8");

  const verbose = config.verbose === true;

  if (verbose) {
    console.log("=== Received WeChat Encrypted Message ===");
    console.log("XML:", xmlString);
  }

  // 3. Parse XML to extract Encrypt field
  const parser = new XMLParser({
    ignoreAttributes: false,
    parseTagValue: false,
    trimValues: true,
  });

  const xmlObj = parser.parse(xmlString);
  const encryptedMsg = xmlObj.xml?.Encrypt || xmlObj.xml?.encrypt;

  if (!encryptedMsg) {
    res.statusCode = 400;
    res.end("Missing Encrypt field in XML");
    return;
  }

  // 4. Verify signature
  const isValid = verifySignature(token, timestamp, nonce, encryptedMsg, msgSignature);
  if (!isValid) {
    console.error("Invalid message signature");
    res.statusCode = 403;
    res.end("Invalid signature");
    return;
  }

  // 5. Decrypt message
  let decryptedXml: string;
  try {
    decryptedXml = decryptMessage(encodingAESKey, encryptedMsg, corpid);
    if (verbose) {
      console.log("=== Decrypted Message XML ===");
      console.log(decryptedXml);
    }
  } catch (error) {
    console.error("Decryption failed:", error);
    res.statusCode = 500;
    res.end("Decryption failed");
    return;
  }

  // 6. Parse WeCom message
  const wecomMessage = parseWeComMessage(decryptedXml);
  if (verbose) {
    console.log("=== Parsed WeChat Message ===");
    console.log(JSON.stringify(wecomMessage, null, 2));
  }

  // 6.1. Skip event messages (enter_agent, LOCATION, etc.)
  if (wecomMessage.MsgType === "event") {
    if (verbose) {
      console.log(`[WeCom] 跳过事件消息: ${(wecomMessage as any).Event}`);
    }
    res.statusCode = 200;
    res.setHeader("Content-Type", "text/plain");
    res.end("success");
    return;
  }

  // 6.5. Process voice message with ASR if configured
  let voiceTranscript: string | undefined;
  if (wecomMessage.MsgType === "voice") {
    if (verbose) {
      console.log("[Voice] 检测到语音消息");
      console.log(`[Voice] MediaId: ${wecomMessage.MediaId}`);
      console.log(`[Voice] Format: ${wecomMessage.Format}`);
    }

    const asrConfig = config.tencentAsr;
    if (asrConfig?.enabled && asrConfig.secretId && asrConfig.secretKey) {
      if (verbose) {
        console.log("[Voice] 腾讯云 ASR 已启用，开始语音识别...");
      }

      try {
        // Download voice file
        const voiceBuffer = await wecomOfficialAPI.downloadMedia(
          config.corpid,
          config.corpsecret,
          wecomMessage.MediaId
        );

        // Save to temp file
        const tempFilePath = join(
          tmpdir(),
          `wecom-voice-${Date.now()}-${wecomMessage.MediaId}.${wecomMessage.Format || "amr"}`
        );
        await writeFile(tempFilePath, voiceBuffer);
        if (verbose) {
          console.log(`[Voice] ✓ 语音文件已保存: ${tempFilePath}`);
        }

        // Recognize voice
        const asrResult = await recognizeVoice(tempFilePath, {
          secretId: asrConfig.secretId,
          secretKey: asrConfig.secretKey,
          region: asrConfig.region,
          engineModelType: asrConfig.engineModelType,
        });

        if (asrResult.success && asrResult.text) {
          voiceTranscript = asrResult.text;
          if (verbose) {
            console.log(`[Voice] ✓ 语音识别成功: ${voiceTranscript}`);
          }
        } else {
          console.warn(`[Voice] ✗ 语音识别失败: ${asrResult.error}`);
        }

        // Clean up temp file (optional, OS will clean tmpdir eventually)
        // await unlink(tempFilePath).catch(() => {});
      } catch (error) {
        console.error("[Voice] 语音处理失败:", error);
      }
    } else {
      if (verbose) {
        console.log("[Voice] ASR 未配置或未启用，跳过语音识别");
      }
    }
  }

  // 6.7. Download image (if image message)
  let imagePath: string | undefined;
  if (wecomMessage.MsgType === "image") {
    if (verbose) {
      console.log("[Image] 检测到图片消息");
      console.log(`[Image] MediaId: ${wecomMessage.MediaId}`);
      console.log(`[Image] PicUrl: ${wecomMessage.PicUrl}`);
    }

    try {
      // Download image using MediaId (more reliable than PicUrl)
      const imageBuffer = await wecomOfficialAPI.downloadMedia(
        config.corpid,
        config.corpsecret,
        wecomMessage.MediaId
      );

      // Save to temp file
      const tempFilePath = join(
        tmpdir(),
        `wecom-image-${Date.now()}-${wecomMessage.MediaId}.jpg`
      );
      await writeFile(tempFilePath, imageBuffer);
      imagePath = tempFilePath;

      if (verbose) {
        console.log(`[Image] ✓ 图片文件已保存: ${tempFilePath}`);
        console.log(`[Image] ✓ 文件大小: ${imageBuffer.length} bytes`);
      }
    } catch (error) {
      console.error("[Image] 图片下载失败:", error);
      if (verbose) {
        console.log("[Image] ⚠ 将回退到使用 PicUrl");
      }
      // Will fall back to PicUrl in formatMessageForClawdbot
    }
  }

  // 7. Convert to Clawdbot format
  let { text, mediaUrls } = formatMessageForClawdbot(wecomMessage);

  // 7.5. Append voice transcript if available
  if (voiceTranscript) {
    text = `[语音内容]\n${voiceTranscript}`;
    if (verbose) {
      console.log("[Voice] ✓ 已将语音识别结果添加到消息中");
    }
  }

  const userId = wecomMessage.FromUserName;

  // Log compact summary in non-verbose mode
  if (!verbose) {
    const contentPreview = (text || "").substring(0, 50) + ((text?.length || 0) > 50 ? "..." : "");
    console.log(`[WeCom] 收到消息: From=${userId}, Type=${wecomMessage.MsgType}, Content=${contentPreview}`);
  } else {
    console.log("=== WeCom Context to Agent ===");
    console.log("From:", userId);
    console.log("Body:", text);
    console.log("MediaUrls:", mediaUrls);
    console.log("MediaPaths:", imagePath ? [imagePath] : undefined);
    console.log("===================================");
  }

  // 8. Return success immediately (WeCom requires response within 5 seconds)
  res.statusCode = 200;
  res.setHeader("Content-Type", "text/plain");
  res.end("success");

  // 9. Process message asynchronously
  const systemPrompt = config.systemPrompt?.trim() || undefined;

  // Dispatch within session context
  const runtime = getWecomRuntime();
  await runInSessionContext(userId, accountId, async () => {
    await runtime.channel.reply.dispatchReplyWithBufferedBlockDispatcher({
    ctx: {
      From: userId,
      Body: text,
      AccountId: accountId,
      SessionKey: `wecom:${accountId}:${userId}`,
      MediaUrls: imagePath ? undefined : mediaUrls, // Use local path if available
      MediaPaths: imagePath ? [imagePath] : undefined, // Prefer local path over URL
      GroupSystemPrompt: systemPrompt,
    },
    cfg,
    dispatcherOptions: {
      responsePrefix: "",
      deliver: async (payload) => {
        if (verbose) {
          console.log("=== WeCom Deliver Payload ===");
          console.log("Text:", payload.text?.substring(0, 100));
          console.log("MediaUrl:", payload.mediaUrl);
        }

        // 🔍 自动检测文件路径（如果 mediaUrl 未设置）
        let mediaUrl = payload.mediaUrl;
        if (!mediaUrl && payload.text) {
          // 1. 匹配 markdown 图片语法: ![alt](path)
          const markdownImageRegex = /!\[.*?\]\(([/~][^\s)]+\.(?:png|jpg|jpeg|gif|webp|bmp|mp4|avi|mov|mp3|wav|amr))\)/gi;
          const markdownMatches = [...payload.text.matchAll(markdownImageRegex)];

          if (markdownMatches && markdownMatches.length > 0) {
            mediaUrl = markdownMatches[0][1];
            if (verbose) {
              console.log(`[Auto-detect] ✅ 检测到 Markdown 图片: ${mediaUrl}`);
            }
          } else {
            // 2. 匹配文件路径模式 (支持反引号、引号包裹的路径)
            const filePathRegex = /[`'"]?([/~][^\s`'"<>]+\.(?:png|jpg|jpeg|gif|webp|bmp|mp4|avi|mov|mp3|wav|amr|pdf))[`'"]?/gi;
            const matches = [...payload.text.matchAll(filePathRegex)];

            if (matches && matches.length > 0) {
              mediaUrl = matches[0][1];
              if (verbose) {
                console.log(`[Auto-detect] ✅ 检测到文件路径: ${mediaUrl}`);
              }
            }
          }
        }

        if (verbose) {
          console.log("MediaUrl (final):", mediaUrl);
        }

        const msg: SimpleWecomMessage = {
          text: payload.text,
          mediaUrl: mediaUrl
        };

        await wecomClient.sendMessage(userId, msg, {
          webhookUrl: config.webhookUrl,
          webhookToken: config.webhookToken,
          weworkApiUrl: config.weworkApiUrl,
          weworkNamespace: config.weworkNamespace,
          weworkToken: config.weworkToken,
          weworkCode: config.weworkCode,
          corpid: config.corpid,
          corpsecret: config.corpsecret,
          agentid: config.agentid,
          token: config.token,
          encodingAESKey: config.encodingAESKey
        });

        // Log compact summary in non-verbose mode
        if (!verbose) {
          const textPreview = (payload.text || "").substring(0, 50) + ((payload.text?.length || 0) > 50 ? "..." : "");
          const mediaInfo = mediaUrl ? `, Media=${mediaUrl.split('/').pop()}` : "";
          console.log(`[WeCom] 发送回复: To=${userId}${mediaInfo}, Text=${textPreview}`);
        }
      },
      onError: (err) => {
        console.error("WeCom dispatch error:", err);
      },
    },
    replyOptions: {},
  });
  }, verbose); // End runInSessionContext
}

/**
 * Handle legacy JSON/Multipart format messages (backwards compatible)
 */
async function handleLegacyMessage(
  req: IncomingMessage,
  res: ServerResponse,
  contentType: string,
  config: any,
  accountId: string,
  cfg: any,
) {
  const verbose = config.verbose === true;
  let email: string | undefined;
  let text: string | undefined;
  let imageUrl: string | undefined;
  let sync = false;
  const files: Array<{ filename: string; path: string; mimetype: string }> = [];

  if (contentType.includes("application/json")) {
    const raw = await readBody(req);
    if (raw.length === 0) {
      res.statusCode = 400;
      res.end("Empty body");
      return;
    }
    const body = JSON.parse(raw.toString());
    email = body.email;
    text = body.text;
    imageUrl = body.imageUrl;
    sync = Boolean(body.sync);
  } else if (contentType.includes("multipart/form-data")) {
    const boundary = contentType.split("boundary=")[1]?.split(";")[0];
    if (!boundary) throw new Error("No boundary");
    const buffer = await readBody(req);
    const result = parseMultipart(buffer, boundary);

    email = result.fields.email;
    text = result.fields.text;
    sync = result.fields.sync === "true";

    // Handle files
    for (const file of result.files) {
      const tempPath = join(tmpdir(), `simple-wecom-${randomUUID()}-${file.filename}`);
      await writeFile(tempPath, file.data);
      files.push({
        filename: file.filename,
        path: tempPath,
        mimetype: file.mimetype,
      });
    }
  }

  if (!email) {
    res.statusCode = 400;
    res.end("Missing email");
    return;
  }

  // Handle Sync Request
  if (sync) {
    wecomClient.registerPendingRequest(email, res);
  } else {
    res.statusCode = 200;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ status: "ok" }));
  }

  // Prepare Media
  const mediaUrls: string[] = [];
  if (imageUrl) mediaUrls.push(imageUrl);
  for (const file of files) {
    mediaUrls.push(`file://${file.path}`);
  }

  // Add file paths to message text for LLM to see
  let enrichedText = text || "";
  if (files.length > 0) {
    enrichedText += "\n\n[上传的文件]";
    for (const file of files) {
      enrichedText += `\n- ${file.filename}: ${file.path}`;
    }
  }

  // 🔧 Add hidden instruction for recipient targeting
  enrichedText = `${enrichedText}\n\n[系统提示：如果需要发送媒体文件（图片/视频/音频等），接收者ID为: ${email}]`;

  // Log compact summary in non-verbose mode
  if (!verbose) {
    const textPreview = (text || "").substring(0, 50) + ((text?.length || 0) > 50 ? "..." : "");
    console.log(`[WeCom Legacy] 收到消息: From=${email}, Files=${files.length}, Content=${textPreview}`);
  } else {
    console.log("=== WeCom Context to Agent ===");
    console.log("From:", email);
    console.log("Body:", enrichedText);
    console.log("MediaUrls:", mediaUrls);
    console.log("Files count:", files.length);
    console.log("===================================");
  }

  // Read systemPrompt from config
  const systemPrompt = config.systemPrompt?.trim() || undefined;

  // Dispatch within session context
  const runtime = getWecomRuntime();
  await runInSessionContext(email!, accountId, async () => {
    await runtime.channel.reply.dispatchReplyWithBufferedBlockDispatcher({
    ctx: {
      From: email,
      Body: enrichedText,
      AccountId: accountId,
      SessionKey: `wecom:${accountId}:${email}`,
      MediaUrls: mediaUrls.length > 0 ? mediaUrls : undefined,
      GroupSystemPrompt: systemPrompt,
    },
    cfg,
    dispatcherOptions: {
      responsePrefix: "",
      deliver: async (payload) => {
        if (verbose) {
          console.log("=== WeCom Deliver Payload ===");
          console.log("Text:", payload.text);
          console.log("MediaUrl:", payload.mediaUrl);
          console.log("================================");
        }

        const msg: SimpleWecomMessage = {
          text: payload.text,
          mediaUrl: payload.mediaUrl
        };

        await wecomClient.sendMessage(email!, msg, {
          webhookUrl: config.webhookUrl,
          webhookToken: config.webhookToken,
          weworkApiUrl: config.weworkApiUrl,
          weworkNamespace: config.weworkNamespace,
          weworkToken: config.weworkToken,
          weworkCode: config.weworkCode,
          corpid: config.corpid,
          corpsecret: config.corpsecret,
          agentid: config.agentid,
          token: config.token,
          encodingAESKey: config.encodingAESKey
        });

        // Log compact summary in non-verbose mode
        if (!verbose) {
          const textPreview = (payload.text || "").substring(0, 50) + ((payload.text?.length || 0) > 50 ? "..." : "");
          const mediaInfo = payload.mediaUrl ? `, Media=${payload.mediaUrl.split('/').pop()}` : "";
          console.log(`[WeCom Legacy] 发送回复: To=${email}${mediaInfo}, Text=${textPreview}`);
        }
      },
      onError: (err) => {
        console.error("WeCom dispatch error:", err);
      },
    },
    replyOptions: {},
  });
  }, verbose); // End runInSessionContext
}
