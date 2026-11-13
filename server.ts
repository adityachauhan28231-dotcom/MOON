import 'dotenv/config';
import crypto from 'crypto';
import express from 'express';
import type { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createClient } from '@supabase/supabase-js';
import { GoogleGenAI } from '@google/genai';
import { AccessToken, TokenVerifier } from 'livekit-server-sdk';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Strip accidental KEY= prefix, surrounding quotes, and whitespace from an env value
 */
function cleanEnvValue(raw: string | undefined, expectedKeyName?: string): string {
  if (!raw) return '';
  let trimmed = raw.trim().replace(/^['"]+|['"]+$/g, '').trim();
  if (expectedKeyName && trimmed.startsWith(`${expectedKeyName}=`)) {
    trimmed = trimmed
      .slice(`${expectedKeyName}=`.length)
      .trim()
      .replace(/^['"]+|['"]+$/g, '')
      .trim();
  }
  return trimmed;
}

/**
 * Normalize Supabase Project Base URL to strictly protocol + host
 */
function resolveSupabaseBaseUrl(): string {
  const raw = cleanEnvValue(
    process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL,
    'VITE_SUPABASE_URL'
  );

  if (!raw) return '';
  try {
    const withProtocol =
      raw.startsWith('http://') || raw.startsWith('https://')
        ? raw
        : `https://${raw}`;
    const parsed = new URL(withProtocol);
    return parsed.origin;
  } catch {
    return raw
      .replace(/\/(auth|rest|realtime|storage|functions)\/v1.*$/i, '')
      .replace(/\/+$/, '');
  }
}

function resolveSupabaseAnonKey(): string {
  return cleanEnvValue(
    process.env.SUPABASE_ANON_KEY ||
      process.env.VITE_SUPABASE_ANON_KEY ||
      process.env.VITE_SUPABASE_PUBLIC_ANON_KEY,
    'VITE_SUPABASE_ANON_KEY'
  );
}

/**
 * Normalize LiveKit WebSocket URL to strictly wss://<host> or ws://<host> without trailing path/slash
 */
function resolveLiveKitWsUrl(): string {
  const raw = cleanEnvValue(
    process.env.LIVEKIT_URL || process.env.LIVEKIT_WS_URL,
    'LIVEKIT_URL'
  );

  if (!raw) return '';
  try {
    const normalizedProto = raw
      .replace(/^wss:\/\//i, 'https://')
      .replace(/^ws:\/\//i, 'http://');
    const withProto =
      normalizedProto.startsWith('http://') ||
      normalizedProto.startsWith('https://')
        ? normalizedProto
        : `https://${normalizedProto}`;
    const parsed = new URL(withProto);
    const wsProto = parsed.protocol === 'http:' ? 'ws:' : 'wss:';
    return `${wsProto}//${parsed.host}`;
  } catch {
    if (raw.startsWith('wss://') || raw.startsWith('ws://')) {
      return raw.replace(/\/+$/, '');
    }
    return `wss://${raw.replace(/\/+$/, '')}`;
  }
}

function liveKitWsToHttpOrigin(wsUrl: string): string {
  return wsUrl
    .replace(/^wss:\/\//i, 'https://')
    .replace(/^ws:\/\//i, 'http://')
    .replace(/\/+$/, '');
}

/**
 * Inspect LiveKit credentials safely without ever exposing key or secret values
 */
function resolveLiveKitCredentials() {
  const wsUrl = resolveLiveKitWsUrl();
  const apiKey = cleanEnvValue(process.env.LIVEKIT_API_KEY, 'LIVEKIT_API_KEY');
  const apiSecret = cleanEnvValue(
    process.env.LIVEKIT_API_SECRET,
    'LIVEKIT_API_SECRET'
  );

  const hasUrl = Boolean(wsUrl);
  const hasApiKey = Boolean(apiKey);
  const hasApiSecret = Boolean(apiSecret);
  const isConfigured = hasUrl && hasApiKey && hasApiSecret;

  // Detect common secret copy-paste issues (e.g. masked bullet dots •••• from LiveKit Cloud UI)
  const secretHasBulletsOrMask =
    /[\u2022\u25CF\u25AA*•]/.test(apiSecret) ||
    (hasApiSecret && !/[a-zA-Z0-9]/.test(apiSecret));
  const keyHasBulletsOrMask =
    /[\u2022\u25CF\u25AA*•]/.test(apiKey) ||
    (hasApiKey && !/[a-zA-Z0-9]/.test(apiKey));
  const keysAppearSwapped =
    hasApiKey &&
    hasApiSecret &&
    !apiKey.startsWith('API') &&
    apiSecret.startsWith('API');

  let formatIssueCode:
    | 'masked_secret'
    | 'swapped_keys'
    | 'invalid_key_format'
    | null = null;
  let formatIssueMessage: string | null = null;

  if (secretHasBulletsOrMask) {
    formatIssueCode = 'masked_secret';
    formatIssueMessage =
      'LIVEKIT_API_SECRET currently contains masked bullet characters (••••) instead of your real alphanumeric secret. In the LiveKit Cloud Dashboard (Settings -> Keys), click the Reveal (eye) icon or generate a new API Key pair, copy the actual alphanumeric Secret string, and update LIVEKIT_API_SECRET in AI Studio Secrets.';
  } else if (keyHasBulletsOrMask) {
    formatIssueCode = 'invalid_key_format';
    formatIssueMessage =
      'LIVEKIT_API_KEY contains masked characters. Copy the plain-text API Key (starts with "API...") into LIVEKIT_API_KEY.';
  } else if (keysAppearSwapped) {
    formatIssueCode = 'swapped_keys';
    formatIssueMessage =
      'LIVEKIT_API_KEY and LIVEKIT_API_SECRET appear to be swapped (LIVEKIT_API_SECRET starts with "API"). Swap their values in AI Studio Secrets.';
  } else if (hasApiKey && !apiKey.startsWith('API')) {
    formatIssueCode = 'invalid_key_format';
    formatIssueMessage =
      'LIVEKIT_API_KEY does not start with "API". Verify that LIVEKIT_API_KEY matches the API Key from your LiveKit project.';
  }

  return {
    wsUrl,
    apiKey,
    apiSecret,
    hasUrl,
    hasApiKey,
    hasApiSecret,
    isConfigured,
    formatIssueCode,
    formatIssueMessage,
  };
}

/**
 * Validate a signed LiveKit JWT against LiveKit Cloud's /rtc/validate endpoint
 * to catch signature mismatches before the browser attempts WebRTC connection.
 */
async function validateTokenWithLiveKitServer(
  wsUrl: string,
  jwt: string
): Promise<{
  ok: boolean;
  status: number;
  reason: string;
}> {
  const httpOrigin = liveKitWsToHttpOrigin(wsUrl);
  const validateUrl = `${httpOrigin}/rtc/validate?access_token=${encodeURIComponent(
    jwt
  )}`;
  const response = await fetch(validateUrl, {
    method: 'GET',
  });
  const text = (await response.text()).trim();
  return {
    ok: response.ok,
    status: response.status,
    reason: text || `HTTP ${response.status}`,
  };
}

/**
 * Order two user IDs canonically using least() and greatest()
 */
function getCanonicalPair(userA: string, userB: string): [string, string] {
  return userA < userB ? [userA, userB] : [userB, userA];
}

const MOON_AI_TEXT_MODEL = 'gemini-3.8-flash';

const MOON_AI_SYSTEM_INSTRUCTION = `You are MOON AI, a helpful, intelligent assistant built into the MOON application.
- Language support: Reply naturally in the same language and style the user uses — Hindi (देवनागरी), Hinglish (Roman Hindi + English), or English. If the user asks you to switch languages, follow their preference.
- Capabilities: Help users with study topics, mathematics (step-by-step solutions), science, general knowledge, writing, coding, and explaining attached images clearly.
- Privacy boundary: You do NOT have access to the user's private friend messages or calls. Uploaded images are analyzed ephemerally for the current question only.`;

/**
 * Initialize server-side GoogleGenAI client strictly from process.env.GEMINI_API_KEY
 */
function resolveServerGeminiClient(): {
  configured: boolean;
  ai: GoogleGenAI | null;
  errorMessage: string | null;
} {
  const apiKey = cleanEnvValue(process.env.GEMINI_API_KEY, 'GEMINI_API_KEY');
  if (
    !apiKey ||
    apiKey === 'MY_GEMINI_API_KEY' ||
    /[\u2022\u25CF\u25AA*•]/.test(apiKey)
  ) {
    return {
      configured: false,
      ai: null,
      errorMessage:
        'GEMINI_API_KEY server-side secret उपलब्ध नहीं है। कृपया इसे AI Studio Settings > Secrets पैनल में जोड़ें।',
    };
  }

  const ai = new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });

  return {
    configured: true,
    ai,
    errorMessage: null,
  };
}

interface MoonAiHistoryItem {
  role: 'user' | 'model';
  text: string;
}

interface MoonAiImagePayload {
  mimeType: string;
  data: string;
}

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  // Allow up to 15MB JSON body for ephemeral base64 image attachments
  app.use(express.json({ limit: '15mb' }));

  /**
   * GET /api/livekit/status
   * Verifies server-side LiveKit credentials and tests token signature against LiveKit Cloud
   * without exposing any secret values or JWT tokens.
   */
  app.get('/api/livekit/status', async (_req: Request, res: Response) => {
    const {
      wsUrl,
      apiKey,
      apiSecret,
      hasUrl,
      hasApiKey,
      hasApiSecret,
      isConfigured,
      formatIssueCode,
      formatIssueMessage,
    } = resolveLiveKitCredentials();

    const missingKeys: string[] = [];
    if (!hasUrl) missingKeys.push('LIVEKIT_URL');
    if (!hasApiKey) missingKeys.push('LIVEKIT_API_KEY');
    if (!hasApiSecret) missingKeys.push('LIVEKIT_API_SECRET');

    const wsHostPreview = wsUrl ? wsUrl.replace(/^wss?:\/\//, '') : null;

    if (!isConfigured) {
      res.json({
        configured: false,
        cloudVerified: false,
        hasUrl,
        hasApiKey,
        hasApiSecret,
        missingKeys,
        wsHostPreview,
        diagnosticCode: 'missing_env',
        diagnosticMessage: `Missing server environment variable(s): ${missingKeys.join(', ')}.`,
      });
      return;
    }

    if (formatIssueCode && formatIssueMessage) {
      res.json({
        configured: true,
        cloudVerified: false,
        hasUrl,
        hasApiKey,
        hasApiSecret,
        missingKeys: [],
        wsHostPreview,
        diagnosticCode: formatIssueCode,
        diagnosticMessage: formatIssueMessage,
      });
      return;
    }

    try {
      const probeToken = new AccessToken(apiKey, apiSecret, {
        identity: 'moon-healthcheck-probe',
        name: 'MOON Server Probe',
        ttl: 60,
      });
      probeToken.addGrant({
        roomJoin: true,
        room: 'moon-healthcheck-room',
        canPublish: true,
        canSubscribe: true,
        canPublishData: true,
      });
      const probeJwt = await probeToken.toJwt();

      const cloudCheck = await validateTokenWithLiveKitServer(wsUrl, probeJwt);

      if (!cloudCheck.ok) {
        const lowerReason = cloudCheck.reason.toLowerCase();
        const isInvalidKey = lowerReason.includes('invalid api key');
        res.json({
          configured: true,
          cloudVerified: false,
          hasUrl,
          hasApiKey,
          hasApiSecret,
          missingKeys: [],
          wsHostPreview,
          diagnosticCode: isInvalidKey
            ? 'cloud_rejected_key'
            : 'cloud_rejected_token',
          diagnosticMessage: isInvalidKey
            ? `LiveKit server (${wsHostPreview}) rejected LIVEKIT_API_KEY ("${cloudCheck.reason}"). Ensure LIVEKIT_API_KEY belongs to project ${wsHostPreview}.`
            : `LiveKit server (${wsHostPreview}) recognized LIVEKIT_API_KEY but rejected the token signature ("${cloudCheck.reason}"). Ensure LIVEKIT_API_SECRET is the exact unmasked alphanumeric secret paired with this API Key in project ${wsHostPreview}.`,
        });
        return;
      }

      res.json({
        configured: true,
        cloudVerified: true,
        hasUrl,
        hasApiKey,
        hasApiSecret,
        missingKeys: [],
        wsHostPreview,
        diagnosticCode: 'ok',
        diagnosticMessage: `LiveKit Cloud (${wsHostPreview}) verified API Key and HMAC-SHA256 token signature.`,
      });
    } catch (err) {
      res.json({
        configured: true,
        cloudVerified: false,
        hasUrl,
        hasApiKey,
        hasApiSecret,
        missingKeys: [],
        wsHostPreview,
        diagnosticCode: 'network_error',
        diagnosticMessage:
          err instanceof Error
            ? `Could not reach LiveKit server (${wsHostPreview}) to validate token: ${err.message}`
            : 'Could not reach LiveKit server to validate token.',
      });
    }
  });

  /**
   * POST /api/livekit/token
   * Generates a short-lived LiveKit access token strictly after:
   * 1. Validating the caller's Supabase access token (Authorization: Bearer <jwt>)
   * 2. Verifying that the caller and target friendId are accepted friends in public.friendships (user1, user2)
   * 3. Verifying the signed LiveKit JWT locally and against LiveKit Cloud's /rtc/validate endpoint
   */
  app.post('/api/livekit/token', async (req: Request, res: Response) => {
    try {
      const {
        wsUrl,
        apiKey,
        apiSecret,
        hasUrl,
        hasApiKey,
        hasApiSecret,
        isConfigured,
        formatIssueMessage,
      } = resolveLiveKitCredentials();

      if (!isConfigured) {
        const missing: string[] = [];
        if (!hasUrl) missing.push('LIVEKIT_URL');
        if (!hasApiKey) missing.push('LIVEKIT_API_KEY');
        if (!hasApiSecret) missing.push('LIVEKIT_API_SECRET');
        res.status(503).json({
          error: `LiveKit server credentials are not configured yet. Missing environment variable(s): ${missing.join(', ')}. Configure them in AI Studio Secrets.`,
        });
        return;
      }

      if (formatIssueMessage) {
        res.status(503).json({
          error: formatIssueMessage,
        });
        return;
      }

      const supabaseUrl = resolveSupabaseBaseUrl();
      const supabaseAnonKey = resolveSupabaseAnonKey();
      if (!supabaseUrl || !supabaseAnonKey) {
        res.status(503).json({
          error:
            'Supabase URL or Anon Key is missing on the server. Ensure VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY are configured.',
        });
        return;
      }

      const authHeader = req.headers.authorization || '';
      const tokenMatch = authHeader.match(/^Bearer\s+(.+)$/i);
      const supabaseAccessToken = tokenMatch ? tokenMatch[1].trim() : '';

      if (!supabaseAccessToken) {
        res.status(401).json({
          error:
            'Missing Supabase Authorization Bearer token. Please sign in to MOON first.',
        });
        return;
      }

      const friendId =
        typeof req.body?.friendId === 'string' ? req.body.friendId.trim() : '';
      if (!friendId) {
        res.status(400).json({
          error: 'Target friendId is required to request a voice call token.',
        });
        return;
      }

      // Create a request-scoped Supabase client authenticated as the caller
      const userSupabase = createClient(supabaseUrl, supabaseAnonKey, {
        auth: {
          persistSession: false,
          autoRefreshToken: false,
          detectSessionInUrl: false,
        },
        global: {
          headers: {
            Authorization: `Bearer ${supabaseAccessToken}`,
          },
        },
      });

      // Step 1: Verify the caller's identity with Supabase Auth
      const {
        data: { user: callerUser },
        error: authError,
      } = await userSupabase.auth.getUser(supabaseAccessToken);

      if (authError || !callerUser) {
        res.status(401).json({
          error: `Supabase authentication verification failed: ${
            authError?.message || 'Invalid or expired session token.'
          }`,
        });
        return;
      }

      if (callerUser.id === friendId) {
        res.status(400).json({
          error: 'You cannot initiate a voice call with yourself.',
        });
        return;
      }

      // Step 2: Verify that callerUser.id and friendId are accepted friends in public.friendships (user1, user2)
      const [u1, u2] = getCanonicalPair(callerUser.id, friendId);
      const { data: friendshipRows, error: friendshipError } =
        await userSupabase
          .from('friendships')
          .select('user1, user2')
          .or(
            `and(user1.eq.${u1},user2.eq.${u2}),and(user1.eq.${u2},user2.eq.${u1})`
          )
          .limit(1);

      if (friendshipError) {
        res.status(500).json({
          error: `Failed to verify friendship in public.friendships: ${friendshipError.message}`,
        });
        return;
      }

      if (!friendshipRows || friendshipRows.length === 0) {
        res.status(403).json({
          error:
            'Access denied: Voice calling is restricted to accepted friends in public.friendships.',
        });
        return;
      }

      // Step 3: Load caller profile metadata for display inside the LiveKit room
      const { data: callerProfile } = await userSupabase
        .from('profiles')
        .select('username, display_name, friend_code, avatar_hue')
        .eq('id', callerUser.id)
        .maybeSingle();

      const participantName =
        (callerProfile?.display_name as string | undefined) ||
        (callerProfile?.username as string | undefined) ||
        callerUser.email?.split('@')[0] ||
        'MOON User';

      // Deterministic canonical room name for this accepted friendship pair
      const canonicalRoomName = `moon-call-${u1}-${u2}`;

      // Step 4: Generate short-lived (600s / 10m) LiveKit access token
      const accessToken = new AccessToken(apiKey, apiSecret, {
        identity: String(callerUser.id),
        name: participantName,
        ttl: 600,
        metadata: JSON.stringify({
          userId: callerUser.id,
          username: callerProfile?.username || participantName,
          friendCode: callerProfile?.friend_code || '',
          avatarHue: callerProfile?.avatar_hue || '268',
        }),
      });

      accessToken.addGrant({
        roomJoin: true,
        room: canonicalRoomName,
        canPublish: true,
        canSubscribe: true,
        canPublishData: true,
      });

      const jwt = (await accessToken.toJwt()).trim();

      if (!jwt || jwt.split('.').length !== 3) {
        res.status(500).json({
          error:
            'Generated LiveKit token did not produce a valid 3-part JWT string.',
        });
        return;
      }

      // Step 5: Verify token claims locally with TokenVerifier
      const verifier = new TokenVerifier(apiKey, apiSecret);
      await verifier.verify(jwt, 30);

      // Step 6: Validate token against LiveKit Cloud's /rtc/validate endpoint
      const cloudValidation = await validateTokenWithLiveKitServer(wsUrl, jwt);
      if (!cloudValidation.ok) {
        const wsHostPreview = wsUrl.replace(/^wss?:\/\//, '');
        const lowerReason = cloudValidation.reason.toLowerCase();
        const detail = lowerReason.includes('invalid api key')
          ? `LiveKit Cloud (${wsHostPreview}) rejected LIVEKIT_API_KEY ("${cloudValidation.reason}"). Verify LIVEKIT_API_KEY matches project ${wsHostPreview}.`
          : `LiveKit Cloud (${wsHostPreview}) rejected the token signature ("${cloudValidation.reason}"). Verify LIVEKIT_API_SECRET in AI Studio Secrets is the exact unmasked alphanumeric secret for ${wsHostPreview} (not masked •••• dots).`;

        res.status(502).json({
          error: detail,
        });
        return;
      }

      res.json({
        token: jwt,
        wsUrl,
        roomName: canonicalRoomName,
        participantIdentity: String(callerUser.id),
        participantName,
        expiresInSeconds: 600,
        cloudValidated: true,
      });
    } catch (err) {
      res.status(500).json({
        error:
          err instanceof Error
            ? `LiveKit token generation failed: ${err.message}`
            : 'Unexpected server error while generating LiveKit token.',
      });
    }
  });

  /**
   * GET /api/moon-ai/status
   * Safe server-side check for whether GEMINI_API_KEY is configured on the backend.
   * Never exposes the API key value.
   */
  app.get('/api/moon-ai/status', (_req: Request, res: Response) => {
    const { configured, errorMessage } = resolveServerGeminiClient();
    res.json({
      configured,
      model: MOON_AI_TEXT_MODEL,
      message: configured
        ? 'MOON AI server-side Gemini integration is ready.'
        : errorMessage,
    });
  });

  /**
   * POST /api/moon-ai/chat
   * Server-side Gemini endpoint for MOON AI text chat (Hindi, Hinglish, English)
   * and ephemeral image understanding.
   * - Strictly verifies the caller's Supabase session (Authorization: Bearer <jwt>).
   * - Never accesses or exposes private friend messages (public.messages).
   * - Never stores uploaded images permanently.
   */
  app.post('/api/moon-ai/chat', async (req: Request, res: Response) => {
    try {
      // 1. Check server-side GEMINI_API_KEY secret
      const { configured, ai, errorMessage } = resolveServerGeminiClient();
      if (!configured || !ai) {
        res.status(503).json({
          error:
            errorMessage ||
            'GEMINI_API_KEY is not configured on the server. Please add GEMINI_API_KEY in AI Studio Secrets.',
        });
        return;
      }

      // 2. Verify Supabase Authentication (do not bypass existing auth/RLS)
      const supabaseUrl = resolveSupabaseBaseUrl();
      const supabaseAnonKey = resolveSupabaseAnonKey();
      if (!supabaseUrl || !supabaseAnonKey) {
        res.status(503).json({
          error:
            'Supabase URL or Anon Key is missing on the server. Ensure VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY are configured.',
        });
        return;
      }

      const authHeader = req.headers.authorization || '';
      const tokenMatch = authHeader.match(/^Bearer\s+(.+)$/i);
      const supabaseAccessToken = tokenMatch ? tokenMatch[1].trim() : '';

      if (!supabaseAccessToken) {
        res.status(401).json({
          error:
            'Missing Supabase Authorization Bearer token. Please sign in (or Continue as Guest) to use MOON AI.',
        });
        return;
      }

      const userSupabase = createClient(supabaseUrl, supabaseAnonKey, {
        auth: {
          persistSession: false,
          autoRefreshToken: false,
          detectSessionInUrl: false,
        },
        global: {
          headers: {
            Authorization: `Bearer ${supabaseAccessToken}`,
          },
        },
      });

      const {
        data: { user: callerUser },
        error: authError,
      } = await userSupabase.auth.getUser(supabaseAccessToken);

      if (authError || !callerUser) {
        res.status(401).json({
          error: `Supabase authentication failed: ${
            authError?.message || 'Invalid or expired session token.'
          }`,
        });
        return;
      }

      // 3. Validate message, conversation history, and optional ephemeral image
      const rawMessage =
        typeof req.body?.message === 'string' ? req.body.message.trim() : '';
      const rawHistory = Array.isArray(req.body?.history)
        ? (req.body.history as MoonAiHistoryItem[])
        : [];
      const rawImage =
        req.body?.image && typeof req.body.image === 'object'
          ? (req.body.image as MoonAiImagePayload)
          : null;

      let validatedImagePart: {
        inlineData: { mimeType: string; data: string };
      } | null = null;

      if (rawImage && rawImage.data) {
        const mimeType = (rawImage.mimeType || 'image/jpeg').trim().toLowerCase();
        const allowedMimeTypes = new Set([
          'image/jpeg',
          'image/jpg',
          'image/png',
          'image/webp',
          'image/heic',
          'image/heif',
          'image/gif',
        ]);

        if (!allowedMimeTypes.has(mimeType)) {
          res.status(400).json({
            error: `Unsupported image MIME type "${mimeType}". Allowed types: JPEG, PNG, WEBP, HEIC, GIF.`,
          });
          return;
        }

        // Strip optional data:image/...;base64, prefix if present
        const base64Clean = String(rawImage.data)
          .replace(/^data:[^;]+;base64,/i, '')
          .trim();

        if (!base64Clean) {
          res.status(400).json({
            error: 'Attached image data is empty.',
          });
          return;
        }

        validatedImagePart = {
          inlineData: {
            mimeType: mimeType === 'image/jpg' ? 'image/jpeg' : mimeType,
            data: base64Clean,
          },
        };
      }

      if (!rawMessage && !validatedImagePart) {
        res.status(400).json({
          error:
            'Please provide a text question or attach an image for MOON AI.',
        });
        return;
      }

      // Build multi-turn conversation contents (capped to last 20 turns for context)
      const contents: Array<{
        role: 'user' | 'model';
        parts: Array<
          | { text: string }
          | { inlineData: { mimeType: string; data: string } }
        >;
      }> = [];

      const recentHistory = rawHistory.slice(-20);
      for (const item of recentHistory) {
        if (
          item &&
          (item.role === 'user' || item.role === 'model') &&
          typeof item.text === 'string' &&
          item.text.trim()
        ) {
          contents.push({
            role: item.role,
            parts: [{ text: item.text.trim() }],
          });
        }
      }

      const currentTurnParts: Array<
        { text: string } | { inlineData: { mimeType: string; data: string } }
      > = [];

      if (validatedImagePart) {
        currentTurnParts.push(validatedImagePart);
      }

      currentTurnParts.push({
        text:
          rawMessage ||
          'कृपया इस इमेज को ध्यान से देखें और आसान भाषा में समझाएं (Please analyze and explain this image clearly).',
      });

      contents.push({
        role: 'user',
        parts: currentTurnParts,
      });

      // 4. Call Gemini server-side using @google/genai with automatic retry on transient 503 spikes
      const candidateModels = [
        MOON_AI_TEXT_MODEL,
        'gemini-flash-latest',
        'gemini-3.1-flash-lite',
      ];
      let replyText = '';
      let usedModel = MOON_AI_TEXT_MODEL;
      let lastGeminiErr: unknown = null;

      for (let attempt = 0; attempt < candidateModels.length; attempt++) {
        const modelToTry = candidateModels[attempt];
        try {
          const response = await ai.models.generateContent({
            model: modelToTry,
            contents,
            config: {
              systemInstruction: MOON_AI_SYSTEM_INSTRUCTION,
            },
          });
          replyText = (response.text ?? '').trim();
          usedModel = modelToTry;
          if (replyText) {
            break;
          }
        } catch (err) {
          lastGeminiErr = err;
          const msg = err instanceof Error ? err.message : String(err);
          const isTransientOverload =
            msg.includes('503') ||
            msg.includes('UNAVAILABLE') ||
            msg.includes('429') ||
            msg.includes('RESOURCE_EXHAUSTED');

          if (isTransientOverload && attempt < candidateModels.length - 1) {
            await new Promise((resolve) =>
              setTimeout(resolve, 600 * (attempt + 1))
            );
            continue;
          }
          throw err;
        }
      }

      if (!replyText) {
        if (lastGeminiErr) {
          throw lastGeminiErr;
        }
        res.status(502).json({
          error:
            'MOON AI returned an empty response. Please try rephrasing your question.',
        });
        return;
      }

      res.json({
        reply: replyText,
        model: usedModel,
        timestampIso: new Date().toISOString(),
      });
    } catch (err) {
      const rawErrMsg =
        err instanceof Error ? err.message : 'Unexpected Gemini API error.';
      const status =
        rawErrMsg.includes('403') || rawErrMsg.includes('PERMISSION_DENIED')
          ? 403
          : rawErrMsg.includes('429') || rawErrMsg.includes('RESOURCE_EXHAUSTED')
          ? 429
          : 500;

      res.status(status).json({
        error: `MOON AI Error: ${rawErrMsg}`,
      });
    }
  });

  /**
   * Server-side MOON REELS India-First (80% India / 20% Global) Dynamic Feed & Search Endpoint
   * - Aggregates live public videos from 24+ official Indian YouTube channel Atom XML feeds
   *   (Hindi, Bhojpuri, Indian Comedy, Bollywood Music, Indian Entertainment, Indian Gaming, ISRO, Hindi Education)
   *   and 6 International channels.
   * - Enforces an 80% India / 20% Other Countries distribution in the default "For You" feed.
   * - Never falsely labels a foreign creator as Indian: `region: 'IN' | 'GLOBAL'` is strictly assigned
   *   from verified creator channel provenance or explicit Devanagari/Indian metadata.
   * - Supports category filters: for_you, india, bhojpuri, hindi, comedy, entertainment, music, gaming, other_countries.
   */
  type ServerReelRegion = 'IN' | 'GLOBAL';
  type ServerReelFilterTag =
    | 'India'
    | 'Bhojpuri'
    | 'Hindi'
    | 'Comedy'
    | 'Entertainment'
    | 'Music'
    | 'Gaming'
    | 'Other Countries';

  interface ServerReelEntry {
    id: string;
    source: 'youtube' | 'instagram';
    embedCode: string;
    title: string;
    channelName: string;
    channelHandle: string;
    category: string;
    region: ServerReelRegion;
    language: 'hindi' | 'bhojpuri' | 'english';
    tags: ServerReelFilterTag[];
    originalUrl: string;
    thumbnailUrl?: string;
    baseLikes: number;
  }

  const OFFICIAL_YOUTUBE_RSS_CHANNELS: Array<{
    channelId: string;
    name: string;
    handle: string;
    category: string;
    region: ServerReelRegion;
    language: 'hindi' | 'bhojpuri' | 'english';
    tags: ServerReelFilterTag[];
  }> = [
    // --- VERIFIED INDIAN CHANNELS (80% PRIORITY POOL) ---
    {
      channelId: 'UCq-Fj5jknLsUf-MWSy4_brA',
      name: 'T-Series',
      handle: '@TSeries',
      category: 'Bollywood & Indian Music',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Music', 'Entertainment'],
    },
    {
      channelId: 'UCYLlkv4hivYJlOk6Lo-RHNQ',
      name: 'Wave Music Bhojpuri',
      handle: '@WaveMusicBhojpuri',
      category: 'Bhojpuri Music & Reels',
      region: 'IN',
      language: 'bhojpuri',
      tags: ['India', 'Bhojpuri', 'Music', 'Entertainment'],
    },
    {
      channelId: 'UCkS7Vxu4PjM99w0Is6idjcg',
      name: 'Zakir Khan',
      handle: '@ZakirKhan',
      category: 'Indian Stand-Up Comedy',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Comedy', 'Entertainment'],
    },
    {
      channelId: 'UCbTLwN10NoCU4WDzLf1JMOA',
      name: 'YRF (Yash Raj Films)',
      handle: '@yrf',
      category: 'Bollywood Entertainment',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Entertainment', 'Music'],
    },
    {
      channelId: 'UCX8pnu3DYUnx8qy8V_c6oHg',
      name: 'Techno Gamerz',
      handle: '@TechnoGamerzOfficial',
      category: 'Indian Gaming',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Gaming', 'Entertainment'],
    },
    {
      channelId: 'UCbomPUMyPHCgrqD5iYnzj1A',
      name: 'Worldwide Records Bhojpuri',
      handle: '@WorldwideRecordsBhojpuri',
      category: 'Bhojpuri Hits & Culture',
      region: 'IN',
      language: 'bhojpuri',
      tags: ['India', 'Bhojpuri', 'Music', 'Entertainment'],
    },
    {
      channelId: 'UCqwUrj10mAEsqezcItqvwEw',
      name: 'BB Ki Vines',
      handle: '@BBKiVines',
      category: 'Indian Comedy & Vines',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Comedy', 'Entertainment'],
    },
    {
      channelId: 'UC56gTxNs4f9xZ7Pa2i5xNzg',
      name: 'Sony Music India',
      handle: '@SonyMusicIndia',
      category: 'Indian Pop & Bollywood',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Music', 'Entertainment'],
    },
    {
      channelId: 'UC5c9VlYTSvBSCaoMu_GI6gQ',
      name: 'Total Gaming',
      handle: '@TotalGaming093',
      category: 'Indian Gaming Shorts',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Gaming'],
    },
    {
      channelId: 'UC0J8BQahplvTY6LjlnLf_NQ',
      name: 'Saregama Hum Bhojpuri',
      handle: '@SaregamaHumBhojpuri',
      category: 'Bhojpuri Songs & Dance',
      region: 'IN',
      language: 'bhojpuri',
      tags: ['India', 'Bhojpuri', 'Music', 'Entertainment'],
    },
    {
      channelId: 'UC7eHZXheF8nVOfwB2PEslMw',
      name: 'Ashish Chanchlani Vines',
      handle: '@ashishchanchlanivines',
      category: 'Indian Comedy',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Comedy', 'Entertainment'],
    },
    {
      channelId: 'UCZSNzBgFub_WWil6TOTYwAg',
      name: 'Netflix India',
      handle: '@NetflixIndiaOfficial',
      category: 'Indian Entertainment',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Entertainment', 'Comedy'],
    },
    {
      channelId: 'UCJfeUWkrU4JwIJfP-usd-_w',
      name: 'Khesari Music World',
      handle: '@KhesariMusicWorld',
      category: 'Bhojpuri Entertainment',
      region: 'IN',
      language: 'bhojpuri',
      tags: ['India', 'Bhojpuri', 'Music', 'Entertainment'],
    },
    {
      channelId: 'UCKnZHF24IV9PT0cdSdHoWug',
      name: 'Anubhav Singh Bassi',
      handle: '@AnubhavSinghBassi',
      category: 'Hindi Stand-Up Comedy',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Comedy', 'Entertainment'],
    },
    {
      channelId: 'UCFFbwnve3yF62-tVXkTyHqg',
      name: 'Zee Music Company',
      handle: '@zeemusiccompany',
      category: 'Bollywood Music & Dance',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Music', 'Entertainment'],
    },
    {
      channelId: 'UCx6F-rETGiz7xf_vkMmX2yQ',
      name: 'Mythpat',
      handle: '@Mythpat',
      category: 'Indian Gaming & Comedy',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Gaming', 'Comedy'],
    },
    {
      channelId: 'UC4zWG9LccdWGUlF77LZ8toA',
      name: 'Prime Video India',
      handle: '@PrimeVideoIN',
      category: 'Indian Series & Cinema',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Entertainment', 'Comedy'],
    },
    {
      channelId: 'UCj22tfcQrWG7EMEKS0qLeEg',
      name: 'CarryMinati',
      handle: '@CarryMinati',
      category: 'Indian Comedy & Entertainment',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Comedy', 'Entertainment'],
    },
    {
      channelId: 'UCt4atlExw8aj3Bm79nv1fig',
      name: 'Round2hell',
      handle: '@Round2hell',
      category: 'Hindi Sketch Comedy',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Comedy', 'Entertainment'],
    },
    {
      channelId: 'UCfLuT3JwLx8rvHjHfTymekw',
      name: 'Triggered Insaan',
      handle: '@TriggeredInsaan',
      category: 'Indian Comedy & Vlogs',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Comedy', 'Entertainment'],
    },
    {
      channelId: 'UCw5hEVOTfz_AfzsNFWyNlNg',
      name: 'ISRO Official',
      handle: '@isroofficial5866',
      category: 'Indian Space Research (ISRO)',
      region: 'IN',
      language: 'english',
      tags: ['India', 'Entertainment'],
    },
    {
      channelId: 'UC-CSyyi47VX1lD9zyeABW3w',
      name: 'Dhruv Rathee',
      handle: '@dhruvrathee',
      category: 'Hindi Knowledge & Explainer',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi'],
    },
    {
      channelId: 'UCBqFKDipsnzvJdt6UT0lMIg',
      name: 'Sandeep Maheshwari',
      handle: '@SandeepSeminars',
      category: 'Hindi Motivation & Life',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi'],
    },
    {
      channelId: 'UCeVMnSShP_Iviwkknt83cww',
      name: 'CodeWithHarry',
      handle: '@CodeWithHarry',
      category: 'Hindi Coding & Tech',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi'],
    },

    // --- VERIFIED INTERNATIONAL / OTHER COUNTRIES CHANNELS (20% POOL) ---
    {
      channelId: 'UCLA_DiR1FfKNvjuUpBHmylQ',
      name: 'NASA',
      handle: '@NASA',
      category: 'Global Space & Science',
      region: 'GLOBAL',
      language: 'english',
      tags: ['Other Countries'],
    },
    {
      channelId: 'UCsBjURrPoezykLs9EqgamOA',
      name: 'Fireship',
      handle: '@Fireship',
      category: 'Global Tech Shorts',
      region: 'GLOBAL',
      language: 'english',
      tags: ['Other Countries'],
    },
    {
      channelId: 'UC_x5XG1OV2P6uZZ5FSM9Ttw',
      name: 'Google for Developers',
      handle: '@GoogleDevelopers',
      category: 'Global Developer Showcase',
      region: 'GLOBAL',
      language: 'english',
      tags: ['Other Countries'],
    },
    {
      channelId: 'UCYO_jab_esuFRV4b17AJtAw',
      name: '3Blue1Brown',
      handle: '@3blue1brown',
      category: 'Global Visual Math',
      region: 'GLOBAL',
      language: 'english',
      tags: ['Other Countries'],
    },
    {
      channelId: 'UCSMOQeBJ2RAnuFungnQOxLg',
      name: 'Blender Official',
      handle: '@BlenderOfficial',
      category: 'Global 3D Open Cinema',
      region: 'GLOBAL',
      language: 'english',
      tags: ['Other Countries', 'Entertainment'],
    },
    {
      channelId: 'UCHnyfMqiRRG1u-2MsSQLbXA',
      name: 'Veritasium',
      handle: '@veritasium',
      category: 'Global Science & Physics',
      region: 'GLOBAL',
      language: 'english',
      tags: ['Other Countries'],
    },
  ];

  const SERVER_VERIFIED_SEED_REELS: ServerReelEntry[] = [
    // --- INDIA (80% PRIORITY SEED VIDEOS: HINDI, BHOJPURI, COMEDY, BOLLYWOOD, GAMING, ISRO) ---
    {
      id: 'seed-in-tseries-Y6sHVLeAH4g',
      source: 'youtube',
      embedCode: 'Y6sHVLeAH4g',
      title: 'Kahin Jo Tu Mil Jaaye | KING | Shah Rukh Khan, Deepika Padukone',
      channelName: 'T-Series',
      channelHandle: '@TSeries',
      category: 'Bollywood Music',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Music', 'Entertainment'],
      originalUrl: 'https://www.youtube.com/shorts/Y6sHVLeAH4g',
      thumbnailUrl: 'https://i.ytimg.com/vi/Y6sHVLeAH4g/hqdefault.jpg',
      baseLikes: 18400,
    },
    {
      id: 'seed-in-bhojpuri-v2pE14pl3yM',
      source: 'youtube',
      embedCode: 'v2pE14pl3yM',
      title: 'दउरिया | Nikesh Singh & Sweta Sargam | New Bhojpuri Chhath Geet',
      channelName: 'Wave Music Bhojpuri',
      channelHandle: '@WaveMusicBhojpuri',
      category: 'Bhojpuri Music & Festival',
      region: 'IN',
      language: 'bhojpuri',
      tags: ['India', 'Bhojpuri', 'Music', 'Entertainment'],
      originalUrl: 'https://www.youtube.com/shorts/v2pE14pl3yM',
      thumbnailUrl: 'https://i.ytimg.com/vi/v2pE14pl3yM/hqdefault.jpg',
      baseLikes: 9420,
    },
    {
      id: 'seed-in-zakir-fxb2atcN6RM',
      source: 'youtube',
      embedCode: 'fxb2atcN6RM',
      title: 'Fresh Mind Se Padhai | Zakir Khan | Hindi Stand-Up Comedy',
      channelName: 'Zakir Khan',
      channelHandle: '@ZakirKhan',
      category: 'Indian Stand-Up Comedy',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Comedy', 'Entertainment'],
      originalUrl: 'https://www.youtube.com/shorts/fxb2atcN6RM',
      thumbnailUrl: 'https://i.ytimg.com/vi/fxb2atcN6RM/hqdefault.jpg',
      baseLikes: 24100,
    },
    {
      id: 'seed-in-bhojpuri-7EtBzGj4AyY',
      source: 'youtube',
      embedCode: '7EtBzGj4AyY',
      title: 'धनिया मोर शहरी बाड़ी | Khesari Lal Yadav, Pallavi Singh | Bhojpuri Song',
      channelName: 'Khesari Music World',
      channelHandle: '@KhesariMusicWorld',
      category: 'Bhojpuri Superhit',
      region: 'IN',
      language: 'bhojpuri',
      tags: ['India', 'Bhojpuri', 'Music', 'Entertainment'],
      originalUrl: 'https://www.youtube.com/shorts/7EtBzGj4AyY',
      thumbnailUrl: 'https://i.ytimg.com/vi/7EtBzGj4AyY/hqdefault.jpg',
      baseLikes: 16800,
    },
    {
      id: 'seed-gl-nasa-KsHNRgtsrNA',
      source: 'youtube',
      embedCode: 'KsHNRgtsrNA',
      title: 'Goddard Glossary: The Lunar & Planetary Terminator Line',
      channelName: 'NASA Goddard',
      channelHandle: '@NASAGoddard',
      category: 'Global Space Short',
      region: 'GLOBAL',
      language: 'english',
      tags: ['Other Countries'],
      originalUrl: 'https://www.youtube.com/shorts/KsHNRgtsrNA',
      thumbnailUrl: 'https://i.ytimg.com/vi/KsHNRgtsrNA/hq2.jpg',
      baseLikes: 1940,
    },
    {
      id: 'seed-in-bassi-mbOO0Z6ryO0',
      source: 'youtube',
      embedCode: 'mbOO0Z6ryO0',
      title: 'Ambulance — Stand Up Comedy Ft. Anubhav Singh Bassi',
      channelName: 'Anubhav Singh Bassi',
      channelHandle: '@AnubhavSinghBassi',
      category: 'Hindi Stand-Up Comedy',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Comedy', 'Entertainment'],
      originalUrl: 'https://www.youtube.com/watch?v=mbOO0Z6ryO0',
      thumbnailUrl: 'https://i.ytimg.com/vi/mbOO0Z6ryO0/hqdefault.jpg',
      baseLikes: 31200,
    },
    {
      id: 'seed-in-sony-D2iTQnJdHAA',
      source: 'youtube',
      embedCode: 'D2iTQnJdHAA',
      title: 'Jai Hind | Udta Teer | Ayushmann Khurrana, Sara | Sachin-Jigar',
      channelName: 'Sony Music India',
      channelHandle: '@SonyMusicIndia',
      category: 'Indian Patriotic & Music',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Music', 'Entertainment'],
      originalUrl: 'https://www.youtube.com/watch?v=D2iTQnJdHAA',
      thumbnailUrl: 'https://i.ytimg.com/vi/D2iTQnJdHAA/hqdefault.jpg',
      baseLikes: 12900,
    },
    {
      id: 'seed-in-techno-OVgNvkHGOlE',
      source: 'youtube',
      embedCode: 'OVgNvkHGOlE',
      title: 'I TRIED THE ANIME VERSION OF GTA! | Techno Gamerz Hindi',
      channelName: 'Techno Gamerz',
      channelHandle: '@TechnoGamerzOfficial',
      category: 'Indian Gaming',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Gaming', 'Entertainment'],
      originalUrl: 'https://www.youtube.com/watch?v=OVgNvkHGOlE',
      thumbnailUrl: 'https://i.ytimg.com/vi/OVgNvkHGOlE/hqdefault.jpg',
      baseLikes: 28500,
    },
    {
      id: 'seed-in-bhojpuri-RCJGJpERHqU',
      source: 'youtube',
      embedCode: 'RCJGJpERHqU',
      title: 'Aadit Hoi Na Sahay | Shivani Singh & Mahi Shrivastava | Bhojpuri Geet',
      channelName: 'Worldwide Records Bhojpuri',
      channelHandle: '@WorldwideRecordsBhojpuri',
      category: 'Bhojpuri Folk & Festival',
      region: 'IN',
      language: 'bhojpuri',
      tags: ['India', 'Bhojpuri', 'Music', 'Entertainment'],
      originalUrl: 'https://www.youtube.com/shorts/RCJGJpERHqU',
      thumbnailUrl: 'https://i.ytimg.com/vi/RCJGJpERHqU/hqdefault.jpg',
      baseLikes: 8740,
    },
    {
      id: 'seed-gl-costa-LXb3EKWsInQ',
      source: 'youtube',
      embedCode: 'LXb3EKWsInQ',
      title: 'Costa Rica in 4K 60fps HDR — Tropical Night & Rainforest',
      channelName: 'Jacob + Katie Schwarz',
      channelHandle: '@JacobKatieSchwarz',
      category: 'Global 4K Nature',
      region: 'GLOBAL',
      language: 'english',
      tags: ['Other Countries'],
      originalUrl: 'https://www.youtube.com/watch?v=LXb3EKWsInQ',
      thumbnailUrl: 'https://i.ytimg.com/vi/LXb3EKWsInQ/hqdefault.jpg',
      baseLikes: 4210,
    },
    {
      id: 'seed-in-bbkivines-5Sr9XAMg0e0',
      source: 'youtube',
      embedCode: '5Sr9XAMg0e0',
      title: 'Dhindora S1E4 Saste Sherlock | Bhuvan Bam | BB Ki Vines',
      channelName: 'BB Ki Vines',
      channelHandle: '@BBKiVines',
      category: 'Indian Comedy',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Comedy', 'Entertainment'],
      originalUrl: 'https://www.youtube.com/shorts/5Sr9XAMg0e0',
      thumbnailUrl: 'https://i.ytimg.com/vi/5Sr9XAMg0e0/hqdefault.jpg',
      baseLikes: 19600,
    },
    {
      id: 'seed-in-ashish-L2UdqRfJJLI',
      source: 'youtube',
      embedCode: 'L2UdqRfJJLI',
      title: 'Diwali Special Celebration | Ashish Chanchlani Vines',
      channelName: 'Ashish Chanchlani Vines',
      channelHandle: '@ashishchanchlanivines',
      category: 'Indian Festival & Comedy',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Comedy', 'Entertainment'],
      originalUrl: 'https://www.youtube.com/shorts/L2UdqRfJJLI',
      thumbnailUrl: 'https://i.ytimg.com/vi/L2UdqRfJJLI/hqdefault.jpg',
      baseLikes: 22300,
    },
    {
      id: 'seed-in-yrf-wi5-sFqJvOI',
      source: 'youtube',
      embedCode: 'wi5-sFqJvOI',
      title: 'Kaun kaun single hai yahaan? | Befikre | Ranveer Singh | YRF',
      channelName: 'YRF (Yash Raj Films)',
      channelHandle: '@yrf',
      category: 'Bollywood Shorts',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Entertainment', 'Comedy'],
      originalUrl: 'https://www.youtube.com/shorts/wi5-sFqJvOI',
      thumbnailUrl: 'https://i.ytimg.com/vi/wi5-sFqJvOI/hqdefault.jpg',
      baseLikes: 11800,
    },
    {
      id: 'seed-in-isro-qIiYr3tRSqE',
      source: 'youtube',
      embedCode: 'qIiYr3tRSqE',
      title: 'ISRO GSLV-F18 / NVS-03 Sriharikota Launch Mission Highlights',
      channelName: 'ISRO Official',
      channelHandle: '@isroofficial5866',
      category: 'Indian Space Mission',
      region: 'IN',
      language: 'english',
      tags: ['India', 'Entertainment'],
      originalUrl: 'https://www.youtube.com/watch?v=qIiYr3tRSqE',
      thumbnailUrl: 'https://i.ytimg.com/vi/qIiYr3tRSqE/hqdefault.jpg',
      baseLikes: 15400,
    },
    {
      id: 'seed-gl-dune-Way9Dexny3w',
      source: 'youtube',
      embedCode: 'Way9Dexny3w',
      title: 'Dune: Part Two — Official Desert Moon & Arrakis Trailer',
      channelName: 'Warner Bros. Pictures',
      channelHandle: '@WarnerBros',
      category: 'Global Sci-Fi Cinema',
      region: 'GLOBAL',
      language: 'english',
      tags: ['Other Countries', 'Entertainment'],
      originalUrl: 'https://www.youtube.com/watch?v=Way9Dexny3w',
      thumbnailUrl: 'https://i.ytimg.com/vi/Way9Dexny3w/hqdefault.jpg',
      baseLikes: 8530,
    },
    {
      id: 'seed-in-bhojpuri-C-KWpyz9iRM',
      source: 'youtube',
      embedCode: 'C-KWpyz9iRM',
      title: 'खजाना | Khajana | Shubham Raj (SBR) | Bhojpuri Song',
      channelName: 'Saregama Hum Bhojpuri',
      channelHandle: '@SaregamaHumBhojpuri',
      category: 'Bhojpuri Music',
      region: 'IN',
      language: 'bhojpuri',
      tags: ['India', 'Bhojpuri', 'Music', 'Entertainment'],
      originalUrl: 'https://www.youtube.com/watch?v=C-KWpyz9iRM',
      thumbnailUrl: 'https://i.ytimg.com/vi/C-KWpyz9iRM/hqdefault.jpg',
      baseLikes: 7650,
    },
    {
      id: 'seed-in-totalgaming--0aRp83-pGk',
      source: 'youtube',
      embedCode: '-0aRp83-pGk',
      title: 'GTA 5 Part 27 (Hindi Dubbed Gameplay) | Total Gaming',
      channelName: 'Total Gaming',
      channelHandle: '@TotalGaming093',
      category: 'Indian Gaming',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Gaming', 'Entertainment'],
      originalUrl: 'https://www.youtube.com/watch?v=-0aRp83-pGk',
      thumbnailUrl: 'https://i.ytimg.com/vi/-0aRp83-pGk/hqdefault.jpg',
      baseLikes: 19200,
    },
    {
      id: 'seed-in-zee-a6v8JI6oJF8',
      source: 'youtube',
      embedCode: 'a6v8JI6oJF8',
      title: 'Raksha Bandhan Reprise | Akshay Kumar, Shreya Ghoshal | Zee Music',
      channelName: 'Zee Music Company',
      channelHandle: '@zeemusiccompany',
      category: 'Indian Festival Music',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Music', 'Entertainment'],
      originalUrl: 'https://www.youtube.com/shorts/a6v8JI6oJF8',
      thumbnailUrl: 'https://i.ytimg.com/vi/a6v8JI6oJF8/hqdefault.jpg',
      baseLikes: 10500,
    },
    {
      id: 'seed-in-prime-3rJ5LHELfks',
      source: 'youtube',
      embedCode: '3rJ5LHELfks',
      title: 'Paresh Rawal Faces Amrish Puri | Hulchul Classic Hindi Comedy',
      channelName: 'Prime Video India',
      channelHandle: '@PrimeVideoIN',
      category: 'Bollywood Comedy',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Comedy', 'Entertainment'],
      originalUrl: 'https://www.youtube.com/shorts/3rJ5LHELfks',
      thumbnailUrl: 'https://i.ytimg.com/vi/3rJ5LHELfks/hqdefault.jpg',
      baseLikes: 17300,
    },
    {
      id: 'seed-gl-fireship-Tn6-PIqc4UM',
      source: 'youtube',
      embedCode: 'Tn6-PIqc4UM',
      title: 'React in 100 Seconds — Fast Developer Short',
      channelName: 'Fireship',
      channelHandle: '@Fireship',
      category: 'Global Code & Tech',
      region: 'GLOBAL',
      language: 'english',
      tags: ['Other Countries'],
      originalUrl: 'https://www.youtube.com/watch?v=Tn6-PIqc4UM',
      thumbnailUrl: 'https://i.ytimg.com/vi/Tn6-PIqc4UM/hqdefault.jpg',
      baseLikes: 7850,
    },

    // --- VERIFIED PUBLIC INSTAGRAM REELS (80% INDIA / 20% GLOBAL) ---
    {
      id: 'seed-ig-in-isro-DcRNjRGh8G1',
      source: 'instagram',
      embedCode: 'DcRNjRGh8G1',
      title: 'National Space Day Message from Dr. V. Narayanan, Chairman ISRO',
      channelName: 'ISRO (Official Instagram)',
      channelHandle: '@isro.dos',
      category: 'Indian Space Mission (IG)',
      region: 'IN',
      language: 'english',
      tags: ['India', 'Entertainment'],
      originalUrl: 'https://www.instagram.com/reel/DcRNjRGh8G1/',
      baseLikes: 38400,
    },
    {
      id: 'seed-ig-in-bcci-DdzB8x3zoxq',
      source: 'instagram',
      embedCode: 'DdzB8x3zoxq',
      title: '55 ODI Centuries Young — Virat Kohli on Unlocking a New Version of Himself | Team India',
      channelName: 'Team India (BCCI Official)',
      channelHandle: '@indiancricketteam',
      category: 'Indian Cricket & Sports (IG)',
      region: 'IN',
      language: 'english',
      tags: ['India', 'Entertainment'],
      originalUrl: 'https://www.instagram.com/reel/DdzB8x3zoxq/',
      baseLikes: 92500,
    },
    {
      id: 'seed-ig-in-bcci-DejmfjNz14h',
      source: 'instagram',
      embedCode: 'DejmfjNz14h',
      title: 'Captain Smriti Mandhana Wins Her First Toss as Team India Full-Time T20I Captain',
      channelName: 'Team India (BCCI Official)',
      channelHandle: '@indiancricketteam',
      category: 'Indian Cricket & Sports (IG)',
      region: 'IN',
      language: 'english',
      tags: ['India', 'Entertainment'],
      originalUrl: 'https://www.instagram.com/reel/DejmfjNz14h/',
      baseLikes: 64100,
    },
    {
      id: 'seed-ig-in-ranveer-DdL95Kmsgqo',
      source: 'instagram',
      embedCode: 'DdL95Kmsgqo',
      title: 'ISRO Continues to Prove Why It Belongs Among the Elite Space Agencies — Jai Hind',
      channelName: 'Ranveer Allahbadia',
      channelHandle: '@ranveerallahbadia',
      category: 'Indian Creator & Podcast (IG)',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Entertainment'],
      originalUrl: 'https://www.instagram.com/reel/DdL95Kmsgqo/',
      baseLikes: 45200,
    },
    {
      id: 'seed-ig-gl-nasa-Dbn-XJhk0_-',
      source: 'instagram',
      embedCode: 'Dbn-XJhk0_-',
      title: 'Lunar Landers, Assemble — Next Generation Commercial Lunar Landers in Clean Rooms',
      channelName: 'NASA (Official Instagram)',
      channelHandle: '@nasa',
      category: 'Global Lunar & Space (IG)',
      region: 'GLOBAL',
      language: 'english',
      tags: ['Other Countries', 'Entertainment'],
      originalUrl: 'https://www.instagram.com/reel/Dbn-XJhk0_-/',
      baseLikes: 51900,
    },
    {
      id: 'seed-ig-in-bcci-DeI2UaHzKix',
      source: 'instagram',
      embedCode: 'DeI2UaHzKix',
      title: 'Indian Cricket Is in a Very Good Space: VVS Laxman on Coaching Team India',
      channelName: 'Team India (BCCI Official)',
      channelHandle: '@indiancricketteam',
      category: 'Indian Cricket & Sports (IG)',
      region: 'IN',
      language: 'english',
      tags: ['India', 'Entertainment'],
      originalUrl: 'https://www.instagram.com/reel/DeI2UaHzKix/',
      baseLikes: 48700,
    },
    {
      id: 'seed-ig-in-isrosight-DfIOF-QMH5_',
      source: 'instagram',
      embedCode: 'DfIOF-QMH5_',
      title: 'Lift-Off of GSLV-F18 Carrying NVS-03 from SDSC SHAR Sriharikota',
      channelName: 'ISRO Sight',
      channelHandle: '@isrosight',
      category: 'Indian Space Launch (IG)',
      region: 'IN',
      language: 'english',
      tags: ['India', 'Entertainment'],
      originalUrl: 'https://www.instagram.com/reel/DfIOF-QMH5_/',
      baseLikes: 29400,
    },
    {
      id: 'seed-ig-in-nationsradar-DfK5RwIyd1L',
      source: 'instagram',
      embedCode: 'DfK5RwIyd1L',
      title: 'ISRO Successfully Launched NVS-03 Aboard GSLV-F18 from Sriharikota (Hindi Explainer)',
      channelName: 'The Nations Radar',
      channelHandle: '@thenationsradar',
      category: 'Hindi Space & Comedy Reaction (IG)',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Comedy', 'Entertainment'],
      originalUrl: 'https://www.instagram.com/reel/DfK5RwIyd1L/',
      baseLikes: 33800,
    },
    {
      id: 'seed-ig-in-satirical-DfUnE4MO6Km',
      source: 'instagram',
      embedCode: 'DfUnE4MO6Km',
      title: 'How ISRO Revived a Project — Made in India NavIC Navigation Explainer',
      channelName: 'Satirical Citizen',
      channelHandle: '@satirical_citizen',
      category: 'Indian Education & Explainer (IG)',
      region: 'IN',
      language: 'hindi',
      tags: ['India', 'Hindi', 'Entertainment'],
      originalUrl: 'https://www.instagram.com/reel/DfUnE4MO6Km/',
      baseLikes: 21600,
    },
    {
      id: 'seed-ig-gl-nasa-DbL6n0ggXDZ',
      source: 'instagram',
      embedCode: 'DbL6n0ggXDZ',
      title: 'Sound On! Cosmic Sonifications Turn Images From Across the Universe Into Music',
      channelName: 'NASA (Official Instagram)',
      channelHandle: '@nasa',
      category: 'Global Space & Music (IG)',
      region: 'GLOBAL',
      language: 'english',
      tags: ['Other Countries', 'Music', 'Entertainment'],
      originalUrl: 'https://www.instagram.com/reel/DbL6n0ggXDZ/',
      baseLikes: 44300,
    },
    {
      id: 'seed-ig-in-bcci-DcFZQLdFPZ1',
      source: 'instagram',
      embedCode: 'DcFZQLdFPZ1',
      title: 'Determination, Discipline, Patience — The DDP Philosophy Day 1 Heroics | Team India',
      channelName: 'Team India (BCCI Official)',
      channelHandle: '@indiancricketteam',
      category: 'Indian Cricket & Sports (IG)',
      region: 'IN',
      language: 'english',
      tags: ['India', 'Entertainment'],
      originalUrl: 'https://www.instagram.com/reel/DcFZQLdFPZ1/',
      baseLikes: 53900,
    },
    {
      id: 'seed-ig-gl-nasa-DbYmqpplO_N',
      source: 'instagram',
      embedCode: 'DbYmqpplO_N',
      title: 'The Sun and Moon Are Coming Together to Put On a Show for Earth',
      channelName: 'NASA (Official Instagram)',
      channelHandle: '@nasa',
      category: 'Global Eclipse & Lunar Science (IG)',
      region: 'GLOBAL',
      language: 'english',
      tags: ['Other Countries', 'Entertainment'],
      originalUrl: 'https://www.instagram.com/reel/DbYmqpplO_N/',
      baseLikes: 47800,
    },
  ];

  let cachedAggregatedReels: ServerReelEntry[] = [];
  let lastRssFetchTime = 0;

  function decodeXmlEntities(raw: string): string {
    return raw
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
  }

  /**
   * Interleaves Indian (`region === 'IN'`) and Global (`region === 'GLOBAL'`) reels
   * in an exact 4:1 ratio (80% India / 20% Other Countries) for the "For You" feed.
   */
  function interleaveIndia80Global20(items: ServerReelEntry[]): ServerReelEntry[] {
    const indiaPool = items.filter((item) => item.region === 'IN');
    const globalPool = items.filter((item) => item.region === 'GLOBAL');
    const result: ServerReelEntry[] = [];

    let inIdx = 0;
    let glIdx = 0;

    while (inIdx < indiaPool.length || glIdx < globalPool.length) {
      // Push up to 4 Indian reels (80%)
      for (let k = 0; k < 4 && inIdx < indiaPool.length; k++) {
        result.push(indiaPool[inIdx++]);
      }
      // Push 1 Global reel (20%)
      if (glIdx < globalPool.length) {
        result.push(globalPool[glIdx++]);
      }
    }

    return result;
  }

  async function getAggregatedServerReels(): Promise<ServerReelEntry[]> {
    const now = Date.now();
    if (
      cachedAggregatedReels.length > 30 &&
      now - lastRssFetchTime < 15 * 60 * 1000
    ) {
      return cachedAggregatedReels;
    }

    const indianChannelLists: ServerReelEntry[][] = [];
    const globalChannelLists: ServerReelEntry[][] = [];

    await Promise.all(
      OFFICIAL_YOUTUBE_RSS_CHANNELS.map(async (ch) => {
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 4500);
          const resp = await fetch(
            `https://www.youtube.com/feeds/videos.xml?channel_id=${encodeURIComponent(
              ch.channelId
            )}`,
            { signal: controller.signal }
          );
          clearTimeout(timeout);
          if (!resp.ok) return;
          const xml = await resp.text();
          const entryRegex =
            /<entry>[\s\S]*?<yt:videoId>([^<]+)<\/yt:videoId>[\s\S]*?<title>([^<]+)<\/title>[\s\S]*?<\/entry>/g;
          const items: ServerReelEntry[] = [];
          let match: RegExpExecArray | null;
          while ((match = entryRegex.exec(xml)) !== null) {
            const videoId = match[1].trim();
            const title = decodeXmlEntities(match[2].trim());
            if (videoId && title) {
              items.push({
                id: `rss-${ch.region.toLowerCase()}-${videoId}`,
                source: 'youtube',
                embedCode: videoId,
                title,
                channelName: ch.name,
                channelHandle: ch.handle,
                category: ch.category,
                region: ch.region,
                language: ch.language,
                tags: ch.tags,
                originalUrl: `https://www.youtube.com/shorts/${videoId}`,
                thumbnailUrl: `https://i.ytimg.com/vi/${videoId}/hqdefault.jpg`,
                baseLikes: 1200 + ((videoId.charCodeAt(0) * 43) % 9500),
              });
            }
          }
          if (items.length > 0) {
            if (ch.region === 'IN') {
              indianChannelLists.push(items);
            } else {
              globalChannelLists.push(items);
            }
          }
        } catch {
          // Ignore individual channel fetch timeout
        }
      })
    );

    const roundRobin = (lists: ServerReelEntry[][]): ServerReelEntry[] => {
      const out: ServerReelEntry[] = [];
      const maxLen = lists.reduce((m, l) => Math.max(m, l.length), 0);
      for (let i = 0; i < maxLen; i++) {
        for (const list of lists) {
          if (i < list.length) {
            out.push(list[i]);
          }
        }
      }
      return out;
    };

    const interleavedRss = interleaveIndia80Global20([
      ...roundRobin(indianChannelLists),
      ...roundRobin(globalChannelLists),
    ]);

    const seenKeys = new Set<string>();
    const seenUrls = new Set<string>();
    const deduplicated: ServerReelEntry[] = [];

    for (const item of [...SERVER_VERIFIED_SEED_REELS, ...interleavedRss]) {
      const codeKey = `${item.source}:${item.embedCode.toLowerCase()}`;
      const urlKey = item.originalUrl.toLowerCase();
      if (seenKeys.has(codeKey) || seenUrls.has(urlKey)) {
        continue;
      }
      seenKeys.add(codeKey);
      seenUrls.add(urlKey);
      deduplicated.push(item);
    }

    cachedAggregatedReels = interleaveIndia80Global20(deduplicated);
    lastRssFetchTime = now;
    return cachedAggregatedReels;
  }

  app.get('/api/reels/feed', async (req: Request, res: Response) => {
    try {
      const cursor = Math.max(0, parseInt(String(req.query.cursor || '0'), 10) || 0);
      const limit = Math.min(
        50,
        Math.max(1, parseInt(String(req.query.limit || '12'), 10) || 12)
      );
      const sourceFilter = String(req.query.source || 'all').toLowerCase();
      const categoryFilter = String(req.query.category || 'for_you').toLowerCase();
      const query = String(req.query.q || '').trim();

      const youtubeApiKey = cleanEnvValue(
        process.env.YOUTUBE_API_KEY,
        'YOUTUBE_API_KEY'
      );

      let catalog = await getAggregatedServerReels();
      let searchMode: 'youtube_data_api' | 'official_rss_and_oembed' =
        'official_rss_and_oembed';

      if (query && youtubeApiKey && sourceFilter !== 'instagram') {
        try {
          const ytSearchUrl = new URL(
            'https://www.googleapis.com/youtube/v3/search'
          );
          ytSearchUrl.searchParams.set('part', 'snippet');
          ytSearchUrl.searchParams.set('type', 'video');
          ytSearchUrl.searchParams.set('videoEmbeddable', 'true');
          ytSearchUrl.searchParams.set('regionCode', 'IN');
          ytSearchUrl.searchParams.set('maxResults', '25');
          ytSearchUrl.searchParams.set('q', `${query} #shorts`);
          ytSearchUrl.searchParams.set('key', youtubeApiKey);

          const ytResp = await fetch(ytSearchUrl.toString());
          if (ytResp.ok) {
            const ytJson = (await ytResp.json()) as {
              items?: Array<{
                id?: { videoId?: string };
                snippet?: {
                  title?: string;
                  channelTitle?: string;
                  thumbnails?: { high?: { url?: string } };
                };
              }>;
            };
            if (Array.isArray(ytJson.items) && ytJson.items.length > 0) {
              searchMode = 'youtube_data_api';
              const apiItems: ServerReelEntry[] = [];
              for (const raw of ytJson.items) {
                const vid = raw.id?.videoId?.trim();
                if (!vid) continue;
                const chTitle = raw.snippet?.channelTitle || 'YouTube Creator';
                const titleDecoded = decodeXmlEntities(
                  raw.snippet?.title || `YouTube Short (${vid})`
                );
                const hasDevanagari = /[\u0900-\u097F]/.test(titleDecoded);
                apiItems.push({
                  id: `ytapi-${vid}`,
                  source: 'youtube',
                  embedCode: vid,
                  title: titleDecoded,
                  channelName: chTitle,
                  channelHandle: `@${chTitle.replace(/\s+/g, '').toLowerCase()}`,
                  category: 'YouTube Search Result',
                  region: hasDevanagari ? 'IN' : 'GLOBAL',
                  language: hasDevanagari ? 'hindi' : 'english',
                  tags: hasDevanagari ? ['India', 'Hindi'] : ['Other Countries'],
                  originalUrl: `https://www.youtube.com/shorts/${vid}`,
                  thumbnailUrl:
                    raw.snippet?.thumbnails?.high?.url ||
                    `https://i.ytimg.com/vi/${vid}/hqdefault.jpg`,
                  baseLikes: 1200,
                });
              }
              const seen = new Set<string>();
              const merged: ServerReelEntry[] = [];
              for (const item of [...apiItems, ...catalog]) {
                const k = `${item.source}:${item.embedCode.toLowerCase()}`;
                if (!seen.has(k)) {
                  seen.add(k);
                  merged.push(item);
                }
              }
              catalog = merged;
            }
          }
        } catch {
          // Fall back to aggregated official RSS catalog
        }
      }

      let filtered = catalog;
      if (sourceFilter === 'youtube' || sourceFilter === 'instagram') {
        filtered = filtered.filter((item) => item.source === sourceFilter);
      }

      // Apply India-First Category Filter
      if (categoryFilter === 'india') {
        filtered = filtered.filter((item) => item.region === 'IN');
      } else if (categoryFilter === 'bhojpuri') {
        filtered = filtered.filter(
          (item) =>
            item.language === 'bhojpuri' || item.tags.includes('Bhojpuri')
        );
      } else if (categoryFilter === 'hindi') {
        filtered = filtered.filter(
          (item) => item.language === 'hindi' || item.tags.includes('Hindi')
        );
      } else if (categoryFilter === 'comedy') {
        filtered = filtered.filter((item) => item.tags.includes('Comedy'));
      } else if (categoryFilter === 'entertainment') {
        filtered = filtered.filter((item) =>
          item.tags.includes('Entertainment')
        );
      } else if (categoryFilter === 'music') {
        filtered = filtered.filter((item) => item.tags.includes('Music'));
      } else if (categoryFilter === 'gaming') {
        filtered = filtered.filter((item) => item.tags.includes('Gaming'));
      } else if (categoryFilter === 'other_countries') {
        filtered = filtered.filter(
          (item) =>
            item.region === 'GLOBAL' || item.tags.includes('Other Countries')
        );
      } else {
        // Default "For You" -> enforce 80% India / 20% Other Countries ratio
        filtered = interleaveIndia80Global20(filtered);
      }

      if (query && searchMode !== 'youtube_data_api') {
        const qLower = query.toLowerCase();
        filtered = filtered.filter(
          (item) =>
            item.title.toLowerCase().includes(qLower) ||
            item.channelName.toLowerCase().includes(qLower) ||
            item.channelHandle.toLowerCase().includes(qLower) ||
            item.category.toLowerCase().includes(qLower) ||
            item.language.toLowerCase().includes(qLower) ||
            item.tags.some((t) => t.toLowerCase().includes(qLower)) ||
            item.embedCode.toLowerCase().includes(qLower)
        );
      }

      const slice = filtered.slice(cursor, cursor + limit);
      const nextCursor = cursor + slice.length;
      const hasMore = nextCursor < filtered.length;

      const indiaCountInSlice = slice.filter((i) => i.region === 'IN').length;

      res.json({
        items: slice,
        nextCursor,
        hasMore,
        totalAvailable: filtered.length,
        indiaCountInSlice,
        searchMode,
      });
    } catch (err) {
      res.status(500).json({
        error:
          err instanceof Error
            ? err.message
            : 'Failed to load dynamic reels feed.',
      });
    }
  });

  /**
   * Checks whether Instagram's official embed endpoint (`https://www.instagram.com/reel/<SHORTCODE>/embed/`)
   * permits embedding for a given public shortcode or returns an EmbedIsBroken / blocked response.
   */
  app.get(
    '/api/reels/instagram-embed-status',
    async (req: Request, res: Response) => {
      const shortcode = String(req.query.shortcode || '')
        .trim()
        .replace(/[^a-zA-Z0-9_-]/g, '');
      if (!shortcode || shortcode.length < 5 || shortcode.length > 32) {
        return res.status(400).json({
          shortcode,
          embedPermitted: false,
          reason: 'Invalid Instagram Reel shortcode.',
        });
      }

      const embedUrl = `https://www.instagram.com/reel/${encodeURIComponent(
        shortcode
      )}/embed/`;
      const originalUrl = `https://www.instagram.com/reel/${encodeURIComponent(
        shortcode
      )}/`;

      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        const resp = await fetch(embedUrl, {
          signal: controller.signal,
        });
        clearTimeout(timeout);

        if (!resp.ok) {
          return res.json({
            shortcode,
            embedUrl,
            originalUrl,
            embedPermitted: false,
            reason: `Instagram returned HTTP ${resp.status}.`,
          });
        }

        const html = await resp.text();
        const isBroken =
          html.includes('EmbedIsBroken') ||
          html.includes('Sorry, this page isn') ||
          html.includes('may have been removed');
        const hasEmbeddedMedia =
          html.includes('class="EmbeddedMedia"') ||
          html.includes('class="EmbedVideo"') ||
          html.includes('class="Embed"');

        return res.json({
          shortcode,
          embedUrl,
          originalUrl,
          embedPermitted: !isBroken && hasEmbeddedMedia,
          reason:
            !isBroken && hasEmbeddedMedia
              ? 'Official Instagram embed page loaded. Note: Instagram may still require opening on Instagram for inline video playback depending on browser third-party cookie/iframe policies.'
              : 'Instagram blocked or disabled embedding for this Reel.',
        });
      } catch {
        return res.json({
          shortcode,
          embedUrl,
          originalUrl,
          embedPermitted: true,
          reason: 'Proceeding with client-side official Instagram embed.',
        });
      }
    }
  );

  // ============================================================================
  // MOON GLOBAL NEWS HOME FEED — REAL PUBLIC RSS AGGREGATOR (60% INDIA / 40% WORLD)
  // ============================================================================

  interface PublicNewsRssSource {
    id: string;
    name: string;
    handle: string;
    logoBadge: string;
    url: string;
    publisherWebsite: string;
    defaultCountry: 'IN' | 'US' | 'GB' | 'CN' | 'RU' | 'JP' | 'GLOBAL';
    language: 'hi' | 'en';
    defaultCategory:
      | 'Breaking News'
      | 'India News'
      | 'World News'
      | 'Politics'
      | 'Technology'
      | 'Science'
      | 'Business'
      | 'Sports'
      | 'Entertainment'
      | 'Bihar News'
      | 'Traders';
    isIndia: boolean;
  }

  interface MoonNewsArticleItem {
    id: string;
    sourceId: string;
    sourceName: string;
    sourceHandle: string;
    sourceLogoBadge: string;
    sourceWebsite: string;
    headline: string;
    summary: string;
    hindiSummary: string;
    articleUrl: string;
    imageUrl?: string;
    publishedAtIso: string;
    publishedAtText: string;
    publishedDateIst: string;
    isTodayIst: boolean;
    isYesterdayIst: boolean;
    dayBucket: 'today' | 'previous';
    relativeTimeText: string;
    countryCode: 'IN' | 'US' | 'GB' | 'CN' | 'RU' | 'JP' | 'GLOBAL';
    countryLabel: string;
    language: 'hi' | 'en';
    primaryCategory: string;
    categories: string[];
    isIndia: boolean;
    isBihar: boolean;
  }

  const PUBLIC_NEWS_RSS_SOURCES: PublicNewsRssSource[] = [
    // INDIA & HINDI SOURCES (60% Feed Target)
    {
      id: 'bbc-hindi',
      name: 'BBC News हिंदी',
      handle: '@bbchindi',
      logoBadge: 'BBC HI',
      url: 'https://feeds.bbci.co.uk/hindi/rss.xml',
      publisherWebsite: 'https://www.bbc.com/hindi',
      defaultCountry: 'IN',
      language: 'hi',
      defaultCategory: 'India News',
      isIndia: true,
    },
    {
      id: 'ndtv-hindi',
      name: 'NDTV इंडिया (हिंदी)',
      handle: '@ndtvindia',
      logoBadge: 'NDTV',
      url: 'https://feeds.feedburner.com/ndtvkhabar-latest',
      publisherWebsite: 'https://ndtv.in',
      defaultCountry: 'IN',
      language: 'hi',
      defaultCategory: 'India News',
      isIndia: true,
    },
    {
      id: 'google-bihar-today-hi',
      name: 'बिहार आज की ताज़ा ख़बर (Bihar Daily RSS)',
      handle: '@bihartoday.hi',
      logoBadge: 'BIHAR',
      url: 'https://news.google.com/rss/search?q=(Bihar+OR+%E0%A4%AC%E0%A4%BF%E0%A4%B9%E0%A4%BE%E0%A4%B0+OR+Patna+OR+%E0%A4%AA%E0%A4%9F%E0%A4%A8%E0%A4%BE)+when:1d&hl=hi&gl=IN&ceid=IN:hi',
      publisherWebsite: 'https://news.google.com',
      defaultCountry: 'IN',
      language: 'hi',
      defaultCategory: 'Bihar News',
      isIndia: true,
    },
    {
      id: 'google-bihar-hi',
      name: 'बिहार समाचार (Bihar Hindi RSS)',
      handle: '@biharnews.hi',
      logoBadge: 'BIHAR',
      url: 'https://news.google.com/rss/search?q=Bihar+OR+%E0%A4%AC%E0%A4%BF%E0%A4%B9%E0%A4%BE%E0%A4%B0+OR+Patna&hl=hi&gl=IN&ceid=IN:hi',
      publisherWebsite: 'https://news.google.com',
      defaultCountry: 'IN',
      language: 'hi',
      defaultCategory: 'Bihar News',
      isIndia: true,
    },
    {
      id: 'toi-india',
      name: 'Times of India',
      handle: '@timesofindia',
      logoBadge: 'TOI',
      url: 'https://timesofindia.indiatimes.com/rssfeedstopstories.cms',
      publisherWebsite: 'https://timesofindia.indiatimes.com',
      defaultCountry: 'IN',
      language: 'en',
      defaultCategory: 'India News',
      isIndia: true,
    },
    {
      id: 'bbc-india',
      name: 'BBC News India',
      handle: '@bbcindia',
      logoBadge: 'BBC IN',
      url: 'https://feeds.bbci.co.uk/news/world/asia/india/rss.xml',
      publisherWebsite: 'https://www.bbc.com/news/world/asia/india',
      defaultCountry: 'IN',
      language: 'en',
      defaultCategory: 'India News',
      isIndia: true,
    },
    {
      id: 'google-india-hi',
      name: 'भारत मुख्य समाचार (Hindi RSS)',
      handle: '@bharatnews.hi',
      logoBadge: 'BHARAT',
      url: 'https://news.google.com/rss?hl=hi&gl=IN&ceid=IN:hi',
      publisherWebsite: 'https://news.google.com',
      defaultCountry: 'IN',
      language: 'hi',
      defaultCategory: 'Breaking News',
      isIndia: true,
    },
    {
      id: 'google-tech-hi',
      name: 'टेक्नोलॉजी न्यूज़ (India Tech Hindi)',
      handle: '@techindia.hi',
      logoBadge: 'TECH HI',
      url: 'https://news.google.com/rss/headlines/section/topic/TECHNOLOGY?hl=hi&gl=IN&ceid=IN:hi',
      publisherWebsite: 'https://news.google.com',
      defaultCountry: 'IN',
      language: 'hi',
      defaultCategory: 'Technology',
      isIndia: true,
    },
    {
      id: 'google-sports-hi',
      name: 'खेल समाचार (India Sports Hindi)',
      handle: '@sportsindia.hi',
      logoBadge: 'SPORTS',
      url: 'https://news.google.com/rss/headlines/section/topic/SPORTS?hl=hi&gl=IN&ceid=IN:hi',
      publisherWebsite: 'https://news.google.com',
      defaultCountry: 'IN',
      language: 'hi',
      defaultCategory: 'Sports',
      isIndia: true,
    },

    // WORLDWIDE SOURCES (40% Feed Target — USA, UK, China, Russia, Japan, Global)
    {
      id: 'bbc-world',
      name: 'BBC World News',
      handle: '@bbcworld',
      logoBadge: 'BBC',
      url: 'https://feeds.bbci.co.uk/news/world/rss.xml',
      publisherWebsite: 'https://www.bbc.com/news/world',
      defaultCountry: 'GB',
      language: 'en',
      defaultCategory: 'World News',
      isIndia: false,
    },
    {
      id: 'npr-usa',
      name: 'NPR News (USA)',
      handle: '@npr',
      logoBadge: 'NPR US',
      url: 'https://feeds.npr.org/1001/rss.xml',
      publisherWebsite: 'https://www.npr.org/sections/news/',
      defaultCountry: 'US',
      language: 'en',
      defaultCategory: 'World News',
      isIndia: false,
    },
    {
      id: 'npr-world',
      name: 'NPR International',
      handle: '@nprworld',
      logoBadge: 'NPR',
      url: 'https://feeds.npr.org/1004/rss.xml',
      publisherWebsite: 'https://www.npr.org/sections/world/',
      defaultCountry: 'US',
      language: 'en',
      defaultCategory: 'World News',
      isIndia: false,
    },
    {
      id: 'dw-world',
      name: 'DW News (Deutsche Welle)',
      handle: '@dwnews',
      logoBadge: 'DW',
      url: 'https://rss.dw.com/xml/rss-en-world',
      publisherWebsite: 'https://www.dw.com/en',
      defaultCountry: 'GLOBAL',
      language: 'en',
      defaultCategory: 'World News',
      isIndia: false,
    },
    {
      id: 'bbc-asia',
      name: 'BBC News Asia (China • Japan • Asia)',
      handle: '@bbcasia',
      logoBadge: 'ASIA',
      url: 'https://feeds.bbci.co.uk/news/world/asia/rss.xml',
      publisherWebsite: 'https://www.bbc.com/news/world/asia',
      defaultCountry: 'GLOBAL',
      language: 'en',
      defaultCategory: 'World News',
      isIndia: false,
    },
    {
      id: 'bbc-europe',
      name: 'BBC News Europe (UK • Russia • Europe)',
      handle: '@bbceurope',
      logoBadge: 'EUROPE',
      url: 'https://feeds.bbci.co.uk/news/world/europe/rss.xml',
      publisherWebsite: 'https://www.bbc.com/news/world/europe',
      defaultCountry: 'GB',
      language: 'en',
      defaultCategory: 'World News',
      isIndia: false,
    },
    {
      id: 'bbc-tech',
      name: 'BBC Technology',
      handle: '@bbctech',
      logoBadge: 'TECH',
      url: 'https://feeds.bbci.co.uk/news/technology/rss.xml',
      publisherWebsite: 'https://www.bbc.com/news/technology',
      defaultCountry: 'GLOBAL',
      language: 'en',
      defaultCategory: 'Technology',
      isIndia: false,
    },
    {
      id: 'bbc-science',
      name: 'BBC Science & Environment',
      handle: '@bbcscience',
      logoBadge: 'SCI',
      url: 'https://feeds.bbci.co.uk/news/science_and_environment/rss.xml',
      publisherWebsite: 'https://www.bbc.com/news/science_and_environment',
      defaultCountry: 'GLOBAL',
      language: 'en',
      defaultCategory: 'Science',
      isIndia: false,
    },
    {
      id: 'bbc-business',
      name: 'BBC Business',
      handle: '@bbcbusiness',
      logoBadge: 'BIZ',
      url: 'https://feeds.bbci.co.uk/news/business/rss.xml',
      publisherWebsite: 'https://www.bbc.com/news/business',
      defaultCountry: 'GLOBAL',
      language: 'en',
      defaultCategory: 'Business',
      isIndia: false,
    },
    {
      id: 'bbc-sport',
      name: 'BBC Sport Worldwide',
      handle: '@bbcsport',
      logoBadge: 'SPORT',
      url: 'https://feeds.bbci.co.uk/sport/rss.xml',
      publisherWebsite: 'https://www.bbc.com/sport',
      defaultCountry: 'GLOBAL',
      language: 'en',
      defaultCategory: 'Sports',
      isIndia: false,
    },
    {
      id: 'bbc-entertainment',
      name: 'BBC Entertainment & Arts',
      handle: '@bbcentertainment',
      logoBadge: 'ARTS',
      url: 'https://feeds.bbci.co.uk/news/entertainment_and_arts/rss.xml',
      publisherWebsite: 'https://www.bbc.com/news/entertainment_and_arts',
      defaultCountry: 'GLOBAL',
      language: 'en',
      defaultCategory: 'Entertainment',
      isIndia: false,
    },
    // TRADERS & BUSINESS NEWS SOURCES FOR GLOBAL NEWS FEED
    {
      id: 'traders-india-stocks-hi',
      name: 'Indian Stock Market (Nifty 50 • Sensex • NSE/BSE)',
      handle: '@indiamarket',
      logoBadge: 'NIFTY',
      url: 'https://news.google.com/rss/search?q=(NSE+OR+BSE+OR+%22Nifty+50%22+OR+Sensex+OR+%22%E0%A4%B6%E0%A5%87%E0%A4%AF%E0%A4%B0+%E0%A4%AC%E0%A4%BE%E0%A4%9C%E0%A4%BE%E0%A4%B0%22+OR+%E0%A4%A8%E0%A4%BF%E0%A4%AB%E0%A5%8D%E0%A4%9F%E0%A5%80+OR+%E0%A4%B8%E0%A5%87%E0%A4%82%E0%A4%B8%E0%A5%87%E0%A4%95%E0%A5%8D%E0%A4%B8)+when:2d&hl=hi&gl=IN&ceid=IN:hi',
      publisherWebsite: 'https://www.nseindia.com',
      defaultCountry: 'IN',
      language: 'hi',
      defaultCategory: 'Traders',
      isIndia: true,
    },
    {
      id: 'traders-et-markets',
      name: 'Economic Times Markets (Traders)',
      handle: '@etmarkets',
      logoBadge: 'ET MKT',
      url: 'https://economictimes.indiatimes.com/markets/rssfeeds/1977021501.cms',
      publisherWebsite: 'https://economictimes.indiatimes.com/markets',
      defaultCountry: 'IN',
      language: 'en',
      defaultCategory: 'Traders',
      isIndia: true,
    },
    {
      id: 'traders-gold-silver-hi',
      name: 'Gold & Silver Bullion Market (सोना-चांदी बाजार)',
      handle: '@goldsilver.in',
      logoBadge: 'GOLD',
      url: 'https://news.google.com/rss/search?q=(%22Gold+Price%22+OR+%22Silver+Price%22+OR+%22MCX+Gold%22+OR+%22Gold+Rate%22+OR+%22%E0%A4%B8%E0%A5%8B%E0%A4%A8%E0%A5%87+%E0%A4%95%E0%A4%BE+%E0%A4%AD%E0%A4%BE%E0%A4%B5%22+OR+%22%E0%A4%9A%E0%A4%BE%E0%A4%82%E0%A4%A6%E0%A5%80+%E0%A4%95%E0%A4%BE+%E0%A4%AD%E0%A4%BE%E0%A4%B5%22+OR+%22%E0%A4%B8%E0%A4%B0%E0%A5%8D%E0%A4%B0%E0%A4%BE%E0%A4%AB%E0%A4%BE+%E0%A4%AC%E0%A4%BE%E0%A4%9C%E0%A4%BE%E0%A4%B0%22)+when:3d&hl=hi&gl=IN&ceid=IN:hi',
      publisherWebsite: 'https://www.mcxindia.com',
      defaultCountry: 'IN',
      language: 'hi',
      defaultCategory: 'Traders',
      isIndia: true,
    },
    {
      id: 'traders-company-updates-hi',
      name: 'Company Updates & Earnings (कंपनी अपडेट्स)',
      handle: '@companyupdates',
      logoBadge: 'CORP',
      url: 'https://news.google.com/rss/search?q=(%22Quarterly+Results%22+OR+IPO+OR+Dividend+OR+Reliance+OR+TCS+OR+Infosys+OR+HDFC+OR+%22%E0%A4%A4%E0%A4%BF%E0%A4%AE%E0%A4%BE%E0%A4%B9%E0%A5%80+%E0%A4%A8%E0%A4%A4%E0%A5%80%E0%A4%9C%E0%A5%87%22+OR+%22%E0%A4%95%E0%A4%82%E0%A4%AA%E0%A4%A8%E0%A5%80%22)+when:2d&hl=hi&gl=IN&ceid=IN:hi',
      publisherWebsite: 'https://www.bseindia.com',
      defaultCountry: 'IN',
      language: 'hi',
      defaultCategory: 'Traders',
      isIndia: true,
    },
    {
      id: 'traders-education-hi',
      name: 'Trading & Investor Education (ट्रेडिंग शिक्षा)',
      handle: '@tradingedu',
      logoBadge: 'EDU',
      url: 'https://news.google.com/rss/search?q=(SEBI+OR+%22Mutual+Fund%22+OR+SIP+OR+%E0%A4%A8%E0%A4%BF%E0%A4%B5%E0%A5%87%E0%A4%B6+OR+%22%E0%A4%AE%E0%A5%8D%E0%A4%AF%E0%A5%82%E0%A4%9A%E0%A5%81%E0%A4%85%E0%A4%B2+%E0%A4%AB%E0%A4%82%E0%A4%A1%22)+when:7d&hl=hi&gl=IN&ceid=IN:hi',
      publisherWebsite: 'https://investor.sebi.gov.in',
      defaultCountry: 'IN',
      language: 'hi',
      defaultCategory: 'Traders',
      isIndia: true,
    },
    {
      id: 'traders-global-markets',
      name: 'International Market News (Wall Street • Nasdaq • Global)',
      handle: '@globaltraders',
      logoBadge: 'GLOBAL',
      url: 'https://news.google.com/rss/search?q=(%22Wall+Street%22+OR+Nasdaq+OR+%22S%26P+500%22+OR+%22Global+Markets%22+OR+Nikkei+OR+FTSE)+when:3d&hl=en-IN&gl=IN&ceid=IN:en',
      publisherWebsite: 'https://www.bbc.com/news/business',
      defaultCountry: 'GLOBAL',
      language: 'en',
      defaultCategory: 'Traders',
      isIndia: false,
    },
  ];

  const decodeRssXmlEntities = (raw: string): string => {
    if (!raw) return '';
    return raw
      .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#039;/g, "'")
      .replace(/&apos;/g, "'")
      .replace(/&nbsp;/g, ' ')
      .replace(/&#(\d+);/g, (_m, dec) => {
        const code = Number(dec);
        return Number.isFinite(code) ? String.fromCharCode(code) : '';
      })
      .replace(/&#x([0-9a-fA-F]+);/g, (_m, hex) => {
        const code = parseInt(hex, 16);
        return Number.isFinite(code) ? String.fromCharCode(code) : '';
      });
  };

  const stripHtmlTags = (html: string): string => {
    return decodeRssXmlEntities(html)
      .replace(/<iframe[\s\S]*?<\/iframe>/gi, ' ')
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  };

  const extractTagContent = (xmlBlock: string, tagName: string): string => {
    const regex = new RegExp(
      `<${tagName}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tagName}>`,
      'i'
    );
    const match = xmlBlock.match(regex);
    return match ? decodeRssXmlEntities(match[1]).trim() : '';
  };

  const extractRssImageUrl = (itemXml: string): string | undefined => {
    // 1. Check <media:content url="..."> or <media:thumbnail url="...">
    const mediaMatch =
      itemXml.match(/<media:content[^>]+url=["']([^"']+)["']/i) ||
      itemXml.match(/<media:thumbnail[^>]+url=["']([^"']+)["']/i);
    if (mediaMatch && mediaMatch[1]) {
      let url = decodeRssXmlEntities(mediaMatch[1]);
      // Upgrade BBC 240px thumbnails to 800px high-resolution images
      if (url.includes('ichef.bbci.co.uk')) {
        url = url
          .replace('/standard/240/', '/standard/800/')
          .replace('/ws/240/', '/ws/800/');
      }
      return url;
    }

    // 2. Check <enclosure url="..." type="image/..." />
    const enclosureMatch =
      itemXml.match(
        /<enclosure[^>]+url=["']([^"']+)["'][^>]*type=["']image\/[^"']+["']/i
      ) ||
      itemXml.match(
        /<enclosure[^>]+type=["']image\/[^"']+["'][^>]*url=["']([^"']+)["']/i
      ) ||
      itemXml.match(/<enclosure[^>]+url=["']([^"']+\.(?:jpg|jpeg|png|webp|cms)[^"']*)["']/i);
    if (enclosureMatch && enclosureMatch[1]) {
      return decodeRssXmlEntities(enclosureMatch[1]);
    }

    // 3. Check <img src="..."> inside <content:encoded> or <description>
    const decodedItem = decodeRssXmlEntities(itemXml);
    const imgMatches = [...decodedItem.matchAll(/<img[^>]+src=["']([^"']+)["']/gi)];
    for (const match of imgMatches) {
      const candidate = match[1];
      if (
        candidate &&
        candidate.startsWith('http') &&
        !candidate.includes('npr-rss-pixel') &&
        !candidate.includes('1x1') &&
        !candidate.includes('tracker')
      ) {
        return candidate;
      }
    }

    return undefined;
  };

  const detectArticleCountry = (
    text: string,
    defaultCountry: 'IN' | 'US' | 'GB' | 'CN' | 'RU' | 'JP' | 'GLOBAL',
    isIndiaSource: boolean
  ): {
    code: 'IN' | 'US' | 'GB' | 'CN' | 'RU' | 'JP' | 'GLOBAL';
    label: string;
  } => {
    const lower = text.toLowerCase();
    if (
      isIndiaSource ||
      /\b(india|indian|delhi|mumbai|bihar|patna|bengaluru|chennai|kolkata|hyderabad|modi|bjp|congress|isro|rupee|sensex|nifty)\b/i.test(
        lower
      ) ||
      /(भारत|बिहार|पटना|दिल्ली|मुंबई|मोदी|सरकार|रुपया|क्रिकेट)/.test(text)
    ) {
      return { code: 'IN', label: '🇮🇳 India' };
    }
    if (
      /\b(china|chinese|beijing|shanghai|xi jinping|taiwan|hong kong)\b/i.test(
        lower
      ) ||
      /(चीन|बीजिंग)/.test(text)
    ) {
      return { code: 'CN', label: '🇨🇳 China' };
    }
    if (
      /\b(russia|russian|moscow|putin|kremlin|ukraine)\b/i.test(lower) ||
      /(रूस|मॉस्को|पुतिन)/.test(text)
    ) {
      return { code: 'RU', label: '🇷🇺 Russia' };
    }
    if (
      /\b(japan|japanese|tokyo|osaka|yen)\b/i.test(lower) ||
      /(जापान|टोक्यो)/.test(text)
    ) {
      return { code: 'JP', label: '🇯🇵 Japan' };
    }
    if (
      /\b(u\.s\.|united states|america|american|washington|white house|trump|biden|pentagon|congress|california|new york|texas|florida)\b/i.test(
        lower
      ) ||
      /(अमेरिका|वाशिंगटन|ट्रंप)/.test(text)
    ) {
      return { code: 'US', label: '🇺🇸 USA' };
    }
    if (
      /\b(u\.k\.|uk|britain|british|england|london|scotland|starmer|downing street)\b/i.test(
        lower
      ) ||
      /(ब्रिटेन|लंदन|इंग्लैंड)/.test(text)
    ) {
      return { code: 'GB', label: '🇬🇧 UK' };
    }

    const labelMap: Record<
      'IN' | 'US' | 'GB' | 'CN' | 'RU' | 'JP' | 'GLOBAL',
      string
    > = {
      IN: '🇮🇳 India',
      US: '🇺🇸 USA',
      GB: '🇬🇧 UK',
      CN: '🇨🇳 China',
      RU: '🇷🇺 Russia',
      JP: '🇯🇵 Japan',
      GLOBAL: '🌍 World',
    };
    return { code: defaultCountry, label: labelMap[defaultCountry] };
  };

  const detectArticleCategories = (
    text: string,
    defaultCategory: string,
    isIndia: boolean
  ): { primary: string; categories: string[]; isBihar: boolean } => {
    const lower = text.toLowerCase();
    const cats = new Set<string>([defaultCategory]);

    const isBihar =
      defaultCategory === 'Bihar News' ||
      /\b(bihar|patna|bodhgaya|bhagalpur|muzaffarpur|darbhanga|vaishali|supaul|nitish|tejashwi|bhojpuri|chhath)\b/i.test(
        lower
      ) ||
      /(बिहार|पटना|बोधगया|गया जिला|गया ज़िला|भागलपुर|मुजफ्फरपुर|दरभंगा|वैशाली|सुपौल|नीतीश|तेजस्वी|छठ)/.test(
        text
      );
    if (isBihar) {
      cats.add('Bihar News');
      cats.add('India News');
    }

    if (isIndia) {
      cats.add('India News');
    } else {
      cats.add('World News');
    }

    if (
      /\b(breaking|urgent|alert|attack|explosion|earthquake|crisis|live)\b/i.test(
        lower
      ) ||
      /(बड़ी खबर|ब्रेकिंग|हमला|भूकंप|आपातकाल)/.test(text)
    ) {
      cats.add('Breaking News');
    }

    if (
      /\b(election|parliament|minister|president|senate|house|government|policy|party|vote|court|supreme court|impeach)\b/i.test(
        lower
      ) ||
      /(चुनाव|संसद|प्रधानमंत्री|मुख्यमंत्री|सरकार|सुप्रीम कोर्ट|राजनीति|विपक्ष|नेता)/.test(
        text
      )
    ) {
      cats.add('Politics');
    }

    if (
      /\b(ai|artificial intelligence|tech|software|apple|google|microsoft|meta|cyber|smartphone|chip|robot|digital|internet|app)\b/i.test(
        lower
      ) ||
      /(टेक्नोलॉजी|एआई|स्मार्टफोन|इंटरनेट|साइबर|डिजिटल)/.test(text)
    ) {
      cats.add('Technology');
    }

    if (
      /\b(science|space|nasa|isro|climate|planet|satellite|research|medicine|health|scientist|astronomy)\b/i.test(
        lower
      ) ||
      /(विज्ञान|अंतरिक्ष|इसरो|नासा|सैटेलाइट|शोध|पर्यावरण)/.test(text)
    ) {
      cats.add('Science');
    }

    if (
      defaultCategory === 'Traders' ||
      /\b(market|economy|bank|stock|sensex|nifty|nse|bse|gold|silver|bullion|mcx|ipo|dividend|earnings|quarterly|sebi|mutual fund|sip|oil|trade|company|gdp|inflation|business|invest|billion|tax|salary|wall street|nasdaq)\b/i.test(
        lower
      ) ||
      /(अर्थव्यवस्था|शेयर बाजार|निफ्टी|सेंसेक्स|सोना|चांदी|सोने का भाव|चांदी का भाव|कंपनी|तिमाही नतीजे|म्यूचुअल फंड|एसआईपी|सेबी|बैंक|महंगाई|व्यापार|सैलरी|पेंशन|निवेश)/.test(
        text
      )
    ) {
      cats.add('Business');
      cats.add('Traders');
    }

    if (
      !/चोरी|गिरफ्तार|लूट|तस्करी|हत्या|पुलिस|theft|robbery|arrest/i.test(text) &&
      (/\b(gold price|silver price|gold rate|silver rate|bullion|mcx|24k|22k|gold futures|silver futures|sovereign gold)\b/i.test(
        lower
      ) ||
        /(सोने का भाव|चांदी का भाव|सर्राफा|सोना सस्ता|सोना महंगा|चांदी सस्ती|चांदी महंगी|सोना-चांदी|सोने की कीमत|चांदी की कीमत|एमसीएक्स)/.test(
          text
        ))
    ) {
      cats.add('Gold & Silver');
      cats.add('Traders');
    }

    if (
      /\b(nifty|sensex|nse|bse|dalal street|indian stock|share market)\b/i.test(
        lower
      ) ||
      /(निफ्टी|सेंसेक्स|शेयर बाजार|बीएसई|एनएसई)/.test(text)
    ) {
      cats.add('Indian Stock Market');
      cats.add('Traders');
    }

    if (
      /\b(company|quarterly|q1|q2|q3|q4|earnings|profit|revenue|ipo|dividend|tata|reliance|infosys|hdfc|tcs|adani)\b/i.test(
        lower
      ) ||
      /(कंपनी|तिमाही नतीजे|मुनाफा|आईपीओ|डिविडेंड|रिलायंस|टाटा|इंफोसिस)/.test(text)
    ) {
      cats.add('Company Updates');
      cats.add('Traders');
    }

    if (
      /\b(sebi|mutual fund|sip|investor|portfolio|trading education|diversification|demat)\b/i.test(
        lower
      ) ||
      /(सेबी|म्यूचुअल फंड|एसआईपी|निवेश|पोर्टफोलियो|डीमैट|ट्रेडिंग)/.test(text)
    ) {
      cats.add('Trading Education');
      cats.add('Traders');
    }

    if (
      /\b(wall street|nasdaq|s&p 500|dow jones|nikkei|ftse|global market|fed|federal reserve)\b/i.test(
        lower
      ) ||
      /(वॉल स्ट्रीट|ग्लोबल मार्केट|अंतर्राष्ट्रीय बाजार)/.test(text)
    ) {
      cats.add('International Market');
      cats.add('Traders');
    }

    if (
      /\b(cricket|football|sport|match|test|ipl|olympic|fifa|player|goal|tournament|win|league|bcci)\b/i.test(
        lower
      ) ||
      /(क्रिकेट|फुटबॉल|खेल|मैच|टीम इंडिया|खिलाड़ी|टूर्नामेंट)/.test(text)
    ) {
      cats.add('Sports');
    }

    if (
      /\b(film|movie|actor|bollywood|hollywood|music|singer|celebrity|cinema|award|show|series)\b/i.test(
        lower
      ) ||
      /(बॉलीवुड|फिल्म|सिनेमा|अभिनेता|गायक|मनोरंजन)/.test(text)
    ) {
      cats.add('Entertainment');
    }

    const primary = isBihar ? 'Bihar News' : defaultCategory;
    return { primary, categories: Array.from(cats), isBihar };
  };

  const buildHindiContextualSummary = (params: {
    headline: string;
    summary: string;
    sourceName: string;
    countryLabel: string;
    primaryCategory: string;
    language: 'hi' | 'en';
  }): string => {
    const hasDevanagari = /[\u0900-\u097F]/.test(
      `${params.headline} ${params.summary}`
    );
    if (hasDevanagari) {
      if (
        params.summary &&
        params.summary.length > 15 &&
        params.summary !== params.headline
      ) {
        return params.summary;
      }
      return `${params.sourceName} की रिपोर्ट के अनुसार: ${params.headline}। विस्तृत जानकारी के लिए मूल लेख पढ़ें।`;
    }

    const categoryHindiMap: Record<string, string> = {
      'Breaking News': 'बड़ी ख़बर',
      'India News': 'भारत समाचार',
      'World News': 'विश्व समाचार',
      Politics: 'राजनीति',
      Technology: 'टेक्नोलॉजी',
      Science: 'विज्ञान एवं अंतरिक्ष',
      Business: 'व्यापार एवं अर्थव्यवस्था',
      Sports: 'खेल जगत',
      Entertainment: 'मनोरंजन',
      'Bihar News': 'बिहार समाचार',
    };
    const catHi = categoryHindiMap[params.primaryCategory] || 'ताज़ा समाचार';
    const shortSnippet = params.summary
      ? params.summary.slice(0, 180) + (params.summary.length > 180 ? '...' : '')
      : params.headline;

    return `🇮🇳 हिंदी सारांश (${catHi} • ${params.sourceName}): ${shortSnippet}`;
  };

  const istYmdFormatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Kolkata',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  });

  const istReadableDateFormatter = new Intl.DateTimeFormat('en-IN', {
    timeZone: 'Asia/Kolkata',
    weekday: 'short',
    day: 'numeric',
    month: 'short',
    year: 'numeric',
  });

  const istHindiDateFormatter = new Intl.DateTimeFormat('hi-IN', {
    timeZone: 'Asia/Kolkata',
    weekday: 'long',
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  });

  const getIstDateKey = (date: Date): string => {
    return istYmdFormatter.format(date);
  };

  const getCurrentIstCalendarMetadata = () => {
    const now = new Date();
    const todayKey = getIstDateKey(now);
    const [y, m, d] = todayKey.split('-').map(Number);
    const prevUtcNoon = new Date(Date.UTC(y, m - 1, d, 12, 0, 0) - 86400000);
    const yesterdayKey = prevUtcNoon.toISOString().slice(0, 10);
    const todayFormattedIst = istReadableDateFormatter.format(now);
    const todayFormattedHindi = istHindiDateFormatter.format(now);
    const fetchedAtIstText =
      now.toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata',
        day: 'numeric',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true,
      }) + ' IST';

    return {
      todayKey,
      yesterdayKey,
      todayFormattedIst,
      todayFormattedHindi,
      fetchedAtIstText,
    };
  };

  const parseRssPubDateToIst = (
    pubDateRaw: string,
    todayKey: string,
    yesterdayKey: string
  ): {
    iso: string;
    text: string;
    publishedDateIst: string;
    isTodayIst: boolean;
    isYesterdayIst: boolean;
    dayBucket: 'today' | 'previous';
    relativeTimeText: string;
  } | null => {
    if (!pubDateRaw || !pubDateRaw.trim()) {
      return null;
    }
    const parsed = new Date(pubDateRaw.trim());
    if (Number.isNaN(parsed.getTime())) {
      return null;
    }

    const publishedDateIst = getIstDateKey(parsed);
    const isTodayIst = publishedDateIst === todayKey;
    const isYesterdayIst = publishedDateIst === yesterdayKey;
    const dayBucket: 'today' | 'previous' = isTodayIst ? 'today' : 'previous';

    const formattedIst =
      parsed.toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata',
        day: 'numeric',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true,
      }) + ' IST';

    const diffMinutes = Math.max(
      0,
      Math.round((Date.now() - parsed.getTime()) / 60000)
    );
    let relativeTimeText = '';
    if (isTodayIst) {
      if (diffMinutes < 2) {
        relativeTimeText = 'Just now • Today (आज)';
      } else if (diffMinutes < 60) {
        relativeTimeText = `${diffMinutes}m ago • Today (आज)`;
      } else {
        const hrs = Math.floor(diffMinutes / 60);
        const mins = diffMinutes % 60;
        relativeTimeText =
          mins > 0
            ? `${hrs}h ${mins}m ago • Today (आज)`
            : `${hrs}h ago • Today (आज)`;
      }
    } else if (isYesterdayIst) {
      relativeTimeText = `Yesterday • कल (${publishedDateIst})`;
    } else {
      const shortDay = parsed.toLocaleDateString('en-IN', {
        timeZone: 'Asia/Kolkata',
        day: 'numeric',
        month: 'short',
        year: 'numeric',
      });
      relativeTimeText = `Previous Day • ${shortDay}`;
    }

    return {
      iso: parsed.toISOString(),
      text: formattedIst,
      publishedDateIst,
      isTodayIst,
      isYesterdayIst,
      dayBucket,
      relativeTimeText,
    };
  };

  const fetchSingleRssSource = async (
    source: PublicNewsRssSource,
    todayKey: string,
    yesterdayKey: string
  ): Promise<MoonNewsArticleItem[]> => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    try {
      const resp = await fetch(source.url, {
        signal: controller.signal,
        headers: {
          Accept:
            'application/rss+xml, application/xml, text/xml, */*;q=0.8',
          'User-Agent': 'MOON-Messenger-NewsReader/1.0',
          'Cache-Control': 'no-cache',
        },
      });
      clearTimeout(timeout);
      if (!resp.ok) return [];

      const xml = await resp.text();
      const itemBlocks = xml.match(/<item(?:\s[^>]*)?>[\s\S]*?<\/item>/gi) || [];
      const items: MoonNewsArticleItem[] = [];

      for (const block of itemBlocks.slice(0, 24)) {
        let rawTitle = extractTagContent(block, 'title');
        const rawLink = extractTagContent(block, 'link');
        const rawGuid = extractTagContent(block, 'guid');
        // Require a real item-level publication date from the RSS item; never fabricate or substitute channel build time
        const rawPubDate =
          extractTagContent(block, 'pubDate') ||
          extractTagContent(block, 'dc:date') ||
          extractTagContent(block, 'published') ||
          extractTagContent(block, 'updated');
        const rawDescription = extractTagContent(block, 'description');
        const rawSourceTag = extractTagContent(block, 'source');
        const sourceUrlMatch = block.match(/<source[^>]+url=["']([^"']+)["']/i);

        const articleUrl = (rawLink || rawGuid).trim();
        if (!rawTitle || !articleUrl || !articleUrl.startsWith('http')) {
          continue;
        }

        const pubInfo = parseRssPubDateToIst(rawPubDate, todayKey, yesterdayKey);
        if (!pubInfo) {
          // Skip undated RSS items so yesterday/undated links never masquerade as today's news
          continue;
        }

        // Clean Google News trailing " - SourceName" from title if <source> exists
        let effectiveSourceName = source.name;
        let effectiveSourceWebsite = source.publisherWebsite;
        if (rawSourceTag) {
          effectiveSourceName = stripHtmlTags(rawSourceTag);
          if (sourceUrlMatch && sourceUrlMatch[1]) {
            effectiveSourceWebsite = decodeRssXmlEntities(sourceUrlMatch[1]);
          }
          const suffix = ` - ${effectiveSourceName}`;
          if (rawTitle.endsWith(suffix)) {
            rawTitle = rawTitle.slice(0, -suffix.length).trim();
          }
        }

        const headline = stripHtmlTags(rawTitle);
        let summary = stripHtmlTags(rawDescription);
        if (rawSourceTag && summary.endsWith(effectiveSourceName)) {
          summary = summary
            .slice(0, -effectiveSourceName.length)
            .replace(/[-–—•\s]+$/, '')
            .trim();
        }
        if (!summary || summary === headline) {
          summary = headline;
        }

        const imageUrl = extractRssImageUrl(block);
        const combinedText = `${headline} ${summary}`;
        const countryInfo = detectArticleCountry(
          combinedText,
          source.defaultCountry,
          source.isIndia
        );
        const isIndia = source.isIndia || countryInfo.code === 'IN';
        const categoryInfo = detectArticleCategories(
          combinedText,
          source.defaultCategory,
          isIndia
        );

        const hindiSummary = buildHindiContextualSummary({
          headline,
          summary,
          sourceName: effectiveSourceName,
          countryLabel: countryInfo.label,
          primaryCategory: categoryInfo.primary,
          language: source.language,
        });

        const uniqueKey = crypto
          .createHash('sha1')
          .update(`${source.id}:${articleUrl}:${headline}`)
          .digest('hex')
          .slice(0, 16);

        items.push({
          id: `news-${source.id}-${uniqueKey}`,
          sourceId: source.id,
          sourceName: effectiveSourceName,
          sourceHandle: source.handle,
          sourceLogoBadge: source.logoBadge,
          sourceWebsite: effectiveSourceWebsite,
          headline,
          summary,
          hindiSummary,
          articleUrl,
          imageUrl,
          publishedAtIso: pubInfo.iso,
          publishedAtText: pubInfo.text,
          publishedDateIst: pubInfo.publishedDateIst,
          isTodayIst: pubInfo.isTodayIst,
          isYesterdayIst: pubInfo.isYesterdayIst,
          dayBucket: pubInfo.dayBucket,
          relativeTimeText: pubInfo.relativeTimeText,
          countryCode: countryInfo.code,
          countryLabel: countryInfo.label,
          language: /[\u0900-\u097F]/.test(headline) ? 'hi' : source.language,
          primaryCategory: categoryInfo.primary,
          categories: categoryInfo.categories,
          isIndia,
          isBihar: categoryInfo.isBihar,
        });
      }

      return items;
    } catch {
      clearTimeout(timeout);
      return [];
    }
  };

  let cachedNewsPool: MoonNewsArticleItem[] = [];
  let cachedNewsTimestamp = 0;
  let cachedIstDateKey = '';
  const NEWS_CACHE_TTL_MS = 2 * 60 * 1000; // 2 minutes fresh cache

  const getAggregatedNewsPool = async (
    forceRefresh = false
  ): Promise<MoonNewsArticleItem[]> => {
    const now = Date.now();
    const { todayKey, yesterdayKey } = getCurrentIstCalendarMetadata();

    // Recompute isTodayIst / isYesterdayIst / relativeTimeText if serving from cache on the same IST day
    if (
      !forceRefresh &&
      cachedNewsPool.length > 0 &&
      cachedIstDateKey === todayKey &&
      now - cachedNewsTimestamp < NEWS_CACHE_TTL_MS
    ) {
      return cachedNewsPool;
    }

    const results = await Promise.all(
      PUBLIC_NEWS_RSS_SOURCES.map((src) =>
        fetchSingleRssSource(src, todayKey, yesterdayKey)
      )
    );
    const flat = results.flat();

    // Deduplicate by normalized headline or articleUrl
    const seenUrls = new Set<string>();
    const seenHeadlines = new Set<string>();
    const seenIds = new Set<string>();
    const deduped: MoonNewsArticleItem[] = [];

    for (const item of flat) {
      const normUrl = item.articleUrl.toLowerCase().replace(/\/+$/, '');
      const normTitle = item.headline.toLowerCase().slice(0, 65);
      if (
        seenIds.has(item.id) ||
        seenUrls.has(normUrl) ||
        seenHeadlines.has(normTitle)
      ) {
        continue;
      }
      seenIds.add(item.id);
      seenUrls.add(normUrl);
      seenHeadlines.add(normTitle);
      deduped.push(item);
    }

    // Strictly prioritize Today (Asia/Kolkata) articles over Previous Days, then sort newest first
    deduped.sort((a, b) => {
      if (a.isTodayIst !== b.isTodayIst) {
        return a.isTodayIst ? -1 : 1;
      }
      return (
        new Date(b.publishedAtIso).getTime() -
        new Date(a.publishedAtIso).getTime()
      );
    });

    if (deduped.length > 0) {
      cachedNewsPool = deduped;
      cachedNewsTimestamp = now;
      cachedIstDateKey = todayKey;
    }
    return deduped;
  };

  // In-process server-side scheduled RSS refresh every 10 minutes so daily feeds stay warm
  const SERVER_AUTO_REFRESH_INTERVAL_MS = 10 * 60 * 1000;
  setInterval(() => {
    void getAggregatedNewsPool(true).catch(() => {
      // Ignore transient network errors during background refresh
    });
  }, SERVER_AUTO_REFRESH_INTERVAL_MS);

  /**
   * Interleaves Indian news (60% = 3 per 5 items) and International news (40% = 2 per 5 items)
   * within a single date bucket while preserving chronological freshness.
   */
  const interleaveBucket6040 = (
    bucketItems: MoonNewsArticleItem[]
  ): MoonNewsArticleItem[] => {
    const indiaPool = bucketItems
      .filter((i) => i.isIndia)
      .sort(
        (a, b) =>
          new Date(b.publishedAtIso).getTime() -
          new Date(a.publishedAtIso).getTime()
      );

    const worldPool = bucketItems
      .filter((i) => !i.isIndia)
      .sort(
        (a, b) =>
          new Date(b.publishedAtIso).getTime() -
          new Date(a.publishedAtIso).getTime()
      );

    const maxWorldFor6040 =
      indiaPool.length > 0
        ? Math.max(1, Math.round((indiaPool.length * 2) / 3))
        : worldPool.length;
    const cappedWorldPool = worldPool.slice(0, maxWorldFor6040);

    const interleaved: MoonNewsArticleItem[] = [];
    let iIdx = 0;
    let wIdx = 0;

    // 60% India (3 items) : 40% International (2 items) pattern: IN, IN, WORLD, IN, WORLD
    while (iIdx < indiaPool.length || wIdx < cappedWorldPool.length) {
      for (let k = 0; k < 2 && iIdx < indiaPool.length; k++) {
        interleaved.push(indiaPool[iIdx++]);
      }
      if (wIdx < cappedWorldPool.length) {
        interleaved.push(cappedWorldPool[wIdx++]);
      }
      if (iIdx < indiaPool.length) {
        interleaved.push(indiaPool[iIdx++]);
      }
      if (wIdx < cappedWorldPool.length) {
        interleaved.push(cappedWorldPool[wIdx++]);
      }
    }

    return interleaved;
  };

  /**
   * Prioritizes Today (Asia/Kolkata) 60/40 interleaved items strictly before Previous Days 60/40 items.
   */
  const interleaveIndiaFirst6040 = (
    items: MoonNewsArticleItem[]
  ): MoonNewsArticleItem[] => {
    const todayBucket = items.filter((i) => i.isTodayIst);
    const previousBucket = items.filter((i) => !i.isTodayIst);
    return [
      ...interleaveBucket6040(todayBucket),
      ...interleaveBucket6040(previousBucket),
    ];
  };

  app.get('/api/news/feed', async (req: Request, res: Response) => {
    try {
      const filter = String(req.query.filter || 'for_you')
        .trim()
        .toLowerCase();
      const country = String(req.query.country || 'ALL')
        .trim()
        .toUpperCase();
      const dateFilterRaw = String(req.query.dateFilter || 'today')
        .trim()
        .toLowerCase();
      const dateFilter: 'today' | 'previous' | 'all' =
        dateFilterRaw === 'previous'
          ? 'previous'
          : dateFilterRaw === 'all'
            ? 'all'
            : 'today';
      const searchQ = String(req.query.q || '').trim();
      const offset = Math.max(0, Number(req.query.offset) || 0);
      const limit = Math.min(40, Math.max(1, Number(req.query.limit) || 12));
      const forceRefresh = req.query.refresh === '1';

      const istMeta = getCurrentIstCalendarMetadata();
      let pool = await getAggregatedNewsPool(forceRefresh);

      // If user searches a specific keyword, also fetch live Google News RSS for that keyword
      if (searchQ.length >= 2) {
        const dynamicSearchSource: PublicNewsRssSource = {
          id: 'live-search-rss',
          name: 'Google News RSS',
          handle: '@googlenews',
          logoBadge: 'NEWS',
          url: `https://news.google.com/rss/search?q=${encodeURIComponent(
            searchQ
          )}&hl=hi&gl=IN&ceid=IN:hi`,
          publisherWebsite: 'https://news.google.com',
          defaultCountry: 'IN',
          language: 'hi',
          defaultCategory: 'Breaking News',
          isIndia: true,
        };
        const liveSearchItems = await fetchSingleRssSource(
          dynamicSearchSource,
          istMeta.todayKey,
          istMeta.yesterdayKey
        );
        const existingUrls = new Set(pool.map((p) => p.articleUrl));
        pool = [
          ...liveSearchItems.filter((item) => !existingUrls.has(item.articleUrl)),
          ...pool,
        ];
      }

      // Filter by country if requested (IN, US, GB, CN, RU, JP, GLOBAL)
      let filtered = pool;
      if (country !== 'ALL') {
        filtered = filtered.filter((item) => item.countryCode === country);
      }

      const tradersTopic = String(req.query.tradersTopic || 'all')
        .trim()
        .toLowerCase();

      // Filter by feed tab / category
      if (filter === 'india') {
        filtered = filtered.filter((item) => item.isIndia);
      } else if (filter === 'world') {
        filtered = filtered.filter((item) => !item.isIndia);
      } else if (filter === 'bihar') {
        filtered = filtered.filter((item) => item.isBihar);
      } else if (filter === 'traders') {
        filtered = filtered.filter(
          (item) =>
            item.primaryCategory === 'Traders' ||
            item.categories.includes('Traders') ||
            item.categories.includes('Business')
        );
        if (tradersTopic === 'nifty_sensex') {
          filtered = filtered
            .filter(
              (item) =>
                item.categories.includes('Indian Stock Market') ||
                item.sourceId === 'traders-india-stocks-hi' ||
                item.sourceId === 'traders-et-markets'
            )
            .sort((a, b) => {
              if (a.isTodayIst !== b.isTodayIst) return a.isTodayIst ? -1 : 1;
              const aDedicated =
                a.sourceId === 'traders-india-stocks-hi' ||
                a.sourceId === 'traders-et-markets'
                  ? 1
                  : 0;
              const bDedicated =
                b.sourceId === 'traders-india-stocks-hi' ||
                b.sourceId === 'traders-et-markets'
                  ? 1
                  : 0;
              if (bDedicated !== aDedicated) return bDedicated - aDedicated;
              return (
                new Date(b.publishedAtIso).getTime() -
                new Date(a.publishedAtIso).getTime()
              );
            });
        } else if (tradersTopic === 'gold_silver') {
          filtered = filtered
            .filter(
              (item) =>
                !/चोरी|गिरफ्तार|लूट|तस्करी|पुलिस/i.test(item.headline) &&
                (item.sourceId === 'traders-gold-silver-hi' ||
                  item.categories.includes('Gold & Silver'))
            )
            .sort((a, b) => {
              if (a.isTodayIst !== b.isTodayIst) return a.isTodayIst ? -1 : 1;
              const aDedicated =
                a.sourceId === 'traders-gold-silver-hi' ? 1 : 0;
              const bDedicated =
                b.sourceId === 'traders-gold-silver-hi' ? 1 : 0;
              if (bDedicated !== aDedicated) return bDedicated - aDedicated;
              return (
                new Date(b.publishedAtIso).getTime() -
                new Date(a.publishedAtIso).getTime()
              );
            });
        } else if (tradersTopic === 'company_updates') {
          filtered = filtered
            .filter(
              (item) =>
                item.sourceId === 'traders-company-updates-hi' ||
                item.categories.includes('Company Updates')
            )
            .sort((a, b) => {
              if (a.isTodayIst !== b.isTodayIst) return a.isTodayIst ? -1 : 1;
              const aDedicated =
                a.sourceId === 'traders-company-updates-hi' ? 1 : 0;
              const bDedicated =
                b.sourceId === 'traders-company-updates-hi' ? 1 : 0;
              if (bDedicated !== aDedicated) return bDedicated - aDedicated;
              return (
                new Date(b.publishedAtIso).getTime() -
                new Date(a.publishedAtIso).getTime()
              );
            });
        } else if (tradersTopic === 'trading_education') {
          filtered = filtered
            .filter(
              (item) =>
                item.sourceId === 'traders-education-hi' ||
                item.categories.includes('Trading Education')
            )
            .sort((a, b) => {
              if (a.isTodayIst !== b.isTodayIst) return a.isTodayIst ? -1 : 1;
              const aDedicated = a.sourceId === 'traders-education-hi' ? 1 : 0;
              const bDedicated = b.sourceId === 'traders-education-hi' ? 1 : 0;
              if (bDedicated !== aDedicated) return bDedicated - aDedicated;
              return (
                new Date(b.publishedAtIso).getTime() -
                new Date(a.publishedAtIso).getTime()
              );
            });
        } else if (tradersTopic === 'international') {
          filtered = filtered
            .filter(
              (item) =>
                item.sourceId === 'traders-global-markets' ||
                item.categories.includes('International Market') ||
                !item.isIndia
            )
            .sort((a, b) => {
              if (a.isTodayIst !== b.isTodayIst) return a.isTodayIst ? -1 : 1;
              const aDedicated =
                a.sourceId === 'traders-global-markets' ? 1 : 0;
              const bDedicated =
                b.sourceId === 'traders-global-markets' ? 1 : 0;
              if (bDedicated !== aDedicated) return bDedicated - aDedicated;
              return (
                new Date(b.publishedAtIso).getTime() -
                new Date(a.publishedAtIso).getTime()
              );
            });
        } else if (tradersTopic === 'business') {
          filtered = filtered.filter((item) =>
            item.categories.includes('Business')
          );
        } else {
          filtered = filtered.sort((a, b) => {
            if (a.isTodayIst !== b.isTodayIst) return a.isTodayIst ? -1 : 1;
            const aPri = a.primaryCategory === 'Traders' ? 1 : 0;
            const bPri = b.primaryCategory === 'Traders' ? 1 : 0;
            if (bPri !== aPri) return bPri - aPri;
            return (
              new Date(b.publishedAtIso).getTime() -
              new Date(a.publishedAtIso).getTime()
            );
          });
        }
      } else if (filter === 'technology') {
        filtered = filtered.filter((item) =>
          item.categories.includes('Technology')
        );
      } else if (filter === 'sports') {
        filtered = filtered.filter((item) =>
          item.categories.includes('Sports')
        );
      } else if (filter === 'breaking') {
        filtered = filtered.filter((item) =>
          item.categories.includes('Breaking News')
        );
      } else if (filter === 'politics') {
        filtered = filtered.filter((item) =>
          item.categories.includes('Politics')
        );
      } else if (filter === 'science') {
        filtered = filtered.filter((item) =>
          item.categories.includes('Science')
        );
      } else if (filter === 'business') {
        filtered = filtered.filter(
          (item) =>
            item.categories.includes('Business') ||
            item.categories.includes('Traders')
        );
      } else if (filter === 'entertainment') {
        filtered = filtered.filter((item) =>
          item.categories.includes('Entertainment')
        );
      }

      // Apply keyword search filter if provided
      if (searchQ) {
        const qLower = searchQ.toLowerCase();
        const searchMatched = filtered.filter(
          (item) =>
            item.headline.toLowerCase().includes(qLower) ||
            item.summary.toLowerCase().includes(qLower) ||
            item.hindiSummary.toLowerCase().includes(qLower) ||
            item.sourceName.toLowerCase().includes(qLower) ||
            item.countryLabel.toLowerCase().includes(qLower) ||
            item.categories.some((c) => c.toLowerCase().includes(qLower))
        );
        if (searchMatched.length > 0) {
          filtered = searchMatched;
        }
      }

      // Calculate Today vs Previous Days counts for the active category/country before dateFilter slicing
      const todayMatchingItems = filtered.filter((item) => item.isTodayIst);
      const previousMatchingItems = filtered.filter((item) => !item.isTodayIst);
      const todayCount =
        filter === 'for_you' && country === 'ALL'
          ? interleaveBucket6040(todayMatchingItems).length
          : todayMatchingItems.length;
      const previousDaysCount =
        filter === 'for_you' && country === 'ALL'
          ? interleaveBucket6040(previousMatchingItems).length
          : previousMatchingItems.length;

      // Apply Today vs Previous Days filter (strictly prevents yesterday's news from appearing in Today)
      let dateFiltered = filtered;
      if (dateFilter === 'today') {
        dateFiltered = todayMatchingItems;
      } else if (dateFilter === 'previous') {
        dateFiltered = previousMatchingItems;
      }

      // Apply 60% India / 40% International interleaving for 'for_you'
      const ordered =
        filter === 'for_you' && country === 'ALL'
          ? interleaveIndiaFirst6040(dateFiltered)
          : filter === 'traders'
            ? dateFiltered
            : dateFiltered.sort((a, b) => {
                if (a.isTodayIst !== b.isTodayIst) {
                  return a.isTodayIst ? -1 : 1;
                }
                return (
                  new Date(b.publishedAtIso).getTime() -
                  new Date(a.publishedAtIso).getTime()
                );
              });

      const slice = ordered.slice(offset, offset + limit);
      const indiaCountInOrdered = ordered.filter((i) => i.isIndia).length;
      const indiaRatioPercent =
        ordered.length > 0
          ? Math.round((indiaCountInOrdered / ordered.length) * 100)
          : filter === 'world'
            ? 0
            : filter === 'india' || filter === 'bihar'
              ? 100
              : 60;

      return res.json({
        items: slice,
        totalCount: ordered.length,
        todayCount,
        previousDaysCount,
        dateFilter,
        todayIstDateKey: istMeta.todayKey,
        todayFormattedIst: istMeta.todayFormattedIst,
        todayFormattedHindi: istMeta.todayFormattedHindi,
        fetchedAtIstText: istMeta.fetchedAtIstText,
        offset,
        limit,
        hasMore: offset + slice.length < ordered.length,
        indiaRatioPercent,
        sourcesActive: PUBLIC_NEWS_RSS_SOURCES.length,
        fetchedAtIso: new Date().toISOString(),
      });
    } catch (err) {
      return res.status(500).json({
        error:
          err instanceof Error
            ? err.message
            : 'Failed to load real RSS news feed.',
      });
    }
  });

  // Translation cache for on-demand English -> Simple Hindi news summaries
  const hindiTranslationCache = new Map<string, string>();

  app.post('/api/news/translate-hindi', async (req: Request, res: Response) => {
    try {
      const text = String(req.body?.text || '')
        .trim()
        .slice(0, 480);
      if (!text) {
        return res.status(400).json({ error: 'Missing text to translate.' });
      }
      if (/[\u0900-\u097F]/.test(text) && !text.startsWith('🇮🇳 हिंदी सारांश')) {
        return res.json({ hindiText: text });
      }
      if (hindiTranslationCache.has(text)) {
        return res.json({ hindiText: hindiTranslationCache.get(text) });
      }

      const apiUrl = `https://api.mymemory.translated.net/get?q=${encodeURIComponent(
        text
      )}&langpair=en|hi`;
      const resp = await fetch(apiUrl);
      if (resp.ok) {
        const data = (await resp.json()) as {
          responseData?: { translatedText?: string };
        };
        const translated = data?.responseData?.translatedText?.trim();
        if (translated && !translated.includes('MYMEMORY WARNING')) {
          hindiTranslationCache.set(text, translated);
          return res.json({ hindiText: translated });
        }
      }

      return res.json({
        hindiText: `हिंदी अनुवाद: ${text}`,
      });
    } catch {
      return res.status(500).json({
        error: 'Unable to translate summary right now.',
      });
    }
  });

  // ============================================================================
  // MOON TRADING & MARKET EDUCATION FEED — REAL DAILY RSS AGGREGATOR (IST)
  // ============================================================================

  type TradingCategoryType =
    | 'India Market'
    | 'World Market'
    | 'Business News'
    | 'Gold & Silver'
    | 'Company Updates'
    | 'Crypto Education'
    | 'Trading Basics'
    | 'Market Updates';

  interface TradingRssSource {
    id: string;
    name: string;
    handle: string;
    logoBadge: string;
    url: string;
    publisherWebsite: string;
    language: 'hi' | 'en';
    defaultCategory: TradingCategoryType;
    marketRegion: 'IN' | 'GLOBAL';
    marketTag: string;
  }

  interface MoonTradingArticleItem {
    id: string;
    sourceId: string;
    sourceName: string;
    sourceHandle: string;
    sourceLogoBadge: string;
    sourceWebsite: string;
    headline: string;
    summary: string;
    hindiHeadline: string;
    hindiSummary: string;
    englishSummary: string;
    articleUrl: string;
    imageUrl?: string;
    publishedAtIso: string;
    publishedAtText: string;
    publishedDateIst: string;
    isTodayIst: boolean;
    isYesterdayIst: boolean;
    dayBucket: 'today' | 'previous';
    relativeTimeText: string;
    language: 'hi' | 'en';
    primaryCategory: TradingCategoryType;
    categories: TradingCategoryType[];
    marketRegion: 'IN' | 'GLOBAL';
    marketRegionLabel: string;
    marketTags: string[];
    educationalTakeawayHindi: string;
    educationalTakeawayEnglish: string;
  }

  const TRADING_RSS_SOURCES: TradingRssSource[] = [
    // 1. INDIA MARKET (NSE, BSE, Nifty 50, Sensex — Hindi & English)
    {
      id: 'india-market-hindi-daily',
      name: 'भारतीय शेयर बाज़ार (NSE • BSE • सेंसेक्स • निफ्टी)',
      handle: '@indiamarket.hi',
      logoBadge: 'NSE/BSE',
      url: 'https://news.google.com/rss/search?q=(NSE+OR+BSE+OR+%22Nifty+50%22+OR+Sensex+OR+%22%E0%A4%B6%E0%A5%87%E0%A4%AF%E0%A4%B0+%E0%A4%AC%E0%A4%BE%E0%A4%9C%E0%A4%BE%E0%A4%B0%22+OR+%E0%A4%A8%E0%A4%BF%E0%A4%AB%E0%A5%8D%E0%A4%9F%E0%A5%80+OR+%E0%A4%B8%E0%A5%87%E0%A4%82%E0%A4%B8%E0%A5%87%E0%A4%95%E0%A5%8D%E0%A4%B8)+when:2d&hl=hi&gl=IN&ceid=IN:hi',
      publisherWebsite: 'https://www.nseindia.com',
      language: 'hi',
      defaultCategory: 'India Market',
      marketRegion: 'IN',
      marketTag: 'NSE • BSE • Nifty 50 • Sensex',
    },
    {
      id: 'et-markets-rss',
      name: 'Economic Times Markets',
      handle: '@etmarkets',
      logoBadge: 'ET MKT',
      url: 'https://economictimes.indiatimes.com/markets/rssfeeds/1977021501.cms',
      publisherWebsite: 'https://economictimes.indiatimes.com/markets',
      language: 'en',
      defaultCategory: 'India Market',
      marketRegion: 'IN',
      marketTag: 'Indian Equities • NSE/BSE',
    },
    {
      id: 'et-stocks-rss',
      name: 'Economic Times Stocks (Nifty & Sensex)',
      handle: '@etstocks',
      logoBadge: 'STOCKS',
      url: 'https://economictimes.indiatimes.com/markets/stocks/rssfeeds/2146842.cms',
      publisherWebsite: 'https://economictimes.indiatimes.com/markets/stocks',
      language: 'en',
      defaultCategory: 'Market Updates',
      marketRegion: 'IN',
      marketTag: 'Nifty 50 • Sensex Updates',
    },
    {
      id: 'market-updates-hindi-daily',
      name: 'मार्केट अपडेट्स (Sensex & Nifty Daily)',
      handle: '@marketupdates.hi',
      logoBadge: 'UPDATES',
      url: 'https://news.google.com/rss/search?q=(Sensex+OR+Nifty+OR+IPO+OR+RBI+OR+%22%E0%A4%B6%E0%A5%87%E0%A4%AF%E0%A4%B0+%E0%A4%AC%E0%A4%BE%E0%A4%9C%E0%A4%BE%E0%A4%B0+%E0%A4%85%E0%A4%AA%E0%A4%A1%E0%A5%87%E0%A4%9F%22)+when:1d&hl=hi&gl=IN&ceid=IN:hi',
      publisherWebsite: 'https://www.bseindia.com',
      language: 'hi',
      defaultCategory: 'Market Updates',
      marketRegion: 'IN',
      marketTag: 'Daily Market Updates',
    },
    // 2. BUSINESS NEWS (Hindi & English)
    {
      id: 'business-hindi-rss',
      name: 'बिज़नेस और अर्थव्यवस्था (Hindi Business)',
      handle: '@business.hi',
      logoBadge: 'BIZ HI',
      url: 'https://news.google.com/rss/headlines/section/topic/BUSINESS?hl=hi&gl=IN&ceid=IN:hi',
      publisherWebsite: 'https://news.google.com',
      language: 'hi',
      defaultCategory: 'Business News',
      marketRegion: 'IN',
      marketTag: 'India Business & Economy',
    },
    {
      id: 'toi-business-rss',
      name: 'Times of India Business',
      handle: '@toibusiness',
      logoBadge: 'TOI BIZ',
      url: 'https://timesofindia.indiatimes.com/rssfeeds/1898055.cms',
      publisherWebsite: 'https://timesofindia.indiatimes.com/business',
      language: 'en',
      defaultCategory: 'Business News',
      marketRegion: 'IN',
      marketTag: 'Corporate & Economy',
    },
    // 3. WORLD MARKET (Global Indices, Wall Street, Nasdaq, S&P 500, FTSE, Nikkei)
    {
      id: 'world-market-rss',
      name: 'Global Markets (Wall Street • Nasdaq • Nikkei • FTSE)',
      handle: '@globalmarkets',
      logoBadge: 'GLOBAL',
      url: 'https://news.google.com/rss/search?q=(%22Wall+Street%22+OR+Nasdaq+OR+%22S%26P+500%22+OR+%22Global+Markets%22+OR+Nikkei+OR+FTSE+OR+%22Federal+Reserve%22)+when:3d&hl=en-IN&gl=IN&ceid=IN:en',
      publisherWebsite: 'https://www.bbc.com/news/business',
      language: 'en',
      defaultCategory: 'World Market',
      marketRegion: 'GLOBAL',
      marketTag: 'International Markets',
    },
    {
      id: 'bbc-global-business-rss',
      name: 'BBC Global Economy & Markets',
      handle: '@bbcbusiness',
      logoBadge: 'BBC MKT',
      url: 'https://feeds.bbci.co.uk/news/business/rss.xml',
      publisherWebsite: 'https://www.bbc.com/news/business',
      language: 'en',
      defaultCategory: 'World Market',
      marketRegion: 'GLOBAL',
      marketTag: 'World Economy & Trade',
    },
    // 4. CRYPTO EDUCATION & BLOCKCHAIN LITERACY
    {
      id: 'crypto-education-hindi-rss',
      name: 'क्रिप्टो और ब्लॉकचेन शिक्षा (Crypto Education)',
      handle: '@cryptoedu.hi',
      logoBadge: 'CRYPTO',
      url: 'https://news.google.com/rss/search?q=(Cryptocurrency+OR+Bitcoin+OR+Blockchain+OR+%22Digital+Rupee%22+OR+%E0%A4%95%E0%A5%8D%E0%A4%B0%E0%A4%BF%E0%A4%AA%E0%A5%8D%E0%A4%9F%E0%A5%8B+OR+%E0%A4%AC%E0%A4%BF%E0%A4%9F%E0%A4%95%E0%A5%89%E0%A4%87%E0%A4%A8)+when:7d&hl=hi&gl=IN&ceid=IN:hi',
      publisherWebsite: 'https://rbi.org.in',
      language: 'hi',
      defaultCategory: 'Crypto Education',
      marketRegion: 'GLOBAL',
      marketTag: 'Blockchain & Digital Assets Education',
    },
    // 5. TRADING BASICS & INVESTOR EDUCATION (SEBI, Mutual Funds, SIP, Financial Literacy)
    {
      id: 'trading-basics-hindi-rss',
      name: 'निवेश और ट्रेडिंग बेसिक्स (Investor Education)',
      handle: '@tradingbasics.hi',
      logoBadge: 'BASICS',
      url: 'https://news.google.com/rss/search?q=(SEBI+OR+%22Mutual+Fund%22+OR+SIP+OR+%E0%A4%A8%E0%A4%BF%E0%A4%B5%E0%A5%87%E0%A4%B6+OR+%22%E0%A4%AE%E0%A5%8D%E0%A4%AF%E0%A5%82%E0%A4%9A%E0%A5%81%E0%A4%85%E0%A4%B2+%E0%A4%AB%E0%A4%82%E0%A4%A1%22+OR+%22Financial+Literacy%22)+when:7d&hl=hi&gl=IN&ceid=IN:hi',
      publisherWebsite: 'https://investor.sebi.gov.in',
      language: 'hi',
      defaultCategory: 'Trading Basics',
      marketRegion: 'IN',
      marketTag: 'SEBI • SIP • Investor Education',
    },
    // 6. GOLD & SILVER BULLION MARKET NEWS (MCX Gold, Silver, Sarafa Bazaar)
    {
      id: 'gold-silver-market-hindi-rss',
      name: 'सोना और चांदी बाज़ार (Gold & Silver Market News)',
      handle: '@goldsilver.hi',
      logoBadge: 'GOLD/AG',
      url: 'https://news.google.com/rss/search?q=(%22Gold+Price%22+OR+%22Silver+Price%22+OR+%22MCX+Gold%22+OR+%22Gold+Rate%22+OR+%22%E0%A4%B8%E0%A5%8B%E0%A4%A8%E0%A5%87+%E0%A4%95%E0%A4%BE+%E0%A4%AD%E0%A4%BE%E0%A4%B5%22+OR+%22%E0%A4%9A%E0%A4%BE%E0%A4%82%E0%A4%A6%E0%A5%80+%E0%A4%95%E0%A4%BE+%E0%A4%AD%E0%A4%BE%E0%A4%B5%22+OR+%22%E0%A4%B8%E0%A4%B0%E0%A5%8D%E0%A4%B0%E0%A4%BE%E0%A4%AB%E0%A4%BE+%E0%A4%AC%E0%A4%BE%E0%A4%9C%E0%A4%BE%E0%A4%B0%22)+when:3d&hl=hi&gl=IN&ceid=IN:hi',
      publisherWebsite: 'https://www.mcxindia.com',
      language: 'hi',
      defaultCategory: 'Gold & Silver',
      marketRegion: 'IN',
      marketTag: 'Gold & Silver • MCX Bullion',
    },
    // 7. COMPANY UPDATES & CORPORATE RESULTS (Earnings, IPOs, Dividends)
    {
      id: 'company-updates-hindi-rss',
      name: 'कंपनी अपडेट्स और नतीजे (Company Updates & Earnings)',
      handle: '@companyupdates.hi',
      logoBadge: 'COMPANY',
      url: 'https://news.google.com/rss/search?q=(%22Quarterly+Results%22+OR+IPO+OR+Dividend+OR+Reliance+OR+TCS+OR+Infosys+OR+HDFC+OR+%22%E0%A4%A4%E0%A4%BF%E0%A4%AE%E0%A4%BE%E0%A4%B9%E0%A5%80+%E0%A4%A8%E0%A4%A4%E0%A5%80%E0%A4%9C%E0%A5%87%22+OR+%22%E0%A4%95%E0%A4%82%E0%A4%AA%E0%A4%A8%E0%A5%80%22)+when:2d&hl=hi&gl=IN&ceid=IN:hi',
      publisherWebsite: 'https://www.bseindia.com',
      language: 'hi',
      defaultCategory: 'Company Updates',
      marketRegion: 'IN',
      marketTag: 'Company Updates • Earnings • IPO',
    },
  ];

  const classifyTradingArticle = (
    text: string,
    defaultCategory: TradingCategoryType,
    marketRegion: 'IN' | 'GLOBAL'
  ): {
    primary: TradingCategoryType;
    categories: TradingCategoryType[];
    tags: string[];
    eduHindi: string;
    eduEnglish: string;
  } => {
    const lower = text.toLowerCase();
    const cats = new Set<TradingCategoryType>([defaultCategory]);
    const tags = new Set<string>();

    if (
      /\b(nifty|sensex|nse|bse|dalal street|sebi|rbi|rupee|midcap|smallcap)\b/i.test(
        lower
      ) ||
      /(निफ्टी|सेंसेक्स|शेयर बाजार|सेबी|आरबीआई|रुपया|बीएसई|एनएसई)/.test(text)
    ) {
      cats.add('India Market');
      cats.add('Market Updates');
      if (/nifty|निफ्टी/i.test(text)) tags.add('Nifty 50');
      if (/sensex|सेंसेक्स/i.test(text)) tags.add('Sensex');
      if (/\b(nse|bse)\b|एनएसई|बीएसई/i.test(text)) tags.add('NSE / BSE');
    }

    if (
      defaultCategory === 'Gold & Silver' ||
      /\b(gold price|silver price|gold rate|silver rate|bullion|mcx|24k|22k|gold futures|silver futures)\b/i.test(
        lower
      ) ||
      /(सोने का भाव|चांदी का भाव|सर्राफा|सोना सस्ता|सोना महंगा|चांदी सस्ती|चांदी महंगी|सोना-चांदी|सोने की कीमत|चांदी की कीमत)/.test(
        text
      )
    ) {
      cats.add('Gold & Silver');
      tags.add('Gold & Silver');
    }

    if (
      /\b(company|quarterly|q1|q2|q3|q4|results|earnings|dividend|ipo|reliance|tata|tcs|infosys|hdfc|adani)\b/i.test(
        lower
      ) ||
      /(कंपनी|तिमाही नतीजे|मुनाफा|डिविडेंड|आईपीओ|रिलायंस|टाटा|इंफोसिस)/.test(text)
    ) {
      cats.add('Company Updates');
      tags.add('Company Updates');
    }

    if (
      marketRegion === 'GLOBAL' ||
      /\b(wall street|nasdaq|s&p 500|dow jones|fed|federal reserve|nikkei|ftse|global market|us market)\b/i.test(
        lower
      ) ||
      /(वॉल स्ट्रीट|नैस्डैक|ग्लोबल मार्केट|अमेरिकी बाजार)/.test(text)
    ) {
      cats.add('World Market');
      tags.add('World Market');
    }

    if (
      /\b(crypto|bitcoin|ethereum|blockchain|cbdc|digital rupee|web3|token)\b/i.test(
        lower
      ) ||
      /(क्रिप्टो|बिटकॉइन|ब्लॉकचेन|डिजिटल रुपया)/.test(text)
    ) {
      cats.add('Crypto Education');
      tags.add('Blockchain & Crypto');
    }

    if (
      /\b(mutual fund|sip|investor|beginner|portfolio|diversification|compounding|demat|sebi|risk)\b/i.test(
        lower
      ) ||
      /(म्यूचुअल फंड|एसआईपी|निवेश|निवेशक|सेबी|जोखिम|पोर्टफोलियो|डीमैट)/.test(
        text
      )
    ) {
      cats.add('Trading Basics');
      tags.add('Investor Education');
    }

    if (
      /\b(rally|falls|gains|loses|closing|opening|points|high|low|ipo|dividend|results|q1|q2|q3|q4)\b/i.test(
        lower
      ) ||
      /(उछला|गिरावट|तेजी|अंक|आईपीओ|तिमाही नतीजे|बंद|खुला)/.test(text)
    ) {
      cats.add('Market Updates');
      tags.add('Market Update');
    }

    if (
      /\b(company|business|economy|gdp|inflation|bank|revenue|profit|export|import|tax|gst)\b/i.test(
        lower
      ) ||
      /(अर्थव्यवस्था|व्यापार|कंपनी|मुनाफा|बैंक|महंगाई|जीडीपी)/.test(text)
    ) {
      cats.add('Business News');
      tags.add('Business & Economy');
    }

    if (tags.size === 0) {
      tags.add(marketRegion === 'IN' ? 'India Market' : 'Global Market');
    }

    let eduHindi =
      'शैक्षिक नोट: बाज़ार की ख़बरों का उपयोग केवल आर्थिक रुझानों को समझने के लिए करें। किसी भी वित्तीय निर्णय से पहले स्वयं शोध (DYOR) करें।';
    let eduEnglish =
      'Educational Note: Use market news solely to understand macroeconomic & sector trends. Always conduct independent research before making financial decisions.';

    if (cats.has('Crypto Education')) {
      eduHindi =
        'क्रिप्टो शिक्षा: डिजिटल संपत्तियां अत्यधिक अस्थिर (volatile) होती हैं। ब्लॉकचेन तकनीक और नियामक नियमों को समझना केवल शैक्षिक उद्देश्य के लिए है।';
      eduEnglish =
        'Crypto Literacy: Digital assets carry high volatility and regulatory risk. Studying blockchain mechanics is for educational awareness only.';
    } else if (cats.has('Trading Basics')) {
      eduHindi =
        'निवेश शिक्षा: विविधीकरण (Diversification), जोखिम प्रबंधन और दीर्घकालिक अनुशासन वित्तीय साक्षरता के मूल स्तंभ हैं।';
      eduEnglish =
        'Trading Basics: Risk management, asset diversification, and understanding market structure are core pillars of investor literacy.';
    } else if (cats.has('India Market')) {
      eduHindi =
        'मार्केट बेसिक्स: Nifty 50 (NSE) में भारत की 50 प्रमुख कंपनियां और Sensex (BSE) में 30 प्रमुख कंपनियां शामिल होती हैं जो बाज़ार की दिशा दर्शाती हैं।';
      eduEnglish =
        'Market Basics: Nifty 50 (NSE) tracks 50 large Indian companies and Sensex (BSE) tracks 30 blue-chip companies as benchmark indices.';
    }

    return {
      primary: defaultCategory,
      categories: Array.from(cats),
      tags: Array.from(tags),
      eduHindi,
      eduEnglish,
    };
  };

  const buildTradingBilingualSummaries = (params: {
    headline: string;
    summary: string;
    sourceName: string;
    primaryCategory: TradingCategoryType;
    marketRegion: 'IN' | 'GLOBAL';
  }): {
    hindiHeadline: string;
    hindiSummary: string;
    englishSummary: string;
  } => {
    const hasDevanagari = /[\u0900-\u097F]/.test(
      `${params.headline} ${params.summary}`
    );

    const categoryHindiLabel: Record<TradingCategoryType, string> = {
      'India Market': 'भारतीय शेयर बाज़ार (NSE/BSE)',
      'World Market': 'अंतर्राष्ट्रीय बाज़ार (Global Market)',
      'Business News': 'बिज़नेस और अर्थव्यवस्था',
      'Gold & Silver': 'सोना और चांदी बाज़ार (Gold & Silver)',
      'Company Updates': 'कंपनी अपडेट्स और तिमाही नतीजे',
      'Crypto Education': 'क्रिप्टो और ब्लॉकचेन शिक्षा',
      'Trading Basics': 'ट्रेडिंग और निवेश बेसिक्स',
      'Market Updates': 'डेली मार्केट अपडेट',
    };

    const catHi = categoryHindiLabel[params.primaryCategory];
    const cleanSummary =
      params.summary && params.summary.length > 15
        ? params.summary
        : params.headline;

    if (hasDevanagari) {
      return {
        hindiHeadline: params.headline,
        hindiSummary:
          cleanSummary !== params.headline
            ? cleanSummary
            : `${params.sourceName} (${catHi}) की रिपोर्ट: ${params.headline}। पूरी जानकारी और विश्लेषण के लिए मूल लेख पढ़ें।`,
        englishSummary: `[${params.primaryCategory} • ${params.sourceName}] ${params.headline}. Open the full article from ${params.sourceName} for complete market report and official data.`,
      };
    }

    const shortEn =
      cleanSummary.slice(0, 220) + (cleanSummary.length > 220 ? '...' : '');
    return {
      hindiHeadline: `${catHi}: ${params.headline}`,
      hindiSummary: `🇮🇳 हिंदी मार्केट सारांश (${catHi} • ${params.sourceName}): ${shortEn}`,
      englishSummary: cleanSummary,
    };
  };

  const fetchSingleTradingRssSource = async (
    source: TradingRssSource,
    todayKey: string,
    yesterdayKey: string
  ): Promise<MoonTradingArticleItem[]> => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    try {
      const resp = await fetch(source.url, {
        signal: controller.signal,
        headers: {
          Accept:
            'application/rss+xml, application/xml, text/xml, */*;q=0.8',
          'User-Agent': 'MOON-Messenger-TradingReader/1.0',
          'Cache-Control': 'no-cache',
        },
      });
      clearTimeout(timeout);
      if (!resp.ok) return [];

      const xml = await resp.text();
      const itemBlocks = xml.match(/<item(?:\s[^>]*)?>[\s\S]*?<\/item>/gi) || [];
      const items: MoonTradingArticleItem[] = [];

      for (const block of itemBlocks.slice(0, 22)) {
        let rawTitle = extractTagContent(block, 'title');
        const rawLink = extractTagContent(block, 'link');
        const rawGuid = extractTagContent(block, 'guid');
        const rawPubDate =
          extractTagContent(block, 'pubDate') ||
          extractTagContent(block, 'dc:date') ||
          extractTagContent(block, 'published') ||
          extractTagContent(block, 'updated');
        const rawDescription = extractTagContent(block, 'description');
        const rawSourceTag = extractTagContent(block, 'source');
        const sourceUrlMatch = block.match(/<source[^>]+url=["']([^"']+)["']/i);

        const articleUrl = (rawLink || rawGuid).trim();
        if (!rawTitle || !articleUrl || !articleUrl.startsWith('http')) {
          continue;
        }

        const pubInfo = parseRssPubDateToIst(rawPubDate, todayKey, yesterdayKey);
        if (!pubInfo) {
          continue;
        }

        let effectiveSourceName = source.name;
        let effectiveSourceWebsite = source.publisherWebsite;
        if (rawSourceTag) {
          effectiveSourceName = stripHtmlTags(rawSourceTag);
          if (sourceUrlMatch && sourceUrlMatch[1]) {
            effectiveSourceWebsite = decodeRssXmlEntities(sourceUrlMatch[1]);
          }
          const suffix = ` - ${effectiveSourceName}`;
          if (rawTitle.endsWith(suffix)) {
            rawTitle = rawTitle.slice(0, -suffix.length).trim();
          }
        }

        const headline = stripHtmlTags(rawTitle);
        let summary = stripHtmlTags(rawDescription);
        if (rawSourceTag && summary.endsWith(effectiveSourceName)) {
          summary = summary
            .slice(0, -effectiveSourceName.length)
            .replace(/[-–—•\s]+$/, '')
            .trim();
        }
        if (!summary || summary === headline) {
          summary = headline;
        }

        const imageUrl = extractRssImageUrl(block);
        const combinedText = `${headline} ${summary}`;
        const classified = classifyTradingArticle(
          combinedText,
          source.defaultCategory,
          source.marketRegion
        );
        const bilingual = buildTradingBilingualSummaries({
          headline,
          summary,
          sourceName: effectiveSourceName,
          primaryCategory: classified.primary,
          marketRegion: source.marketRegion,
        });

        const uniqueKey = crypto
          .createHash('sha1')
          .update(`trading:${source.id}:${articleUrl}:${headline}`)
          .digest('hex')
          .slice(0, 16);

        items.push({
          id: `trading-${source.id}-${uniqueKey}`,
          sourceId: source.id,
          sourceName: effectiveSourceName,
          sourceHandle: source.handle,
          sourceLogoBadge: source.logoBadge,
          sourceWebsite: effectiveSourceWebsite,
          headline,
          summary,
          hindiHeadline: bilingual.hindiHeadline,
          hindiSummary: bilingual.hindiSummary,
          englishSummary: bilingual.englishSummary,
          articleUrl,
          imageUrl,
          publishedAtIso: pubInfo.iso,
          publishedAtText: pubInfo.text,
          publishedDateIst: pubInfo.publishedDateIst,
          isTodayIst: pubInfo.isTodayIst,
          isYesterdayIst: pubInfo.isYesterdayIst,
          dayBucket: pubInfo.dayBucket,
          relativeTimeText: pubInfo.relativeTimeText,
          language: /[\u0900-\u097F]/.test(headline) ? 'hi' : source.language,
          primaryCategory: classified.primary,
          categories: classified.categories,
          marketRegion: source.marketRegion,
          marketRegionLabel:
            source.marketRegion === 'IN'
              ? '🇮🇳 India Market (NSE/BSE)'
              : '🌍 Global Market',
          marketTags: classified.tags,
          educationalTakeawayHindi: classified.eduHindi,
          educationalTakeawayEnglish: classified.eduEnglish,
        });
      }

      return items;
    } catch {
      clearTimeout(timeout);
      return [];
    }
  };

  let cachedTradingPool: MoonTradingArticleItem[] = [];
  let cachedTradingTimestamp = 0;
  let cachedTradingIstDateKey = '';

  const getAggregatedTradingPool = async (
    forceRefresh = false
  ): Promise<MoonTradingArticleItem[]> => {
    const now = Date.now();
    const { todayKey, yesterdayKey } = getCurrentIstCalendarMetadata();

    if (
      !forceRefresh &&
      cachedTradingPool.length > 0 &&
      cachedTradingIstDateKey === todayKey &&
      now - cachedTradingTimestamp < NEWS_CACHE_TTL_MS
    ) {
      return cachedTradingPool;
    }

    const results = await Promise.all(
      TRADING_RSS_SOURCES.map((src) =>
        fetchSingleTradingRssSource(src, todayKey, yesterdayKey)
      )
    );
    const flat = results.flat();

    const seenUrls = new Set<string>();
    const seenHeadlines = new Set<string>();
    const seenIds = new Set<string>();
    const deduped: MoonTradingArticleItem[] = [];

    for (const item of flat) {
      const normUrl = item.articleUrl.toLowerCase().replace(/\/+$/, '');
      const normTitle = item.headline.toLowerCase().slice(0, 65);
      if (
        seenIds.has(item.id) ||
        seenUrls.has(normUrl) ||
        seenHeadlines.has(normTitle)
      ) {
        continue;
      }
      seenIds.add(item.id);
      seenUrls.add(normUrl);
      seenHeadlines.add(normTitle);
      deduped.push(item);
    }

    // Prioritize Today (Asia/Kolkata) articles first, then Hindi Indian market articles, then newest timestamp
    deduped.sort((a, b) => {
      if (a.isTodayIst !== b.isTodayIst) {
        return a.isTodayIst ? -1 : 1;
      }
      return (
        new Date(b.publishedAtIso).getTime() -
        new Date(a.publishedAtIso).getTime()
      );
    });

    if (deduped.length > 0) {
      cachedTradingPool = deduped;
      cachedTradingTimestamp = now;
      cachedTradingIstDateKey = todayKey;
    }
    return deduped;
  };

  app.get('/api/trading/feed', async (req: Request, res: Response) => {
    try {
      const category = String(req.query.category || 'all')
        .trim()
        .toLowerCase();
      const dateFilterRaw = String(req.query.dateFilter || 'today')
        .trim()
        .toLowerCase();
      const dateFilter: 'today' | 'previous' | 'all' =
        dateFilterRaw === 'previous'
          ? 'previous'
          : dateFilterRaw === 'all'
            ? 'all'
            : 'today';
      const searchQ = String(req.query.q || '').trim();
      const offset = Math.max(0, Number(req.query.offset) || 0);
      const limit = Math.min(40, Math.max(1, Number(req.query.limit) || 12));
      const forceRefresh = req.query.refresh === '1';

      const istMeta = getCurrentIstCalendarMetadata();
      let pool = await getAggregatedTradingPool(forceRefresh);

      // Dynamic live RSS search for custom trading/stock/market queries
      if (searchQ.length >= 2) {
        const dynamicTradingSource: TradingRssSource = {
          id: 'live-trading-search',
          name: 'Market Search RSS',
          handle: '@marketsearch',
          logoBadge: 'MKT',
          url: `https://news.google.com/rss/search?q=${encodeURIComponent(
            `${searchQ} market OR stock OR share`
          )}&hl=hi&gl=IN&ceid=IN:hi`,
          publisherWebsite: 'https://news.google.com',
          language: 'hi',
          defaultCategory: 'Market Updates',
          marketRegion: 'IN',
          marketTag: 'Market Search',
        };
        const liveItems = await fetchSingleTradingRssSource(
          dynamicTradingSource,
          istMeta.todayKey,
          istMeta.yesterdayKey
        );
        const existingUrls = new Set(pool.map((p) => p.articleUrl));
        pool = [
          ...liveItems.filter((item) => !existingUrls.has(item.articleUrl)),
          ...pool,
        ];
      }

      let filtered = pool;
      if (category === 'india_market') {
        filtered = filtered
          .filter(
            (i) =>
              i.primaryCategory === 'India Market' ||
              (i.marketRegion === 'IN' && i.categories.includes('India Market'))
          )
          .sort((a, b) => {
            if (a.isTodayIst !== b.isTodayIst) return a.isTodayIst ? -1 : 1;
            const aPri = a.primaryCategory === 'India Market' ? 1 : 0;
            const bPri = b.primaryCategory === 'India Market' ? 1 : 0;
            if (aPri !== bPri) return bPri - aPri;
            return (
              new Date(b.publishedAtIso).getTime() -
              new Date(a.publishedAtIso).getTime()
            );
          });
      } else if (category === 'world_market') {
        filtered = filtered
          .filter(
            (i) =>
              i.marketRegion === 'GLOBAL' ||
              i.primaryCategory === 'World Market' ||
              i.categories.includes('World Market')
          )
          .sort((a, b) => {
            if (a.isTodayIst !== b.isTodayIst) return a.isTodayIst ? -1 : 1;
            const aGlobal = a.marketRegion === 'GLOBAL' ? 1 : 0;
            const bGlobal = b.marketRegion === 'GLOBAL' ? 1 : 0;
            if (aGlobal !== bGlobal) return bGlobal - aGlobal;
            return (
              new Date(b.publishedAtIso).getTime() -
              new Date(a.publishedAtIso).getTime()
            );
          });
      } else if (category === 'business_news') {
        filtered = filtered
          .filter((i) => i.categories.includes('Business News'))
          .sort((a, b) => {
            if (a.isTodayIst !== b.isTodayIst) return a.isTodayIst ? -1 : 1;
            const aPri = a.primaryCategory === 'Business News' ? 1 : 0;
            const bPri = b.primaryCategory === 'Business News' ? 1 : 0;
            if (aPri !== bPri) return bPri - aPri;
            return (
              new Date(b.publishedAtIso).getTime() -
              new Date(a.publishedAtIso).getTime()
            );
          });
      } else if (category === 'crypto_education') {
        filtered = filtered
          .filter((i) => i.categories.includes('Crypto Education'))
          .sort((a, b) => {
            if (a.isTodayIst !== b.isTodayIst) return a.isTodayIst ? -1 : 1;
            const aPri = a.primaryCategory === 'Crypto Education' ? 1 : 0;
            const bPri = b.primaryCategory === 'Crypto Education' ? 1 : 0;
            if (aPri !== bPri) return bPri - aPri;
            return (
              new Date(b.publishedAtIso).getTime() -
              new Date(a.publishedAtIso).getTime()
            );
          });
      } else if (category === 'trading_basics') {
        filtered = filtered
          .filter((i) => i.categories.includes('Trading Basics'))
          .sort((a, b) => {
            if (a.isTodayIst !== b.isTodayIst) return a.isTodayIst ? -1 : 1;
            const aPri = a.primaryCategory === 'Trading Basics' ? 1 : 0;
            const bPri = b.primaryCategory === 'Trading Basics' ? 1 : 0;
            if (aPri !== bPri) return bPri - aPri;
            return (
              new Date(b.publishedAtIso).getTime() -
              new Date(a.publishedAtIso).getTime()
            );
          });
      } else if (category === 'market_updates') {
        filtered = filtered
          .filter((i) => i.categories.includes('Market Updates'))
          .sort((a, b) => {
            if (a.isTodayIst !== b.isTodayIst) return a.isTodayIst ? -1 : 1;
            const aPri = a.primaryCategory === 'Market Updates' ? 1 : 0;
            const bPri = b.primaryCategory === 'Market Updates' ? 1 : 0;
            if (aPri !== bPri) return bPri - aPri;
            return (
              new Date(b.publishedAtIso).getTime() -
              new Date(a.publishedAtIso).getTime()
            );
          });
      } else if (category === 'gold_silver') {
        filtered = filtered
          .filter((i) => i.categories.includes('Gold & Silver'))
          .sort((a, b) => {
            if (a.isTodayIst !== b.isTodayIst) return a.isTodayIst ? -1 : 1;
            const aPri = a.primaryCategory === 'Gold & Silver' ? 1 : 0;
            const bPri = b.primaryCategory === 'Gold & Silver' ? 1 : 0;
            if (aPri !== bPri) return bPri - aPri;
            return (
              new Date(b.publishedAtIso).getTime() -
              new Date(a.publishedAtIso).getTime()
            );
          });
      } else if (category === 'company_updates') {
        filtered = filtered
          .filter((i) => i.categories.includes('Company Updates'))
          .sort((a, b) => {
            if (a.isTodayIst !== b.isTodayIst) return a.isTodayIst ? -1 : 1;
            const aPri = a.primaryCategory === 'Company Updates' ? 1 : 0;
            const bPri = b.primaryCategory === 'Company Updates' ? 1 : 0;
            if (aPri !== bPri) return bPri - aPri;
            return (
              new Date(b.publishedAtIso).getTime() -
              new Date(a.publishedAtIso).getTime()
            );
          });
      }

      if (searchQ) {
        const qLower = searchQ.toLowerCase();
        const matched = filtered.filter(
          (item) =>
            item.headline.toLowerCase().includes(qLower) ||
            item.summary.toLowerCase().includes(qLower) ||
            item.hindiSummary.toLowerCase().includes(qLower) ||
            item.sourceName.toLowerCase().includes(qLower) ||
            item.marketTags.some((t) => t.toLowerCase().includes(qLower)) ||
            item.categories.some((c) => c.toLowerCase().includes(qLower))
        );
        if (matched.length > 0) {
          filtered = matched;
        }
      }

      const todayMatching = filtered.filter((i) => i.isTodayIst);
      const previousMatching = filtered.filter((i) => !i.isTodayIst);
      const todayCount = todayMatching.length;
      const previousDaysCount = previousMatching.length;

      let dateFiltered = filtered;
      if (dateFilter === 'today') {
        dateFiltered = todayMatching.length > 0 ? todayMatching : filtered;
      } else if (dateFilter === 'previous') {
        dateFiltered = previousMatching;
      }

      const slice = dateFiltered.slice(offset, offset + limit);

      return res.json({
        items: slice,
        totalCount: dateFiltered.length,
        todayCount,
        previousDaysCount,
        dateFilter,
        fallbackToRecentUsed:
          dateFilter === 'today' &&
          todayMatching.length === 0 &&
          filtered.length > 0,
        todayIstDateKey: istMeta.todayKey,
        todayFormattedIst: istMeta.todayFormattedIst,
        todayFormattedHindi: istMeta.todayFormattedHindi,
        fetchedAtIstText: istMeta.fetchedAtIstText,
        sourcesActive: TRADING_RSS_SOURCES.length,
        offset,
        limit,
        hasMore: offset + slice.length < dateFiltered.length,
      });
    } catch (err) {
      return res.status(500).json({
        error:
          err instanceof Error
            ? err.message
            : 'Failed to load live market & trading RSS feed.',
      });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`MOON server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
