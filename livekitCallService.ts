import { RealtimeChannel } from '@supabase/supabase-js';
import { supabase } from '../lib/supabaseClient';
import {
  LiveKitServerStatus,
  LiveKitTokenResponse,
  VoiceCallSignalPayload,
} from '../types/moon';

/**
 * Compute deterministic canonical LiveKit room name for two user IDs using least() and greatest()
 */
export function getCanonicalCallRoomName(userA: string, userB: string): string {
  const [u1, u2] = userA < userB ? [userA, userB] : [userB, userA];
  return `moon-call-${u1}-${u2}`;
}

/**
 * Check if server-side LiveKit credentials (LIVEKIT_URL, LIVEKIT_API_KEY, LIVEKIT_API_SECRET)
 * are configured on the Express backend without exposing secret values to the browser.
 */
export async function fetchLiveKitServerStatus(): Promise<LiveKitServerStatus> {
  const response = await fetch('/api/livekit/status', {
    method: 'GET',
    headers: {
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(
      `Failed to check LiveKit server status (HTTP ${response.status}).`
    );
  }

  return (await response.json()) as LiveKitServerStatus;
}

/**
 * Request a short-lived LiveKit access token from the secure server endpoint (/api/livekit/token).
 * Passes the caller's Supabase access_token in the Authorization Bearer header so the server
 * verifies both Supabase Auth identity and accepted friendship in public.friendships (user1, user2).
 */
export async function requestLiveKitCallToken(
  friendId: string
): Promise<LiveKitTokenResponse> {
  if (!supabase) {
    throw new Error(
      'Supabase client is not configured. Configure VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY first.'
    );
  }

  const {
    data: { session },
    error: sessionError,
  } = await supabase.auth.getSession();

  if (sessionError || !session?.access_token) {
    throw new Error(
      sessionError?.message ||
        'No active Supabase session token found. Please sign in again before placing a voice call.'
    );
  }

  const response = await fetch('/api/livekit/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${session.access_token}`,
    },
    body: JSON.stringify({ friendId }),
  });

  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      payload?.error ||
        `LiveKit token generation failed with HTTP status ${response.status}.`
    );
  }

  const cleanToken =
    typeof payload?.token === 'string'
      ? payload.token.trim().replace(/^['"]+|['"]+$/g, '').trim()
      : '';
  const cleanWsUrl =
    typeof payload?.wsUrl === 'string'
      ? payload.wsUrl.trim().replace(/^['"]+|['"]+$/g, '').replace(/\/+$/, '').trim()
      : '';

  if (!cleanToken || cleanToken.split('.').length !== 3) {
    throw new Error(
      'Server returned a malformed LiveKit JWT token (expected 3 JWT segments).'
    );
  }

  if (!cleanWsUrl || !/^wss?:\/\//i.test(cleanWsUrl)) {
    throw new Error(
      'Server returned an invalid LiveKit WebSocket URL (expected wss:// or ws://).'
    );
  }

  return {
    ...(payload as LiveKitTokenResponse),
    token: cleanToken,
    wsUrl: cleanWsUrl,
  };
}

/**
 * Subscribe to real-time peer-to-peer call signaling over Supabase Realtime Broadcast.
 * Handles incoming call invitations, accept, reject, busy, and end-call events across devices.
 */
export function subscribeToVoiceCallSignaling(
  currentUserId: string,
  onSignal: (signal: VoiceCallSignalPayload) => void
): {
  sendSignal: (signal: VoiceCallSignalPayload) => Promise<void>;
  unsubscribe: () => void;
} {
  const client = supabase;
  if (!client) {
    return {
      sendSignal: async () => {
        throw new Error('Supabase client is not initialized.');
      },
      unsubscribe: () => {},
    };
  }

  const processedCallEvents = new Set<string>();

  const channel: RealtimeChannel = client.channel('moon-voice-signaling', {
    config: {
      broadcast: {
        self: false,
        ack: true,
      },
    },
  });

  channel
    .on('broadcast', { event: 'voice-call-signal' }, ({ payload }) => {
      const data = payload as VoiceCallSignalPayload | undefined;
      if (!data || data.toUserId !== currentUserId) {
        return;
      }

      // Idempotency guard against duplicate broadcast deliveries
      const dedupeKey = `${data.callId}:${data.type}:${data.sentAtIso}`;
      if (processedCallEvents.has(dedupeKey)) {
        return;
      }
      processedCallEvents.add(dedupeKey);

      onSignal(data);
    })
    .subscribe();

  const sendSignal = async (signal: VoiceCallSignalPayload) => {
    const status = await channel.send({
      type: 'broadcast',
      event: 'voice-call-signal',
      payload: signal,
    });

    if (status !== 'ok') {
      throw new Error(
        `Failed to send voice call signal (${signal.type}) over Supabase Realtime Broadcast.`
      );
    }
  };

  const unsubscribe = () => {
    client.removeChannel(channel);
  };

  return { sendSignal, unsubscribe };
}

/**
 * Subtle Web Audio API lunar chime for incoming/outgoing ringing states
 * Safely handles browser autoplay restrictions.
 */
export function createLunarRingtoneController() {
  let intervalId: number | null = null;
  let audioCtx: AudioContext | null = null;

  const playChimeOnce = (mode: 'incoming' | 'outgoing') => {
    try {
      const AudioContextClass =
        window.AudioContext ||
        (window as unknown as { webkitAudioContext?: typeof AudioContext })
          .webkitAudioContext;
      if (!AudioContextClass) return;

      if (!audioCtx) {
        audioCtx = new AudioContextClass();
      }
      if (audioCtx.state === 'suspended') {
        audioCtx.resume().catch(() => {});
      }

      const now = audioCtx.currentTime;
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();

      osc.type = 'sine';
      if (mode === 'incoming') {
        osc.frequency.setValueAtTime(528, now);
        osc.frequency.exponentialRampToValueAtTime(660, now + 0.18);
      } else {
        osc.frequency.setValueAtTime(440, now);
      }

      gain.gain.setValueAtTime(0.001, now);
      gain.gain.exponentialRampToValueAtTime(0.06, now + 0.04);
      gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.45);

      osc.connect(gain);
      gain.connect(audioCtx.destination);

      osc.start(now);
      osc.stop(now + 0.48);
    } catch {
      // Ignore Web Audio autoplay blocks
    }
  };

  return {
    start(mode: 'incoming' | 'outgoing') {
      this.stop();
      playChimeOnce(mode);
      intervalId = window.setInterval(() => {
        playChimeOnce(mode);
      }, 2400);
    },
    stop() {
      if (intervalId !== null) {
        window.clearInterval(intervalId);
        intervalId = null;
      }
    },
  };
}
