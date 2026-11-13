export type AuthMode = 'welcome' | 'login' | 'signup';

export type AppScreen =
  | 'welcome'
  | 'home'
  | 'trading'
  | 'chats'
  | 'friends'
  | 'add-friend'
  | 'requests'
  | 'profile'
  | 'voice-call'
  | 'reels';

export type PresenceState = 'online' | 'idle' | 'offline';

export interface UserProfile {
  id: string;
  username: string;
  displayName: string;
  friendCode: string;
  email?: string;
  isGuest: boolean;
  bio: string;
  avatarHue: number;
  createdAt: string;
}

export interface FriendContact {
  id: string;
  username: string;
  displayName: string;
  friendCode: string;
  presence: PresenceState;
  lastSeenText: string;
  bio: string;
  avatarHue: number;
  unreadCount: number;
}

export type FriendRequestStatus = 'pending' | 'accepted' | 'rejected';

export interface FriendRequest {
  id: string;
  direction: 'incoming' | 'outgoing';
  senderId: string;
  receiverId: string;
  fromUser: {
    id: string;
    username: string;
    displayName: string;
    friendCode: string;
    avatarHue: number;
    bio: string;
  };
  note?: string;
  createdAtText: string;
  status: FriendRequestStatus;
}

export type RelationshipLookupStatus =
  | 'none'
  | 'self'
  | 'friends'
  | 'pending_outgoing'
  | 'pending_incoming';

export interface FriendCodeSearchResult {
  profile: {
    id: string;
    username: string;
    displayName: string;
    friendCode: string;
    avatarHue: number;
    bio: string;
  };
  relationshipStatus: RelationshipLookupStatus;
  existingRequestId?: string;
}

export interface DiagnosticCheckItem {
  id: string;
  title: string;
  status: 'pass' | 'warn' | 'fail';
  detail: string;
  sqlFix?: string;
}

export interface FriendSystemDiagnosticReport {
  checkedAt: string;
  allPassed: boolean;
  checks: DiagnosticCheckItem[];
}

export type MessageDeliveryState = 'sending' | 'delivered' | 'failed';

export type ChatMediaKind = 'image' | 'video';

export interface ChatMediaAttachment {
  version: 1;
  kind: ChatMediaKind;
  bucket: 'chat-media';
  storagePath: string;
  mimeType: string;
  fileName: string;
  fileSize: number;
  caption?: string;
  signedUrl?: string;
}

export type LocationShareSource = 'gps' | 'search' | 'pin';

export interface ChatLocationAttachment {
  version: 1;
  latitude: number;
  longitude: number;
  label: string;
  address?: string;
  caption?: string;
  source: LocationShareSource;
  accuracyMeters?: number;
}

export interface ChatMessage {
  id: string;
  threadFriendId: string;
  senderId: 'me' | string;
  text: string;
  timestampText: string;
  createdAtIso?: string;
  deliveryState: MessageDeliveryState;
  media?: ChatMediaAttachment;
  location?: ChatLocationAttachment;
}

export type VoiceCallPreviewState =
  | 'ready'
  | 'ringing-ui'
  | 'active-ui'
  | 'error-ui';

export type VoiceCallStatus =
  | 'idle'
  | 'calling'
  | 'incoming'
  | 'connecting'
  | 'connected'
  | 'rejected'
  | 'ended'
  | 'error';

export type VoiceCallSignalType =
  | 'call:invite'
  | 'call:accept'
  | 'call:reject'
  | 'call:end'
  | 'call:busy';

export interface VoiceCallSignalPayload {
  type: VoiceCallSignalType;
  callId: string;
  roomName: string;
  fromUserId: string;
  fromUsername: string;
  fromDisplayName: string;
  fromFriendCode: string;
  fromAvatarHue: number;
  toUserId: string;
  sentAtIso: string;
  reason?: string;
}

export interface LiveKitServerStatus {
  configured: boolean;
  cloudVerified: boolean;
  hasUrl: boolean;
  hasApiKey: boolean;
  hasApiSecret: boolean;
  missingKeys: string[];
  wsHostPreview: string | null;
  diagnosticCode?:
    | 'ok'
    | 'missing_env'
    | 'masked_secret'
    | 'swapped_keys'
    | 'invalid_key_format'
    | 'cloud_rejected_token'
    | 'cloud_rejected_key'
    | 'network_error';
  diagnosticMessage?: string | null;
}

export interface LiveKitTokenResponse {
  token: string;
  wsUrl: string;
  roomName: string;
  participantIdentity: string;
  participantName: string;
  expiresInSeconds: number;
  cloudValidated?: boolean;
}

export interface SupabaseReadinessStatus {
  envConfigured: boolean;
  isConnected: boolean;
  configuredUrl: string | null;
  modeLabel: string;
  tablesPrepared: string[];
  missingTables: string[];
  securityNote: string;
  lastError?: string | null;
}

