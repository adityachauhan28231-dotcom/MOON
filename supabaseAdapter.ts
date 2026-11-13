import { RealtimeChannel, User } from '@supabase/supabase-js';
import {
  getConfiguredSupabaseUrl,
  isSupabaseEnvConfigured,
  supabase,
} from '../lib/supabaseClient';
import {
  ChatLocationAttachment,
  ChatMediaAttachment,
  ChatMediaKind,
  ChatMessage,
  DiagnosticCheckItem,
  FriendCodeSearchResult,
  FriendContact,
  FriendRequest,
  FriendSystemDiagnosticReport,
  LocationShareSource,
  SupabaseReadinessStatus,
  UserProfile,
} from '../types/moon';

/**
 * Complete Supabase PostgreSQL Schema + Friend-Only Messaging RLS Policies
 * Matches confirmed database columns:
 * - public.profiles (id, username, friend_code, created_at, avatar_hue, display_name, is_guest, bio)
 * - public.friend_requests (id, sender_id, receiver_id, status, created_at)
 * - public.friendships (id, user1, user2, created_at) [canonical least/greatest]
 * - public.messages (id, sender_id, receiver_id, content, created_at)
 */
export const PREPARED_SUPABASE_SQL_SCHEMA = `-- MOON Messenger — Safe Non-Destructive Schema & RLS Policy Alignment
-- Preserves existing tables and data. Uses friendships(user1, user2) and messages(sender_id, receiver_id, content).

alter table public.profiles add column if not exists avatar_hue text not null default '268';
alter table public.profiles add column if not exists display_name text not null default '';
alter table public.profiles add column if not exists is_guest boolean not null default false;
alter table public.profiles add column if not exists bio text not null default '';

alter table public.profiles enable row level security;

drop policy if exists "profiles_select_authenticated" on public.profiles;
create policy "profiles_select_authenticated"
  on public.profiles for select to authenticated
  using (auth.uid() is not null);

drop policy if exists "profiles_insert_own" on public.profiles;
create policy "profiles_insert_own"
  on public.profiles for insert to authenticated
  with check (auth.uid() = id);

drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own"
  on public.profiles for update to authenticated
  using (auth.uid() = id) with check (auth.uid() = id);

alter table public.friend_requests enable row level security;

drop policy if exists "friend_requests_select_involved" on public.friend_requests;
create policy "friend_requests_select_involved"
  on public.friend_requests for select to authenticated
  using (auth.uid() = sender_id or auth.uid() = receiver_id);

drop policy if exists "friend_requests_insert_sender" on public.friend_requests;
create policy "friend_requests_insert_sender"
  on public.friend_requests for insert to authenticated
  with check (auth.uid() = sender_id and sender_id <> receiver_id and status = 'pending');

drop policy if exists "friend_requests_update_involved" on public.friend_requests;
create policy "friend_requests_update_involved"
  on public.friend_requests for update to authenticated
  using (auth.uid() = receiver_id or auth.uid() = sender_id)
  with check (auth.uid() = receiver_id or auth.uid() = sender_id);

drop policy if exists "friend_requests_delete_involved" on public.friend_requests;
create policy "friend_requests_delete_involved"
  on public.friend_requests for delete to authenticated
  using (auth.uid() = sender_id or auth.uid() = receiver_id);

alter table public.friendships enable row level security;

drop policy if exists "friendships_select_involved" on public.friendships;
create policy "friendships_select_involved"
  on public.friendships for select to authenticated
  using (auth.uid() = user1 or auth.uid() = user2);

drop policy if exists "friendships_insert_when_accepted" on public.friendships;
create policy "friendships_insert_when_accepted"
  on public.friendships for insert to authenticated
  with check (
    (auth.uid() = user1 or auth.uid() = user2)
    and exists (
      select 1 from public.friend_requests fr
      where fr.status = 'accepted'
        and ((fr.sender_id = user1 and fr.receiver_id = user2)
          or (fr.sender_id = user2 and fr.receiver_id = user1))
    )
  );

create or replace function public.are_friends(user_a uuid, user_b uuid)
returns boolean language sql security definer stable set search_path = public as $$
  select exists (
    select 1 from public.friendships f
    where (f.user1 = least(user_a, user_b) and f.user2 = greatest(user_a, user_b))
       or (f.user1 = user_a and f.user2 = user_b)
       or (f.user1 = user_b and f.user2 = user_a)
  );
$$;

create or replace function public.handle_accepted_friend_request()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  u1 uuid := least(new.sender_id, new.receiver_id);
  u2 uuid := greatest(new.sender_id, new.receiver_id);
begin
  if new.status = 'accepted' and (old.status is distinct from 'accepted') then
    insert into public.friendships (user1, user2)
    values (u1, u2)
    on conflict (user1, user2) do nothing;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_friend_request_accepted on public.friend_requests;
create trigger trg_friend_request_accepted
  after update on public.friend_requests
  for each row execute function public.handle_accepted_friend_request();

alter table public.messages enable row level security;

drop policy if exists "messages_select_friends_only" on public.messages;
create policy "messages_select_friends_only"
  on public.messages for select to authenticated
  using (
    (auth.uid() = sender_id or auth.uid() = receiver_id)
    and public.are_friends(sender_id, receiver_id)
  );

drop policy if exists "messages_insert_friends_only" on public.messages;
create policy "messages_insert_friends_only"
  on public.messages for insert to authenticated
  with check (
    auth.uid() = sender_id
    and sender_id <> receiver_id
    and public.are_friends(sender_id, receiver_id)
  );

do $$
begin
  begin alter publication supabase_realtime add table public.messages; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.friend_requests; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.friendships; exception when duplicate_object then null; end;
end $$;

notify pgrst, 'reload schema';`;

export function generateFriendCode(seed?: number): string {
  const digits = seed
    ? String(seed).padStart(4, '0').slice(0, 4)
    : String(Math.floor(1000 + Math.random() * 9000));
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const c1 = chars[Math.floor(Math.random() * chars.length)];
  const c2 = chars[Math.floor(Math.random() * chars.length)];
  return `MOON-${digits}-${c1}${c2}`;
}

export function normalizeFriendCode(raw: string): string {
  const clean = raw.toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (clean.startsWith('MOON')) {
    const body = clean.slice(4);
    if (body.length <= 4) return `MOON-${body}`;
    return `MOON-${body.slice(0, 4)}-${body.slice(4, 6)}`;
  }
  if (clean.length <= 4) {
    return `MOON-${clean}`;
  }
  return `MOON-${clean.slice(0, 4)}-${clean.slice(4, 6)}`;
}

/**
 * Requirement 2: Canonical UUID pair ordering equivalent to PostgreSQL least(a, b) and greatest(a, b)
 */
export function getCanonicalUserPair(
  userA: string,
  userB: string
): [string, string] {
  const a = userA.trim().toLowerCase();
  const b = userB.trim().toLowerCase();
  return a < b ? [userA, userB] : [userB, userA];
}

export function formatRelativeTime(isoString?: string): string {
  if (!isoString) return 'Recent';
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return 'Recent';
  const diffSec = Math.floor((Date.now() - date.getTime()) / 1000);
  if (diffSec < 45) return 'Just now';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

export function formatClockTime(isoString?: string): string {
  const date = isoString ? new Date(isoString) : new Date();
  if (Number.isNaN(date.getTime())) return 'Now';
  return `${String(date.getHours()).padStart(2, '0')}:${String(
    date.getMinutes()
  ).padStart(2, '0')}`;
}

interface DbProfileRow {
  id: string;
  username: string;
  friend_code: string;
  display_name?: string | null;
  is_guest?: boolean | null;
  bio?: string | null;
  avatar_hue?: string | number | null;
  created_at?: string;
}

interface DbFriendshipRow {
  id?: string;
  user1: string;
  user2: string;
  created_at?: string;
}

interface DbFriendRequestRow {
  id: string;
  sender_id: string;
  receiver_id: string;
  status: 'pending' | 'accepted' | 'rejected';
  created_at?: string;
}

interface DbMessageRow {
  id: string;
  sender_id: string;
  receiver_id: string;
  content: string;
  created_at: string;
}

export function parseAvatarHue(
  rawHue: string | number | null | undefined
): number {
  if (typeof rawHue === 'number' && Number.isFinite(rawHue)) {
    return rawHue;
  }
  if (typeof rawHue === 'string' && rawHue.trim() !== '') {
    const parsed = Number.parseInt(rawHue.trim(), 10);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return 268;
}

function resolveDisplayName(row: DbProfileRow): string {
  if (row.display_name && row.display_name.trim()) {
    return row.display_name.trim();
  }
  return (
    (row.username || 'user')
      .split('_')
      .filter(Boolean)
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(' ') || row.username
  );
}

function mapDbProfileToUser(row: DbProfileRow, email?: string): UserProfile {
  return {
    id: row.id,
    username: row.username,
    displayName: resolveDisplayName(row),
    friendCode: row.friend_code,
    email,
    isGuest: Boolean(row.is_guest ?? !email),
    bio: row.bio || 'Connected on MOON · Private friend-code messaging.',
    avatarHue: parseAvatarHue(row.avatar_hue),
    createdAt: row.created_at || new Date().toISOString(),
  };
}

function mapDbProfileToFriend(row: DbProfileRow): FriendContact {
  return {
    id: row.id,
    username: row.username,
    displayName: resolveDisplayName(row),
    friendCode: row.friend_code,
    presence: 'online',
    lastSeenText: `Joined ${formatRelativeTime(row.created_at)}`,
    bio: row.bio || 'Connected via MOON friend code.',
    avatarHue: parseAvatarHue(row.avatar_hue),
    unreadCount: 0,
  };
}

export function getSupabaseReadinessStatus(): SupabaseReadinessStatus {
  const envConfigured = isSupabaseEnvConfigured();
  const configuredUrl = getConfiguredSupabaseUrl();

  return {
    envConfigured,
    isConnected: false,
    configuredUrl,
    modeLabel: envConfigured
      ? 'Supabase Env Configured · Ready to Verify Tables & Auth'
      : 'Awaiting VITE_SUPABASE_URL & VITE_SUPABASE_ANON_KEY in Environment Variables',
    tablesPrepared: ['profiles', 'friend_requests', 'friendships', 'messages'],
    missingTables: [],
    securityNote:
      'Uses @supabase/supabase-js with public anon key only. Friendships use (user1, user2) and messages use (sender_id, receiver_id, content) enforced by Row Level Security.',
  };
}

export async function verifySupabaseDatabaseConnection(): Promise<SupabaseReadinessStatus> {
  const base = getSupabaseReadinessStatus();
  if (!supabase || !base.envConfigured) {
    return {
      ...base,
      isConnected: false,
      lastError:
        'Missing VITE_SUPABASE_URL or VITE_SUPABASE_ANON_KEY in environment variables.',
    };
  }

  const requiredTables = [
    { name: 'profiles', cols: 'id, username, friend_code' },
    {
      name: 'friend_requests',
      cols: 'id, sender_id, receiver_id, status, created_at',
    },
    { name: 'friendships', cols: 'user1, user2' },
    {
      name: 'messages',
      cols: 'id, sender_id, receiver_id, content, created_at',
    },
  ] as const;

  const missingTables: string[] = [];
  const columnErrors: string[] = [];

  for (const t of requiredTables) {
    const { error } = await supabase
      .from(t.name)
      .select(t.cols, { count: 'exact', head: true });

    if (error) {
      if (
        error.code === '42P01' ||
        error.code === 'PGRST205' ||
        error.message?.toLowerCase().includes('does not exist') ||
        error.message?.toLowerCase().includes('schema cache')
      ) {
        if (error.message?.toLowerCase().includes('column')) {
          columnErrors.push(`${t.name}: ${error.message}`);
        } else {
          missingTables.push(t.name);
        }
      } else {
        columnErrors.push(`${t.name}: ${error.message}`);
      }
    }
  }

  const lastError =
    columnErrors.length > 0 ? columnErrors.join(' | ') : null;
  const isConnected = missingTables.length === 0 && !lastError;

  return {
    ...base,
    isConnected,
    missingTables,
    lastError,
    modeLabel: isConnected
      ? 'Connected & Verified · Tables (profiles, friend_requests, friendships, messages) Active'
      : missingTables.length > 0
      ? `Supabase Reachable · Missing Tables (${missingTables.join(', ')})`
      : `Supabase Schema Warning · ${lastError}`,
  };
}

function extractMissingColumnFromError(message?: string): string | null {
  if (!message) return null;
  const match = message.match(/Could not find the '([^']+)' column/i);
  return match?.[1] || null;
}

/**
 * Fetches an existing profile row for an authenticated Supabase user, or creates one if missing.
 * Also guarantees that `friend_code` is populated on the user's profile row.
 */
export async function fetchOrBootstrapProfile(
  authUser: User,
  preferredUsername?: string
): Promise<UserProfile> {
  if (!supabase) {
    throw new Error(
      'Supabase client is not configured. Please set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in your environment variables.'
    );
  }

  const { data: existing, error: fetchError } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', authUser.id)
    .maybeSingle();

  if (fetchError && fetchError.code !== 'PGRST116') {
    throw new Error(
      `Failed to read profiles table: ${fetchError.message}`
    );
  }

  if (existing) {
    const existingRow = existing as DbProfileRow;
    if (!existingRow.friend_code || !existingRow.friend_code.trim()) {
      const generatedCode = generateFriendCode();
      const { data: patched, error: patchError } = await supabase
        .from('profiles')
        .update({ friend_code: generatedCode })
        .eq('id', authUser.id)
        .select('*')
        .maybeSingle();

      if (patchError) {
        throw new Error(
          `Failed to assign missing friend_code on profile: ${patchError.message}`
        );
      }
      if (patched) {
        return mapDbProfileToUser(patched as DbProfileRow, authUser.email);
      }
      existingRow.friend_code = generatedCode;
    }
    return mapDbProfileToUser(existingRow, authUser.email);
  }

  const isAnon = Boolean(authUser.is_anonymous || !authUser.email);
  const rawBase =
    preferredUsername ||
    (authUser.user_metadata?.username as string | undefined) ||
    (authUser.email
      ? authUser.email.split('@')[0]
      : `guest_${authUser.id.slice(0, 6)}`);

  const cleanBase =
    rawBase
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_]/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 18) || 'lunar_user';

  const omittedColumns = new Set<string>();
  let lastInsertError: string | null = null;

  for (let attempt = 0; attempt < 6; attempt++) {
    const candidateUsername =
      attempt === 0
        ? cleanBase.length >= 3
          ? cleanBase
          : `${cleanBase}_${Math.floor(100 + Math.random() * 900)}`
        : `${cleanBase}_${Math.floor(1000 + Math.random() * 9000)}`.slice(0, 24);

    const displayName =
      candidateUsername
        .split('_')
        .filter(Boolean)
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(' ') || 'Lunar User';

    const fullRow: Record<string, unknown> = {
      id: authUser.id,
      username: candidateUsername,
      friend_code: generateFriendCode(),
      display_name: displayName,
      is_guest: isAnon,
      bio: isAnon
        ? 'Exploring MOON via Guest Session · Private friend-code messaging.'
        : 'Connected on MOON · Direct friend-code messaging.',
      avatar_hue: String(255 + Math.floor(Math.random() * 35)),
    };

    for (const col of omittedColumns) {
      delete fullRow[col];
    }

    const { data: created, error: insertError } = await supabase
      .from('profiles')
      .insert(fullRow)
      .select('*')
      .single();

    if (!insertError && created) {
      return mapDbProfileToUser(created as DbProfileRow, authUser.email);
    }

    const missingCol = extractMissingColumnFromError(insertError?.message);
    if (
      missingCol &&
      missingCol !== 'id' &&
      missingCol !== 'username' &&
      missingCol !== 'friend_code' &&
      !omittedColumns.has(missingCol)
    ) {
      omittedColumns.add(missingCol);
      continue;
    }

    lastInsertError = insertError?.message || 'Unknown profile insert error';
  }

  throw new Error(
    `Could not create profile in public.profiles: ${lastInsertError}`
  );
}

export async function signInAsGuestSupabase(
  customUsername?: string
): Promise<UserProfile> {
  if (!supabase) {
    throw new Error(
      'Supabase client is not initialized. Ensure VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY are configured.'
    );
  }

  const { data, error } = await supabase.auth.signInAnonymously();

  if (error || !data.user) {
    const msg = error?.message || 'Anonymous sign-in failed.';
    if (msg.toLowerCase().includes('anonymous')) {
      throw new Error(
        `Supabase Anonymous Sign-Ins are disabled in your project (${msg}). Enable "Allow anonymous sign-ins" in Supabase Dashboard -> Authentication -> Providers -> Anonymous.`
      );
    }
    throw new Error(msg);
  }

  return fetchOrBootstrapProfile(data.user, customUsername);
}

export async function signUpWithEmailSupabase(params: {
  email: string;
  password: string;
  username: string;
}): Promise<{ profile: UserProfile | null; confirmationRequired: boolean }> {
  if (!supabase) {
    throw new Error(
      'Supabase client is not initialized. Ensure VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY are configured.'
    );
  }

  const cleanUsername = params.username
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, '');

  const { data, error } = await supabase.auth.signUp({
    email: params.email.trim(),
    password: params.password,
  });

  if (error) {
    throw new Error(error.message);
  }

  if (!data.user) {
    throw new Error('Sign-up did not return a user record.');
  }

  if (!data.session) {
    return { profile: null, confirmationRequired: true };
  }

  const profile = await fetchOrBootstrapProfile(data.user, cleanUsername);
  return { profile, confirmationRequired: false };
}

export async function signInWithEmailSupabase(params: {
  email: string;
  password: string;
}): Promise<UserProfile> {
  if (!supabase) {
    throw new Error(
      'Supabase credentials are not configured yet. Please enter VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY via environment variables.'
    );
  }

  const { data, error } = await supabase.auth.signInWithPassword({
    email: params.email.trim(),
    password: params.password,
  });

  if (error || !data.user) {
    throw new Error(error?.message || 'Invalid email or password.');
  }

  return fetchOrBootstrapProfile(data.user);
}

export async function signOutSupabase(): Promise<void> {
  if (!supabase) return;
  const { error } = await supabase.auth.signOut();
  if (error) {
    throw new Error(`Sign out failed: ${error.message}`);
  }
}

export async function updateUserProfileSupabase(
  userId: string,
  updates: {
    username?: string;
    displayName?: string;
    bio?: string;
    friendCode?: string;
    avatarHue?: string | number;
  }
): Promise<UserProfile> {
  if (!supabase) {
    throw new Error('Supabase client is not configured.');
  }

  const payload: Record<string, unknown> = {};
  if (updates.username !== undefined) payload.username = updates.username;
  if (updates.displayName !== undefined)
    payload.display_name = updates.displayName;
  if (updates.bio !== undefined) payload.bio = updates.bio;
  if (updates.friendCode !== undefined)
    payload.friend_code = updates.friendCode;
  if (updates.avatarHue !== undefined)
    payload.avatar_hue = String(updates.avatarHue);

  for (let attempt = 0; attempt < 4; attempt++) {
    const { data, error } = await supabase
      .from('profiles')
      .update(payload)
      .eq('id', userId)
      .select('*')
      .single();

    if (!error && data) {
      const {
        data: { user },
      } = await supabase.auth.getUser();
      return mapDbProfileToUser(data as DbProfileRow, user?.email);
    }

    const missingCol = extractMissingColumnFromError(error?.message);
    if (missingCol && missingCol in payload && Object.keys(payload).length > 1) {
      delete payload[missingCol];
      continue;
    }

    throw new Error(error?.message || 'Failed to update profile in Supabase.');
  }

  throw new Error('Failed to update profile in Supabase.');
}

/**
 * Requirement 1 & 2: Check if two users are already friends in public.friendships using user1 and user2.
 * Reports any database query error instead of silently ignoring it.
 */
async function checkAreUsersAlreadyFriends(
  userA: string,
  userB: string
): Promise<boolean> {
  if (!supabase) {
    throw new Error('Supabase client is not configured.');
  }

  const [u1, u2] = getCanonicalUserPair(userA, userB);

  const { data: friendshipRows, error: fErr } = await supabase
    .from('friendships')
    .select('user1, user2')
    .or(
      `and(user1.eq.${u1},user2.eq.${u2}),and(user1.eq.${u2},user2.eq.${u1})`
    )
    .limit(1);

  if (fErr) {
    throw new Error(
      `Failed to check existing friendship in public.friendships: ${fErr.message}`
    );
  }

  return Boolean(friendshipRows && friendshipRows.length > 0);
}

/**
 * Search for a user by their exact friend_code in public.profiles
 * and inspect existing friendship (user1, user2) or pending request (sender_id, receiver_id) state.
 */
export async function searchUserByFriendCodeSupabase(params: {
  currentUser: UserProfile;
  friendCodeInput: string;
}): Promise<FriendCodeSearchResult> {
  if (!supabase) {
    throw new Error('Supabase client is not configured.');
  }

  const rawTrimmed = params.friendCodeInput.trim();
  if (!rawTrimmed) {
    throw new Error('Please enter a friend code to search.');
  }

  const exactCodeUpper = rawTrimmed.toUpperCase();
  const normalizedCode = normalizeFriendCode(rawTrimmed);

  let { data: targetRow, error: lookupError } = await supabase
    .from('profiles')
    .select('*')
    .ilike('friend_code', exactCodeUpper)
    .maybeSingle();

  if (!lookupError && !targetRow && normalizedCode !== exactCodeUpper) {
    const secondTry = await supabase
      .from('profiles')
      .select('*')
      .ilike('friend_code', normalizedCode)
      .maybeSingle();
    targetRow = secondTry.data;
    lookupError = secondTry.error;
  }

  if (lookupError) {
    throw new Error(`Friend code search failed: ${lookupError.message}`);
  }

  if (!targetRow) {
    throw new Error(
      `No user found with friend_code "${exactCodeUpper}". Verify the exact code or ensure the profiles SELECT RLS policy allows authenticated users to look up profiles.`
    );
  }

  const target = targetRow as DbProfileRow;
  const mappedProfile = {
    id: target.id,
    username: target.username,
    displayName: resolveDisplayName(target),
    friendCode: target.friend_code,
    avatarHue: parseAvatarHue(target.avatar_hue),
    bio: target.bio || 'Connected via MOON friend code.',
  };

  // Prevent adding yourself
  if (
    target.id === params.currentUser.id ||
    target.friend_code.toUpperCase() ===
      params.currentUser.friendCode.toUpperCase()
  ) {
    return {
      profile: mappedProfile,
      relationshipStatus: 'self',
    };
  }

  // Check if already accepted friends in public.friendships (user1, user2)
  const isAlreadyFriend = await checkAreUsersAlreadyFriends(
    params.currentUser.id,
    target.id
  );
  if (isAlreadyFriend) {
    return {
      profile: mappedProfile,
      relationshipStatus: 'friends',
    };
  }

  // Check if a pending request already exists in either direction in public.friend_requests
  const { data: existingReqs, error: reqLookupErr } = await supabase
    .from('friend_requests')
    .select('id, sender_id, receiver_id, status, created_at')
    .eq('status', 'pending')
    .or(
      `and(sender_id.eq.${params.currentUser.id},receiver_id.eq.${target.id}),and(sender_id.eq.${target.id},receiver_id.eq.${params.currentUser.id})`
    );

  if (reqLookupErr) {
    throw new Error(
      `Failed to check existing friend requests: ${reqLookupErr.message}`
    );
  }

  if (existingReqs && existingReqs.length > 0) {
    const pending = existingReqs[0] as DbFriendRequestRow;
    return {
      profile: mappedProfile,
      relationshipStatus:
        pending.sender_id === params.currentUser.id
          ? 'pending_outgoing'
          : 'pending_incoming',
      existingRequestId: pending.id,
    };
  }

  return {
    profile: mappedProfile,
    relationshipStatus: 'none',
  };
}

/**
 * Send a friend request using strictly the confirmed columns of public.friend_requests:
 * (sender_id, receiver_id, status).
 * Prevents self-requests and duplicate requests, and reports all errors explicitly.
 */
export async function sendFriendRequestByCodeSupabase(params: {
  currentUser: UserProfile;
  friendCodeInput: string;
}): Promise<{
  request: FriendRequest;
  targetProfile: { displayName: string; friendCode: string; username: string };
}> {
  if (!supabase) {
    throw new Error('Supabase client is not configured.');
  }

  const searchResult = await searchUserByFriendCodeSupabase({
    currentUser: params.currentUser,
    friendCodeInput: params.friendCodeInput,
  });

  if (searchResult.relationshipStatus === 'self') {
    throw new Error('You cannot send a friend request to your own friend code.');
  }

  if (searchResult.relationshipStatus === 'friends') {
    throw new Error(
      `${searchResult.profile.displayName} (@${searchResult.profile.username}) is already in your Friends list.`
    );
  }

  if (searchResult.relationshipStatus === 'pending_outgoing') {
    throw new Error(
      `You already have a pending outgoing friend request to ${searchResult.profile.displayName} (${searchResult.profile.friendCode}).`
    );
  }

  if (searchResult.relationshipStatus === 'pending_incoming') {
    throw new Error(
      `${searchResult.profile.displayName} (${searchResult.profile.friendCode}) has already sent you a friend request! Open the Requests tab to accept it.`
    );
  }

  const target = searchResult.profile;

  // Check if there is a previous row for (sender_id, receiver_id) to handle unique constraint cleanly
  const { data: priorRow, error: priorErr } = await supabase
    .from('friend_requests')
    .select('id, sender_id, receiver_id, status, created_at')
    .eq('sender_id', params.currentUser.id)
    .eq('receiver_id', target.id)
    .maybeSingle();

  if (priorErr) {
    throw new Error(
      `Failed to check prior friend requests: ${priorErr.message}`
    );
  }

  let savedRow: DbFriendRequestRow | null = null;

  if (priorRow && priorRow.status === 'rejected') {
    const { data: updated, error: reError } = await supabase
      .from('friend_requests')
      .update({ status: 'pending' })
      .eq('id', priorRow.id)
      .select('id, sender_id, receiver_id, status, created_at')
      .single();

    if (reError || !updated) {
      throw new Error(
        reError?.message || 'Could not re-send friend request.'
      );
    }
    savedRow = updated as DbFriendRequestRow;
  } else {
    const { data: inserted, error: insertError } = await supabase
      .from('friend_requests')
      .insert({
        sender_id: params.currentUser.id,
        receiver_id: target.id,
        status: 'pending',
      })
      .select('id, sender_id, receiver_id, status, created_at')
      .single();

    if (insertError || !inserted) {
      throw new Error(
        insertError?.message || 'Could not send friend request.'
      );
    }
    savedRow = inserted as DbFriendRequestRow;
  }

  const request: FriendRequest = {
    id: String(savedRow.id),
    direction: 'outgoing',
    senderId: String(savedRow.sender_id),
    receiverId: String(savedRow.receiver_id),
    fromUser: {
      id: target.id,
      username: target.username,
      displayName: target.displayName,
      friendCode: target.friendCode,
      avatarHue: target.avatarHue,
      bio: target.bio,
    },
    createdAtText: formatRelativeTime(savedRow.created_at),
    status: 'pending',
  };

  return {
    request,
    targetProfile: {
      displayName: target.displayName,
      friendCode: target.friendCode,
      username: target.username,
    },
  };
}

/**
 * Requirement 1 & 8: Load accepted friends from public.friendships using user1 and user2.
 * Reports any query error instead of silently ignoring it.
 */
export async function fetchFriendsFromSupabase(
  currentUserId: string
): Promise<FriendContact[]> {
  if (!supabase) {
    throw new Error('Supabase client is not configured.');
  }

  const { data: friendshipRows, error: fErr } = await supabase
    .from('friendships')
    .select('user1, user2, created_at')
    .or(`user1.eq.${currentUserId},user2.eq.${currentUserId}`);

  if (fErr) {
    throw new Error(
      `Failed to query public.friendships (user1, user2): ${fErr.message}`
    );
  }

  const friendIdSet = new Set<string>();
  for (const row of (friendshipRows || []) as DbFriendshipRow[]) {
    const otherId = row.user1 === currentUserId ? row.user2 : row.user1;
    if (otherId && otherId !== currentUserId) {
      friendIdSet.add(otherId);
    }
  }

  const friendIds = Array.from(friendIdSet);
  if (friendIds.length === 0) {
    return [];
  }

  const { data: profileRows, error: pErr } = await supabase
    .from('profiles')
    .select('*')
    .in('id', friendIds);

  if (pErr) {
    throw new Error(`Failed to query friend profiles: ${pErr.message}`);
  }

  return ((profileRows || []) as DbProfileRow[]).map(mapDbProfileToFriend);
}

/**
 * Load pending incoming & outgoing friend requests from public.friend_requests
 * using exact columns (id, sender_id, receiver_id, status, created_at).
 */
export async function fetchFriendRequestsFromSupabase(
  currentUserId: string
): Promise<FriendRequest[]> {
  if (!supabase) {
    throw new Error('Supabase client is not configured.');
  }

  const { data: reqRows, error: reqErr } = await supabase
    .from('friend_requests')
    .select('id, sender_id, receiver_id, status, created_at')
    .or(`sender_id.eq.${currentUserId},receiver_id.eq.${currentUserId}`)
    .eq('status', 'pending')
    .order('created_at', { ascending: false });

  if (reqErr) {
    throw new Error(
      `Failed to query public.friend_requests: ${reqErr.message}`
    );
  }

  if (!reqRows || reqRows.length === 0) {
    return [];
  }

  const typedRequests = reqRows as DbFriendRequestRow[];
  const counterpartIds = Array.from(
    new Set(
      typedRequests.map((r) =>
        r.sender_id === currentUserId ? r.receiver_id : r.sender_id
      )
    )
  );

  const { data: profiles, error: pErr } = await supabase
    .from('profiles')
    .select('*')
    .in('id', counterpartIds);

  if (pErr) {
    throw new Error(`Failed to load request profiles: ${pErr.message}`);
  }

  const profileMap = new Map<string, DbProfileRow>();
  ((profiles || []) as DbProfileRow[]).forEach((p) => profileMap.set(p.id, p));

  const mapped: FriendRequest[] = [];
  for (const r of typedRequests) {
    const isIncoming = r.receiver_id === currentUserId;
    const otherId = isIncoming ? r.sender_id : r.receiver_id;
    const otherProfile = profileMap.get(otherId);

    if (!otherProfile) {
      throw new Error(
        `Could not load profile for user ${otherId} in friend_requests. Ensure the public.profiles SELECT RLS policy allows authenticated users to view profiles.`
      );
    }

    mapped.push({
      id: r.id,
      direction: isIncoming ? 'incoming' : 'outgoing',
      senderId: r.sender_id,
      receiverId: r.receiver_id,
      fromUser: {
        id: otherProfile.id,
        username: otherProfile.username,
        displayName: resolveDisplayName(otherProfile),
        friendCode: otherProfile.friend_code,
        avatarHue: parseAvatarHue(otherProfile.avatar_hue),
        bio: otherProfile.bio || 'Connected via MOON friend code.',
      },
      createdAtText: formatRelativeTime(r.created_at),
      status: r.status,
    });
  }

  return mapped;
}

/**
 * Requirement 2, 3, 4: Accept or reject/cancel a friend request.
 * - Stores friendship pairs canonically using least() and greatest() in (user1, user2).
 * - Avoids duplicate friendship inserts when the database trigger already created the friendship.
 * - Makes acceptance idempotent and handles unique constraint conflicts (23505) safely while reporting any real error.
 */
export async function respondToFriendRequestSupabase(params: {
  currentUserId: string;
  request: FriendRequest;
  action: 'accept' | 'reject';
}): Promise<void> {
  if (!supabase) {
    throw new Error('Supabase client is not configured.');
  }

  if (params.action === 'reject') {
    if (params.request.direction === 'outgoing') {
      const { error } = await supabase
        .from('friend_requests')
        .delete()
        .eq('id', params.request.id)
        .eq('sender_id', params.currentUserId);
      if (error) {
        throw new Error(`Failed to cancel outgoing request: ${error.message}`);
      }
      return;
    }

    // Receiver rejecting an incoming request
    const { data: rejectedRows, error } = await supabase
      .from('friend_requests')
      .update({ status: 'rejected' })
      .eq('id', params.request.id)
      .eq('receiver_id', params.currentUserId)
      .select('id, status');

    if (error) {
      throw new Error(`Failed to reject friend request: ${error.message}`);
    }
    if (!rejectedRows || rejectedRows.length === 0) {
      throw new Error(
        'Friend request could not be updated to rejected (0 rows affected). Check the UPDATE RLS policy on public.friend_requests.'
      );
    }
    return;
  }

  // Action === 'accept' (Strictly only the receiver can accept)
  if (params.request.receiverId !== params.currentUserId) {
    throw new Error('Only the recipient of a friend request can accept it.');
  }

  // Step 1: Update friend_requests status to 'accepted'
  const { data: updatedRequests, error: updateErr } = await supabase
    .from('friend_requests')
    .update({ status: 'accepted' })
    .eq('id', params.request.id)
    .eq('receiver_id', params.currentUserId)
    .select('id, status');

  if (updateErr) {
    throw new Error(`Failed to accept friend request: ${updateErr.message}`);
  }

  if (!updatedRequests || updatedRequests.length === 0) {
    throw new Error(
      'Accepting friend request updated 0 rows. Ensure public.friend_requests has an UPDATE RLS policy allowing receiver_id = auth.uid().'
    );
  }

  // Step 2: Check if the database trigger already created the canonical (user1, user2) friendship row
  const [canonicalUser1, canonicalUser2] = getCanonicalUserPair(
    params.request.senderId,
    params.request.receiverId
  );

  const { data: existingFriendship, error: checkErr } = await supabase
    .from('friendships')
    .select('user1, user2')
    .or(
      `and(user1.eq.${canonicalUser1},user2.eq.${canonicalUser2}),and(user1.eq.${canonicalUser2},user2.eq.${canonicalUser1})`
    )
    .limit(1);

  if (checkErr) {
    throw new Error(
      `Request marked accepted, but checking public.friendships failed: ${checkErr.message}`
    );
  }

  // If the trigger already created the friendship row, we are done (no duplicate insert)
  if (existingFriendship && existingFriendship.length > 0) {
    return;
  }

  // Step 3: Insert canonical (least, greatest) pair into public.friendships (user1, user2)
  const { error: insertFriendshipErr } = await supabase
    .from('friendships')
    .insert({
      user1: canonicalUser1,
      user2: canonicalUser2,
    });

  if (insertFriendshipErr) {
    // 23505 = unique_violation (e.g., if trigger inserted concurrently between our SELECT and INSERT)
    if (insertFriendshipErr.code === '23505') {
      return;
    }
    throw new Error(
      `Failed to create friendship in public.friendships (user1, user2): ${insertFriendshipErr.message}`
    );
  }
}

/**
 * Requirement 8 & 9: Live Friend System & Messages Schema/RLS Diagnostic Tool
 * Verifies the exact confirmed columns:
 * - public.profiles (id, username, friend_code)
 * - public.friend_requests (sender_id, receiver_id, status, created_at)
 * - public.friendships (user1, user2)
 * - public.messages (sender_id, receiver_id, content, created_at)
 */
export async function runFriendSystemDiagnostics(
  currentUser: UserProfile
): Promise<FriendSystemDiagnosticReport> {
  const checks: DiagnosticCheckItem[] = [];

  if (!supabase) {
    return {
      checkedAt: formatClockTime(),
      allPassed: false,
      checks: [
        {
          id: 'supabase-client',
          title: 'Supabase Client Configuration',
          status: 'fail',
          detail:
            'Supabase client is not initialized. Configure VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY.',
        },
      ],
    };
  }

  // 1. Check current user's profile row & friend_code column
  const { data: myProfile, error: myProfileErr } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', currentUser.id)
    .maybeSingle();

  if (myProfileErr || !myProfile) {
    checks.push({
      id: 'profile-row',
      title: '1. Current User Profile & Unique friend_code (public.profiles)',
      status: 'fail',
      detail: myProfileErr
        ? `Could not read your row from public.profiles: ${myProfileErr.message}`
        : 'Your profile row was not found in public.profiles.',
      sqlFix: `create policy "profiles_select_authenticated" on public.profiles for select to authenticated using (auth.uid() is not null);`,
    });
  } else {
    const cols = Object.keys(myProfile);
    const hasFriendCode = Boolean(myProfile.friend_code);

    checks.push({
      id: 'profile-row',
      title: '1. Current User Profile & Unique friend_code (public.profiles)',
      status: hasFriendCode ? 'pass' : 'fail',
      detail: hasFriendCode
        ? `Verified profile @${myProfile.username} with friend_code "${myProfile.friend_code}". Columns detected: [${cols.join(', ')}].`
        : 'Your profile row is missing a friend_code value.',
    });
  }

  // 2. Check public.profiles SELECT RLS for searching other users by friend_code
  const { data: otherProfiles, error: searchRlsErr } = await supabase
    .from('profiles')
    .select('id, username, friend_code')
    .neq('id', currentUser.id)
    .limit(3);

  if (searchRlsErr) {
    checks.push({
      id: 'profiles-search-rls',
      title: '2. Friend Code Search (public.profiles SELECT RLS)',
      status: 'fail',
      detail: `Searching public.profiles returned an error: ${searchRlsErr.message}`,
      sqlFix: `drop policy if exists "profiles_select_authenticated" on public.profiles;\ncreate policy "profiles_select_authenticated" on public.profiles for select to authenticated using (auth.uid() is not null);`,
    });
  } else {
    const count = otherProfiles?.length || 0;
    checks.push({
      id: 'profiles-search-rls',
      title: '2. Friend Code Search (public.profiles SELECT RLS)',
      status: count > 0 ? 'pass' : 'warn',
      detail:
        count > 0
          ? `Verified! Authenticated users can search other profiles by friend_code (${count} other profile(s) visible: ${otherProfiles
              .map((p) => `@${p.username} [${p.friend_code}]`)
              .join(', ')}).`
          : `Query succeeded (0 other profiles found). Create a second user or verify that public.profiles SELECT RLS uses (auth.uid() is not null) rather than (auth.uid() = id).`,
    });
  }

  // 3. Check public.friend_requests (sender_id, receiver_id, status, created_at)
  const { data: reqSample, error: reqErr } = await supabase
    .from('friend_requests')
    .select('id, sender_id, receiver_id, status, created_at')
    .or(`sender_id.eq.${currentUser.id},receiver_id.eq.${currentUser.id}`)
    .limit(5);

  if (reqErr) {
    checks.push({
      id: 'friend-requests-table',
      title: '3. Friend Requests (sender_id, receiver_id, status, created_at)',
      status: 'fail',
      detail: `Error querying public.friend_requests: ${reqErr.message}`,
    });
  } else {
    checks.push({
      id: 'friend-requests-table',
      title: '3. Friend Requests (sender_id, receiver_id, status, created_at)',
      status: 'pass',
      detail: `Verified exact columns (sender_id, receiver_id, status, created_at) on public.friend_requests (${
        reqSample?.length || 0
      } request row(s) involving you).`,
    });
  }

  // 4. Check public.friendships (user1, user2)
  const { data: friendSample, error: friendErr } = await supabase
    .from('friendships')
    .select('user1, user2, created_at')
    .or(`user1.eq.${currentUser.id},user2.eq.${currentUser.id}`)
    .limit(5);

  if (friendErr) {
    checks.push({
      id: 'friendships-table',
      title: '4. Friendships Table (user1, user2 — canonical least/greatest)',
      status: 'fail',
      detail: `Error querying public.friendships (user1, user2): ${friendErr.message}`,
    });
  } else {
    checks.push({
      id: 'friendships-table',
      title: '4. Friendships Table (user1, user2 — canonical least/greatest)',
      status: 'pass',
      detail: `Verified exact columns (user1, user2) and SELECT RLS policy on public.friendships (${
        friendSample?.length || 0
      } active friendship(s)).`,
    });
  }

  // 5. Check public.messages (sender_id, receiver_id, content, created_at)
  const { data: msgSample, error: msgErr } = await supabase
    .from('messages')
    .select('id, sender_id, receiver_id, content, created_at')
    .or(`sender_id.eq.${currentUser.id},receiver_id.eq.${currentUser.id}`)
    .limit(5);

  if (msgErr) {
    checks.push({
      id: 'messages-table',
      title: '5. Messages Table (sender_id, receiver_id, content, created_at)',
      status: 'fail',
      detail: `Error querying public.messages (sender_id, receiver_id, content, created_at): ${msgErr.message}`,
    });
  } else {
    checks.push({
      id: 'messages-table',
      title: '5. Messages Table (sender_id, receiver_id, content, created_at)',
      status: 'pass',
      detail: `Verified exact columns (sender_id, receiver_id, content, created_at) on public.messages (${
        msgSample?.length || 0
      } message(s) accessible).`,
    });
  }

  const allPassed = checks.every((c) => c.status !== 'fail');
  return {
    checkedAt: formatClockTime(),
    allPassed,
    checks,
  };
}

/**
 * Private 1-to-1 Chat Media Constants & Non-Destructive Storage SQL (Option A)
 * - Uses private bucket `chat-media` (`public = false`)
 * - Reuses `public.are_friends(user_a, user_b)` so only accepted friends can upload/view
 * - Zero changes to `public.messages` table columns
 */
export const CHAT_MEDIA_BUCKET = 'chat-media' as const;
export const MAX_CHAT_IMAGE_BYTES = 15 * 1024 * 1024; // 15 MB
export const MAX_CHAT_VIDEO_BYTES = 50 * 1024 * 1024; // 50 MB
const MOON_MEDIA_ENVELOPE_PREFIX = '__MOON_MEDIA_V1__:';

export const ALLOWED_CHAT_IMAGE_MIMES = [
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/gif',
] as const;

export const ALLOWED_CHAT_VIDEO_MIMES = [
  'video/mp4',
  'video/webm',
  'video/quicktime',
  'video/3gpp',
] as const;

export const PREPARED_CHAT_MEDIA_STORAGE_SQL = `-- MOON Messenger — Private chat-media Storage Bucket & Friend-Only RLS (Zero Table Changes)
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'chat-media',
  'chat-media',
  false,
  52428800,
  array['image/jpeg','image/png','image/webp','image/gif','video/mp4','video/webm','video/quicktime','video/3gpp']
)
on conflict (id) do update
set
  public = false,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "chat_media_insert_friends_only" on storage.objects;
create policy "chat_media_insert_friends_only"
  on storage.objects for insert
  to authenticated
  with check (
    bucket_id = 'chat-media'
    and auth.uid() is not null
    and (storage.foldername(name))[1] = auth.uid()::text
    and (storage.foldername(name))[2] is not null
    and (storage.foldername(name))[2] <> auth.uid()::text
    and (storage.foldername(name))[2] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    and public.are_friends(auth.uid(), ((storage.foldername(name))[2])::uuid)
  );

drop policy if exists "chat_media_select_friends_only" on storage.objects;
create policy "chat_media_select_friends_only"
  on storage.objects for select
  to authenticated
  using (
    bucket_id = 'chat-media'
    and auth.uid() is not null
    and (
      (storage.foldername(name))[1] = auth.uid()::text
      or (storage.foldername(name))[2] = auth.uid()::text
    )
    and (storage.foldername(name))[1] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    and (storage.foldername(name))[2] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    and public.are_friends(
      ((storage.foldername(name))[1])::uuid,
      ((storage.foldername(name))[2])::uuid
    )
  );

drop policy if exists "chat_media_delete_sender_only" on storage.objects;
create policy "chat_media_delete_sender_only"
  on storage.objects for delete
  to authenticated
  using (
    bucket_id = 'chat-media'
    and auth.uid() is not null
    and (storage.foldername(name))[1] = auth.uid()::text
  );`;

export function formatFileSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

const EXTENSION_TO_MIME_MAP: Record<string, string> = {
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  png: 'image/png',
  webp: 'image/webp',
  gif: 'image/gif',
  mp4: 'video/mp4',
  m4v: 'video/mp4',
  webm: 'video/webm',
  mov: 'video/quicktime',
  qt: 'video/quicktime',
  '3gp': 'video/3gpp',
  '3gpp': 'video/3gpp',
};

const MIME_ALIASES_MAP: Record<string, string> = {
  'image/jpg': 'image/jpeg',
  'video/x-m4v': 'video/mp4',
  'video/mp4v-es': 'video/mp4',
  'video/x-matroska': 'video/webm',
  'video/mov': 'video/quicktime',
  'video/x-quicktime': 'video/quicktime',
};

export function validateChatMediaFile(file: File): {
  kind: ChatMediaKind;
  mimeType: string;
} {
  const rawMime = (file.type || '').toLowerCase().trim();
  const ext = (file.name || '').split('.').pop()?.toLowerCase().trim() || '';

  const normalizedMime =
    MIME_ALIASES_MAP[rawMime] ||
    ((ALLOWED_CHAT_IMAGE_MIMES as readonly string[]).includes(rawMime) ||
    (ALLOWED_CHAT_VIDEO_MIMES as readonly string[]).includes(rawMime)
      ? rawMime
      : EXTENSION_TO_MIME_MAP[ext] || rawMime);

  const isAllowedImage = (
    ALLOWED_CHAT_IMAGE_MIMES as readonly string[]
  ).includes(normalizedMime);
  const isAllowedVideo = (
    ALLOWED_CHAT_VIDEO_MIMES as readonly string[]
  ).includes(normalizedMime);

  if (!isAllowedImage && !isAllowedVideo) {
    throw new Error(
      `Unsupported file format (${
        rawMime || file.name
      }). Please select a JPG, PNG, WebP, or GIF photo, or an MP4, WebM, or MOV video.`
    );
  }

  if (file.size <= 0) {
    throw new Error('The selected file is empty (0 bytes).');
  }

  if (isAllowedImage && file.size > MAX_CHAT_IMAGE_BYTES) {
    throw new Error(
      `Photo size (${formatFileSize(
        file.size
      )}) exceeds the 15 MB limit. Please choose a smaller image.`
    );
  }

  if (isAllowedVideo && file.size > MAX_CHAT_VIDEO_BYTES) {
    throw new Error(
      `Video size (${formatFileSize(
        file.size
      )}) exceeds the 50 MB limit. Please choose a shorter or compressed video clip.`
    );
  }

  return {
    kind: isAllowedVideo ? 'video' : 'image',
    mimeType: normalizedMime,
  };
}

interface CompactMediaEnvelopeV1 {
  v: 1;
  k: ChatMediaKind;
  b: 'chat-media';
  p: string;
  m: string;
  n: string;
  s: number;
  c?: string;
}

interface CompactLocationEnvelopeV1 {
  v: 1;
  lat: number;
  lng: number;
  lbl: string;
  addr?: string;
  cap?: string;
  src: LocationShareSource;
  acc?: number;
}

const MOON_LOCATION_ENVELOPE_PREFIX = '__MOON_LOCATION_V1__:';

const UUID_PATH_SEGMENT_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/[a-zA-Z0-9._-]+$/i;

export function encodeMediaMessageContent(media: ChatMediaAttachment): string {
  const safeCaption = media.caption ? media.caption.trim().slice(0, 1200) : '';
  const payload: CompactMediaEnvelopeV1 = {
    v: 1,
    k: media.kind,
    b: CHAT_MEDIA_BUCKET,
    p: media.storagePath,
    m: media.mimeType,
    n: media.fileName.slice(0, 120),
    s: media.fileSize,
    ...(safeCaption ? { c: safeCaption } : {}),
  };
  return `${MOON_MEDIA_ENVELOPE_PREFIX}${JSON.stringify(payload)}`;
}

export function encodeLocationMessageContent(
  location: ChatLocationAttachment
): string {
  const safeLabel =
    (location.label || 'Pinned Location').trim().slice(0, 160) ||
    'Pinned Location';
  const safeAddress = location.address
    ? location.address.trim().slice(0, 320)
    : '';
  const safeCaption = location.caption
    ? location.caption.trim().slice(0, 800)
    : '';

  const payload: CompactLocationEnvelopeV1 = {
    v: 1,
    lat: Number(location.latitude.toFixed(6)),
    lng: Number(location.longitude.toFixed(6)),
    lbl: safeLabel,
    src: location.source,
    ...(safeAddress ? { addr: safeAddress } : {}),
    ...(safeCaption ? { cap: safeCaption } : {}),
    ...(typeof location.accuracyMeters === 'number' &&
    Number.isFinite(location.accuracyMeters) &&
    location.accuracyMeters > 0
      ? { acc: Math.round(location.accuracyMeters) }
      : {}),
  };

  return `${MOON_LOCATION_ENVELOPE_PREFIX}${JSON.stringify(payload)}`;
}

export function parseMessageContent(rawContent: string): {
  text: string;
  media?: ChatMediaAttachment;
  location?: ChatLocationAttachment;
} {
  if (!rawContent) {
    return { text: '' };
  }

  if (rawContent.startsWith(MOON_MEDIA_ENVELOPE_PREFIX)) {
    try {
      const jsonPart = rawContent.slice(MOON_MEDIA_ENVELOPE_PREFIX.length);
      const parsed = JSON.parse(jsonPart) as Partial<CompactMediaEnvelopeV1>;
      if (
        parsed &&
        parsed.v === 1 &&
        (parsed.k === 'image' || parsed.k === 'video') &&
        parsed.b === CHAT_MEDIA_BUCKET &&
        typeof parsed.p === 'string' &&
        UUID_PATH_SEGMENT_REGEX.test(parsed.p)
      ) {
        const caption = typeof parsed.c === 'string' ? parsed.c.trim() : '';
        const media: ChatMediaAttachment = {
          version: 1,
          kind: parsed.k,
          bucket: CHAT_MEDIA_BUCKET,
          storagePath: parsed.p,
          mimeType:
            typeof parsed.m === 'string' && parsed.m
              ? parsed.m
              : parsed.k === 'video'
              ? 'video/mp4'
              : 'image/jpeg',
          fileName:
            typeof parsed.n === 'string' && parsed.n
              ? parsed.n
              : parsed.k === 'video'
              ? 'video.mp4'
              : 'photo.jpg',
          fileSize:
            typeof parsed.s === 'number' && Number.isFinite(parsed.s)
              ? parsed.s
              : 0,
          ...(caption ? { caption } : {}),
        };

        return {
          text: caption || (media.kind === 'video' ? '🎬 Video' : '📷 Photo'),
          media,
        };
      }
    } catch {
      // Fall back to plain text if envelope is malformed
    }
    return { text: rawContent };
  }

  if (rawContent.startsWith(MOON_LOCATION_ENVELOPE_PREFIX)) {
    try {
      const jsonPart = rawContent.slice(MOON_LOCATION_ENVELOPE_PREFIX.length);
      const parsed = JSON.parse(jsonPart) as Partial<CompactLocationEnvelopeV1>;
      if (
        parsed &&
        parsed.v === 1 &&
        typeof parsed.lat === 'number' &&
        Number.isFinite(parsed.lat) &&
        parsed.lat >= -90 &&
        parsed.lat <= 90 &&
        typeof parsed.lng === 'number' &&
        Number.isFinite(parsed.lng) &&
        parsed.lng >= -180 &&
        parsed.lng <= 180
      ) {
        const label =
          typeof parsed.lbl === 'string' && parsed.lbl.trim()
            ? parsed.lbl.trim()
            : `${parsed.lat.toFixed(5)}, ${parsed.lng.toFixed(5)}`;
        const address =
          typeof parsed.addr === 'string' && parsed.addr.trim()
            ? parsed.addr.trim()
            : undefined;
        const caption =
          typeof parsed.cap === 'string' && parsed.cap.trim()
            ? parsed.cap.trim()
            : undefined;
        const source: LocationShareSource =
          parsed.src === 'gps' || parsed.src === 'search' || parsed.src === 'pin'
            ? parsed.src
            : 'pin';
        const accuracyMeters =
          typeof parsed.acc === 'number' &&
          Number.isFinite(parsed.acc) &&
          parsed.acc > 0
            ? parsed.acc
            : undefined;

        const location: ChatLocationAttachment = {
          version: 1,
          latitude: parsed.lat,
          longitude: parsed.lng,
          label,
          source,
          ...(address ? { address } : {}),
          ...(caption ? { caption } : {}),
          ...(accuracyMeters ? { accuracyMeters } : {}),
        };

        return {
          text: caption || `📍 ${label}`,
          location,
        };
      }
    } catch {
      // Fall back to plain text if envelope is malformed
    }
    return { text: rawContent };
  }

  return { text: rawContent };
}

// In-memory cache of short-lived signed URLs for private chat-media objects
const signedUrlCache = new Map<string, { url: string; expiresAtMs: number }>();

/**
 * Generates a short-lived signed URL (1 hour) for a private object in `chat-media`.
 * Never uses public URLs. Enforces `<sender_id>/<receiver_id>/<filename>` path structure.
 */
export async function resolveChatMediaSignedUrl(
  storagePath: string
): Promise<string> {
  if (!supabase) {
    throw new Error('Supabase client is not configured.');
  }

  const cleanPath = storagePath.trim();
  if (!UUID_PATH_SEGMENT_REGEX.test(cleanPath)) {
    throw new Error('Invalid private media storage path.');
  }

  const cached = signedUrlCache.get(cleanPath);
  const now = Date.now();
  if (cached && cached.expiresAtMs > now + 60_000) {
    return cached.url;
  }

  const { data, error } = await supabase.storage
    .from(CHAT_MEDIA_BUCKET)
    .createSignedUrl(cleanPath, 3600);

  if (error || !data?.signedUrl) {
    throw new Error(
      error?.message ||
        'Could not authorize private media URL. Verify you are friends and the private chat-media bucket RLS policies are active.'
    );
  }

  signedUrlCache.set(cleanPath, {
    url: data.signedUrl,
    expiresAtMs: now + 50 * 60 * 1000, // Cache for 50 minutes on a 60-minute signed URL
  });

  return data.signedUrl;
}

function mapDbMessageRowToChatMessage(
  row: DbMessageRow,
  currentUserId: string,
  friendId: string
): ChatMessage {
  const parsed = parseMessageContent(row.content);
  const cachedSigned = parsed.media
    ? signedUrlCache.get(parsed.media.storagePath)?.url
    : undefined;

  return {
    id: row.id,
    threadFriendId: friendId,
    senderId: row.sender_id === currentUserId ? 'me' : row.sender_id,
    text: parsed.text,
    timestampText: formatClockTime(row.created_at),
    createdAtIso: row.created_at,
    deliveryState: 'delivered',
    ...(parsed.media
      ? {
          media: {
            ...parsed.media,
            ...(cachedSigned ? { signedUrl: cachedSigned } : {}),
          },
        }
      : {}),
    ...(parsed.location ? { location: parsed.location } : {}),
  };
}

/**
 * Requirement 5: Fetch private messages using exact columns (sender_id, receiver_id, content, created_at)
 */
export async function fetchMessagesForFriendSupabase(
  currentUserId: string,
  friendId: string
): Promise<ChatMessage[]> {
  if (!supabase) {
    throw new Error('Supabase client is not configured.');
  }

  const { data, error } = await supabase
    .from('messages')
    .select('id, sender_id, receiver_id, content, created_at')
    .or(
      `and(sender_id.eq.${currentUserId},receiver_id.eq.${friendId}),and(sender_id.eq.${friendId},receiver_id.eq.${currentUserId})`
    )
    .order('created_at', { ascending: true });

  if (error) {
    throw new Error(
      `Failed to load messages (sender_id, receiver_id, content): ${error.message}`
    );
  }

  return ((data || []) as DbMessageRow[]).map((row) =>
    mapDbMessageRowToChatMessage(row, currentUserId, friendId)
  );
}

/**
 * Requirement 5: Send a private message to a friend using exact columns:
 * (sender_id, receiver_id, content)
 */
export async function sendMessageToFriendSupabase(params: {
  currentUserId: string;
  friendId: string;
  text: string;
}): Promise<ChatMessage> {
  if (!supabase) {
    throw new Error('Supabase client is not configured.');
  }

  const { data, error } = await supabase
    .from('messages')
    .insert({
      sender_id: params.currentUserId,
      receiver_id: params.friendId,
      content: params.text.trim(),
    })
    .select('id, sender_id, receiver_id, content, created_at')
    .single();

  if (error || !data) {
    throw new Error(
      error?.message?.toLowerCase().includes('row-level security')
        ? `Blocked by Supabase Row Level Security (${error.message}): Ensure you and this recipient are in public.friendships (user1, user2).`
        : error?.message || 'Failed to send message.'
    );
  }

  const saved = data as DbMessageRow;
  return mapDbMessageRowToChatMessage(
    saved,
    params.currentUserId,
    params.friendId
  );
}

/**
 * Upload a private photo or video to the `chat-media` bucket and send it to an accepted friend
 * using Option A (Zero `public.messages` Schema Changes).
 */
export async function sendMediaMessageToFriendSupabase(params: {
  currentUserId: string;
  friendId: string;
  file: File;
  caption?: string;
  onProgress?: (percent: number, stageLabel: string) => void;
}): Promise<ChatMessage> {
  if (!supabase) {
    throw new Error('Supabase client is not configured.');
  }

  params.onProgress?.(0, 'Starting private media upload (0%)...');
  const { kind, mimeType } = validateChatMediaFile(params.file);

  if (params.currentUserId === params.friendId) {
    throw new Error('Cannot send media to yourself.');
  }

  params.onProgress?.(12, 'Verifying accepted friendship & RLS...');
  const areFriends = await checkAreUsersAlreadyFriends(
    params.currentUserId,
    params.friendId
  );
  if (!areFriends) {
    throw new Error(
      'Private media sharing is restricted exclusively to accepted friends in public.friendships.'
    );
  }

  // Build safe canonical path `<sender_id>/<receiver_id>/<timestamp>_<random>.<ext>`
  const extFromName = params.file.name.split('.').pop()?.toLowerCase() || '';
  const safeExt =
    /^[a-z0-9]{2,5}$/.test(extFromName)
      ? extFromName
      : kind === 'video'
      ? mimeType === 'video/webm'
        ? 'webm'
        : mimeType === 'video/quicktime'
        ? 'mov'
        : 'mp4'
      : 'jpg';
  const randomToken = Math.random().toString(36).slice(2, 9);
  const storagePath = `${params.currentUserId}/${params.friendId}/${Date.now()}_${randomToken}.${safeExt}`;

  const totalSizeText = formatFileSize(params.file.size);
  let simulatedPercent = 20;
  params.onProgress?.(
    simulatedPercent,
    `Uploading ${kind === 'video' ? 'video' : 'photo'} (${totalSizeText}) to private chat-media...`
  );

  // Smooth progress ticker during active upload transfer (20% -> 84%)
  const progressInterval = setInterval(() => {
    simulatedPercent = Math.min(84, simulatedPercent + (kind === 'video' ? 4 : 7));
    params.onProgress?.(
      simulatedPercent,
      `Uploading ${kind === 'video' ? 'video' : 'photo'} (${totalSizeText}) to private chat-media...`
    );
  }, 180);

  let uploadError: { message?: string } | null = null;
  try {
    const res = await supabase.storage
      .from(CHAT_MEDIA_BUCKET)
      .upload(storagePath, params.file, {
        contentType: mimeType,
        cacheControl: '3600',
        upsert: false,
      });
    uploadError = res.error;
  } finally {
    clearInterval(progressInterval);
  }

  if (uploadError) {
    const rawMsg = uploadError.message || 'Storage upload failed.';
    if (
      rawMsg.toLowerCase().includes('bucket not found') ||
      rawMsg.toLowerCase().includes('not found')
    ) {
      throw new Error(
        `Private storage bucket "chat-media" is not created yet in Supabase (${rawMsg}). Run the Private Chat Media Storage SQL in your Supabase Dashboard -> SQL Editor.`
      );
    }
    if (rawMsg.toLowerCase().includes('row-level security')) {
      throw new Error(
        `Storage upload blocked by Row Level Security (${rawMsg}). Ensure the "chat_media_insert_friends_only" policy is installed on storage.objects and you are accepted friends.`
      );
    }
    throw new Error(`Media upload failed: ${rawMsg}`);
  }

  params.onProgress?.(88, 'Generating private signed media link...');
  let signedUrl: string | undefined;
  try {
    signedUrl = await resolveChatMediaSignedUrl(storagePath);
  } catch {
    // Signed URL can still be resolved on render if needed
  }

  const trimmedCaption = params.caption?.trim().slice(0, 1200) || undefined;
  const mediaAttachment: ChatMediaAttachment = {
    version: 1,
    kind,
    bucket: CHAT_MEDIA_BUCKET,
    storagePath,
    mimeType,
    fileName: params.file.name || `${kind}.${safeExt}`,
    fileSize: params.file.size,
    ...(trimmedCaption ? { caption: trimmedCaption } : {}),
    ...(signedUrl ? { signedUrl } : {}),
  };

  const encodedContent = encodeMediaMessageContent(mediaAttachment);

  params.onProgress?.(95, 'Saving private message to public.messages...');
  const { data, error: insertError } = await supabase
    .from('messages')
    .insert({
      sender_id: params.currentUserId,
      receiver_id: params.friendId,
      content: encodedContent,
    })
    .select('id, sender_id, receiver_id, content, created_at')
    .single();

  if (insertError || !data) {
    // Clean up uploaded object if message insert failed
    await supabase.storage
      .from(CHAT_MEDIA_BUCKET)
      .remove([storagePath])
      .catch(() => {});

    throw new Error(
      insertError?.message?.toLowerCase().includes('row-level security')
        ? `Blocked by Supabase Row Level Security (${insertError.message}): Ensure you and this recipient are in public.friendships (user1, user2).`
        : insertError?.message || 'Failed to save media message.'
    );
  }

  params.onProgress?.(100, 'Upload complete (100%)!');
  const saved = data as DbMessageRow;
  const mapped = mapDbMessageRowToChatMessage(
    saved,
    params.currentUserId,
    params.friendId
  );

  if (signedUrl && mapped.media) {
    mapped.media.signedUrl = signedUrl;
  }

  return mapped;
}

/**
 * Send a private 1-to-1 Location pin or GPS coordinates to an accepted friend
 * using Option A (Zero `public.messages` Schema Changes).
 */
export async function sendLocationMessageToFriendSupabase(params: {
  currentUserId: string;
  friendId: string;
  location: Omit<ChatLocationAttachment, 'version'>;
}): Promise<ChatMessage> {
  if (!supabase) {
    throw new Error('Supabase client is not configured.');
  }

  const { latitude, longitude } = params.location;
  if (
    !Number.isFinite(latitude) ||
    latitude < -90 ||
    latitude > 90 ||
    !Number.isFinite(longitude) ||
    longitude < -180 ||
    longitude > 180
  ) {
    throw new Error('Invalid GPS or map coordinates selected.');
  }

  if (params.currentUserId === params.friendId) {
    throw new Error('Cannot share location with yourself.');
  }

  const areFriends = await checkAreUsersAlreadyFriends(
    params.currentUserId,
    params.friendId
  );
  if (!areFriends) {
    throw new Error(
      'Private location sharing is restricted exclusively to accepted friends in public.friendships.'
    );
  }

  const locationPayload: ChatLocationAttachment = {
    version: 1,
    latitude: Number(latitude.toFixed(6)),
    longitude: Number(longitude.toFixed(6)),
    label:
      (params.location.label || 'Shared Location').trim().slice(0, 160) ||
      'Shared Location',
    source: params.location.source,
    ...(params.location.address?.trim()
      ? { address: params.location.address.trim().slice(0, 320) }
      : {}),
    ...(params.location.caption?.trim()
      ? { caption: params.location.caption.trim().slice(0, 800) }
      : {}),
    ...(typeof params.location.accuracyMeters === 'number' &&
    Number.isFinite(params.location.accuracyMeters) &&
    params.location.accuracyMeters > 0
      ? { accuracyMeters: Math.round(params.location.accuracyMeters) }
      : {}),
  };

  const encodedContent = encodeLocationMessageContent(locationPayload);

  const { data, error } = await supabase
    .from('messages')
    .insert({
      sender_id: params.currentUserId,
      receiver_id: params.friendId,
      content: encodedContent,
    })
    .select('id, sender_id, receiver_id, content, created_at')
    .single();

  if (error || !data) {
    throw new Error(
      error?.message?.toLowerCase().includes('row-level security')
        ? `Blocked by Supabase Row Level Security (${error.message}): Ensure you and this recipient are in public.friendships (user1, user2).`
        : error?.message || 'Failed to send location message.'
    );
  }

  const saved = data as DbMessageRow;
  return mapDbMessageRowToChatMessage(
    saved,
    params.currentUserId,
    params.friendId
  );
}

/**
 * Subscribe to real-time private messages (sender_id, receiver_id, content, created_at),
 * friend requests, and friendships (user1, user2)
 */
export function subscribeToMoonRealtime(
  currentUserId: string,
  callbacks: {
    onIncomingOrSyncedMessage: (
      msg: ChatMessage,
      rawSenderId: string,
      rawReceiverId: string
    ) => void;
    onFriendRequestsChanged: () => void;
    onFriendshipsChanged: () => void;
  }
): () => void {
  const client = supabase;
  if (!client) {
    return () => {};
  }

  const channel: RealtimeChannel = client
    .channel(`moon-realtime-${currentUserId}`)
    .on(
      'postgres_changes',
      {
        event: 'INSERT',
        schema: 'public',
        table: 'messages',
      },
      (payload) => {
        const row = payload.new as DbMessageRow;
        if (
          row.sender_id !== currentUserId &&
          row.receiver_id !== currentUserId
        ) {
          return;
        }
        const friendId =
          row.sender_id === currentUserId ? row.receiver_id : row.sender_id;

        const mapped = mapDbMessageRowToChatMessage(
          row,
          currentUserId,
          friendId
        );
        callbacks.onIncomingOrSyncedMessage(
          mapped,
          row.sender_id,
          row.receiver_id
        );
      }
    )
    .on(
      'postgres_changes',
      {
        event: '*',
        schema: 'public',
        table: 'friend_requests',
      },
      () => {
        callbacks.onFriendRequestsChanged();
      }
    )
    .on(
      'postgres_changes',
      {
        event: '*',
        schema: 'public',
        table: 'friendships',
      },
      () => {
        callbacks.onFriendshipsChanged();
      }
    )
    .subscribe();

  return () => {
    client.removeChannel(channel);
  };
}
