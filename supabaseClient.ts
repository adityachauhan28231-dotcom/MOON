import { createClient, SupabaseClient } from '@supabase/supabase-js';

const rawEnvUrl = String(import.meta.env.VITE_SUPABASE_URL || '').trim();
const rawEnvAnonKey = String(
  import.meta.env.VITE_SUPABASE_ANON_KEY ||
    import.meta.env.VITE_SUPABASE_PUBLIC_ANON_KEY ||
    ''
).trim();

/**
 * Normalizes a Supabase URL so that `createClient()` receives ONLY the base
 * project origin (`https://<project-ref>.supabase.co`).
 *
 * - Strips surrounding quotes and whitespace
 * - Converts Supabase dashboard URLs (`https://supabase.com/dashboard/project/<ref>...`)
 *   into `https://<ref>.supabase.co`
 * - Removes any appended `/auth/v1`, `/rest/v1`, `/realtime/v1`, `/storage/v1`,
 *   `/functions/v1`, or other path segments and trailing slashes
 */
export function normalizeSupabaseBaseUrl(input: string): string {
  const cleaned = input.trim().replace(/^['"]+|['"]+$/g, '').trim();
  if (
    !cleaned ||
    cleaned === 'MY_SUPABASE_URL' ||
    cleaned === 'YOUR_SUPABASE_URL'
  ) {
    return '';
  }

  // Handle case where user pasted a Supabase Dashboard URL
  const dashboardMatch = cleaned.match(
    /supabase\.com\/(?:dashboard\/)?project\/([a-z0-9-]+)/i
  );
  if (dashboardMatch?.[1]) {
    return `https://${dashboardMatch[1].toLowerCase()}.supabase.co`;
  }

  // Strip any accidental API subpaths before URL parsing
  const withoutApiPaths = cleaned
    .replace(/\/(auth|rest|realtime|storage|functions)\/v1(\/.*)?$/i, '')
    .replace(/\/+$/, '');

  const withProtocol =
    withoutApiPaths.startsWith('http://') ||
    withoutApiPaths.startsWith('https://')
      ? withoutApiPaths
      : `https://${withoutApiPaths}`;

  try {
    const parsed = new URL(withProtocol);
    // `parsed.origin` contains strictly `https://<host>` with no trailing slash or path
    return parsed.origin;
  } catch {
    return '';
  }
}

export function normalizeSupabaseAnonKey(input: string): string {
  const cleaned = input.trim().replace(/^['"]+|['"]+$/g, '').trim();
  if (
    !cleaned ||
    cleaned === 'MY_SUPABASE_ANON_KEY' ||
    cleaned === 'YOUR_SUPABASE_ANON_KEY'
  ) {
    return '';
  }
  return cleaned;
}

const supabaseBaseUrl = normalizeSupabaseBaseUrl(rawEnvUrl);
const supabaseAnonKey = normalizeSupabaseAnonKey(rawEnvAnonKey);

/**
 * Checks whether valid non-placeholder Supabase environment variables have been supplied.
 * Never invents credentials and never uses service_role keys.
 */
export function isSupabaseEnvConfigured(): boolean {
  return Boolean(supabaseBaseUrl && supabaseAnonKey);
}

export function getConfiguredSupabaseUrl(): string | null {
  return supabaseBaseUrl || null;
}

/**
 * Singleton Supabase client initialized strictly with the base project URL origin
 * (`https://<project-ref>.supabase.co`) and public anon/publishable key.
 */
export const supabase: SupabaseClient | null =
  supabaseBaseUrl && supabaseAnonKey
    ? createClient(supabaseBaseUrl, supabaseAnonKey, {
        auth: {
          persistSession: true,
          autoRefreshToken: true,
          detectSessionInUrl: false,
        },
      })
    : null;
