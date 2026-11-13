import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig, loadEnv} from 'vite';

export default defineConfig(({mode}) => {
  const env = loadEnv(mode, process.cwd(), '');
  // Only expose the Project base URL and public Anon/Publishable key to the client.
  // NEVER expose SUPABASE_SERVICE_ROLE_KEY or any secret key.
  const rawUrl = (
    process.env.VITE_SUPABASE_URL ||
    env.VITE_SUPABASE_URL ||
    process.env.SUPABASE_URL ||
    env.SUPABASE_URL ||
    ''
  )
    .trim()
    .replace(/^['"]+|['"]+$/g, '');

  let supabaseUrl = rawUrl;
  try {
    if (rawUrl) {
      const withProtocol =
        rawUrl.startsWith('http://') || rawUrl.startsWith('https://')
          ? rawUrl
          : `https://${rawUrl}`;
      const parsed = new URL(withProtocol);
      // Strictly keep only protocol + host (strips /auth/v1, /rest/v1, trailing slashes, etc.)
      supabaseUrl = parsed.origin;
    }
  } catch {
    supabaseUrl = rawUrl
      .replace(/\/(auth|rest|realtime|storage|functions)\/v1.*$/i, '')
      .replace(/\/+$/, '');
  }

  const supabaseAnonKey = (
    process.env.VITE_SUPABASE_ANON_KEY ||
    env.VITE_SUPABASE_ANON_KEY ||
    process.env.VITE_SUPABASE_PUBLIC_ANON_KEY ||
    env.VITE_SUPABASE_PUBLIC_ANON_KEY ||
    process.env.SUPABASE_ANON_KEY ||
    env.SUPABASE_ANON_KEY ||
    ''
  )
    .trim()
    .replace(/^['"]+|['"]+$/g, '');

  return {
    plugins: [react(), tailwindcss()],
    define: {
      'import.meta.env.VITE_SUPABASE_URL': JSON.stringify(supabaseUrl),
      'import.meta.env.VITE_SUPABASE_ANON_KEY': JSON.stringify(supabaseAnonKey),
    },
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
