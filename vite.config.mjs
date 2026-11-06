import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'node:path';

/**
 * The production CSP forbids inline scripts. Vite's React Refresh preamble is
 * inline, so the policy is relaxed only while the dev server is running.
 */
function devCsp() {
  return {
    name: 'reap-dev-csp',
    apply: 'serve',
    transformIndexHtml(html) {
      return html.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'");
    },
  };
}

export default defineConfig({
  root: path.resolve(import.meta.dirname, 'src/ui'),
  base: './',
  plugins: [react(), tailwindcss(), devCsp()],
  server: { port: 5173, strictPort: true, host: '127.0.0.1' },
  build: {
    outDir: path.resolve(import.meta.dirname, 'dist/ui'),
    emptyOutDir: true,
  },
});
