import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// `npm run dev` proxies the API to a local `lattice serve`. The server only accepts loopback
// Host headers, which changeOrigin provides.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://127.0.0.1:7443', changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    // one module script and one stylesheet: nothing inline, so the server's CSP can forbid it
    assetsInlineLimit: 0,
  },
});
