import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The SPA never talks to the resource servers or the IdP directly - only to the BFF.
// In dev, Vite proxies the BFF endpoints to the gateway. changeOrigin:false keeps the
// original Host (127.0.0.1:5173) so the BFF derives the correct browser-facing redirect URI.
const bff = 'http://127.0.0.1:8080';
const proxy = Object.fromEntries(
  ['/api', '/oauth2', '/login', '/logout'].map((path) => [
    path,
    { target: bff, changeOrigin: false },
  ]),
);

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy,
  },
});
