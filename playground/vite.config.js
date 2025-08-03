import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Plugin to serve WASM files with correct MIME type
const wasmPlugin = () => ({
  name: 'wasm',
  configureServer(server) {
    server.middlewares.use((req, res, next) => {
      if (req.url?.endsWith('.wasm')) {
        res.setHeader('Content-Type', 'application/wasm')
      }
      next()
    })
  }
})

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), wasmPlugin()],
  server: {
    headers: {
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Cross-Origin-Opener-Policy': 'same-origin',
    },
    fs: {
      allow: ['..']
    }
  },
  assetsInclude: ['**/*.wasm'],
  define: {
    global: 'globalThis',
  }
})
