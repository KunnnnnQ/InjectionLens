import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 7100,
    strictPort: true,
    proxy: {
      // Literal loopback address, not "localhost": on Windows the name can
      // resolve to ::1 while the API listens on 127.0.0.1.
      '/api': 'http://127.0.0.1:7101',
      '/fixtures': 'http://127.0.0.1:7101',
    },
  },
})
