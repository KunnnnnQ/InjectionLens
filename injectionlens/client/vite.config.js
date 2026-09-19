import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 7100,
    strictPort: true,
    proxy: {
      '/api': 'http://localhost:7101',
      '/fixtures': 'http://localhost:7101',
    },
  },
})
