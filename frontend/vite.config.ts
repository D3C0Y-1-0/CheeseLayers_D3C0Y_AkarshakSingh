import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // The dashboard talks to the FastAPI backend (Member 2) through this path.
  server: { proxy: { '/api': 'http://localhost:8000', '/health': 'http://localhost:8000' } },
})
