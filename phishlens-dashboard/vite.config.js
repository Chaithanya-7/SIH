import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  // Relative asset paths, because the desktop app loads this build from disk.
  //
  // Vite's default base is '/', which emits <script src="/assets/index-xxx.js">.
  // Served over HTTP that is correct. Opened as a file:// URL - which is how the
  // packaged desktop app loads the console - a leading slash resolves to the
  // root of the filesystem, so every asset 404s. The HTML itself still loads, so
  // the window title is right and the body background colour applies, and the
  // result is a correctly-titled black window with nothing in it.
  //
  // That shipped. It survived earlier checks because those confirmed the backend
  // answered and that loadFile() resolved - neither of which says anything about
  // whether the page rendered.
  base: './',
  plugins: [react()],
  server: {
    port: 3005,
    strictPort: true
  }
})
