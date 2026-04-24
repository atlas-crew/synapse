import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5181,
    strictPort: true,
    proxy: {
      '/health': {
        target: 'http://localhost:6191',
        changeOrigin: true,
      },
      '/_sensor': {
        target: 'http://localhost:6191',
        changeOrigin: true,
      },
      '/live': {
        target: 'http://localhost:6191',
        changeOrigin: true,
      },
      '/restart': {
        target: 'http://localhost:6191',
        changeOrigin: true,
      },
      '/reload': {
        target: 'http://localhost:6191',
        changeOrigin: true,
      },
    },
  },
  preview: {
    port: 5181,
    strictPort: true,
  },
  build: {
    outDir: resolve(__dirname, '../synapse-pingora/assets/live'),
    emptyOutDir: true,
    sourcemap: false,
    cssCodeSplit: false,
    modulePreload: false,
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
        entryFileNames: 'assets/app.js',
        chunkFileNames: 'assets/[name].js',
        assetFileNames: (assetInfo) => {
          if (assetInfo.name?.endsWith('.css')) return 'assets/app.css';
          return 'assets/[name][extname]';
        },
      },
    },
  },
  base: '/live/',
});
