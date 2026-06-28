import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(__dirname, './src') } },
  build: {
    // echarts (geo + scatter + bar + pie) is ~520 kB on its own and isolated in
    // its own cacheable chunk below; raise the limit so the warning reflects
    // real regressions, not this expected vendor size.
    chunkSizeWarningLimit: 600,
    // Split the heavy charting lib and React runtime into their own chunks so
    // the app code chunk stays small and vendor code caches independently.
    rolldownOptions: {
      output: {
        advancedChunks: {
          groups: [
            { name: 'echarts', test: /node_modules\/(echarts|zrender)\// },
            { name: 'react', test: /node_modules\/(react|react-dom|scheduler)\// },
          ],
        },
      },
    },
  },
  server: {
    port: 5180,
    strictPort: true,
    proxy: { '/api': 'http://127.0.0.1:8080' }, // dev: hit the local Go server
  },
});
