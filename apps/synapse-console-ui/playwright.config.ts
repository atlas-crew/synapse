import { defineConfig } from '@playwright/test';
import { fileURLToPath } from 'node:url';

const projectDir = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  testDir: './tests',
  timeout: 30_000,
  use: {
    baseURL: 'http://127.0.0.1:4179/live/',
    headless: true,
  },
  webServer: {
    command:
      'pnpm build && python3 -m http.server 4179 --bind 127.0.0.1 -d ../synapse-pingora/assets',
    port: 4179,
    reuseExistingServer: false,
    cwd: projectDir,
  },
});
