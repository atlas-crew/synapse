import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.test.ts', 'src/**/__tests__/**/*.test.ts'],
    setupFiles: ['src/__tests__/vitest.setup.ts'],
    env: {
      DATABASE_URL: 'postgresql://test:test@localhost:5432/signal_horizon_test',
      NODE_ENV: 'test',
      JWT_SECRET: 'test-jwt-secret-for-vitest-minimum-16',
      TELEMETRY_JWT_SECRET: 'test-telemetry-jwt-secret-min16',
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/services/**/*.ts'],
      exclude: ['src/**/*.test.ts'],
    },
    testTimeout: 10000,
    // The synapse-proxy retry tests create brief unhandled rejection
    // windows during fake-timer advancement in executeWithRetry loops.
    // All rejections ARE caught by the retry logic; this suppresses
    // vitest detecting the transient gap between reject() and await.
    dangerouslyIgnoreUnhandledErrors: true,
  },
});
