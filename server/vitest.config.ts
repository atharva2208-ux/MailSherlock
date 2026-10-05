import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    env: {
      NODE_ENV: 'test',
      LOG_LEVEL: 'silent',
      DATABASE_PATH: ':memory:',
      ML_SERVICE_URL: 'http://127.0.0.1:1',
    },
  },
});
