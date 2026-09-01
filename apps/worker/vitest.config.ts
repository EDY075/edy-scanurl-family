import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        bindings: {
          EDY_EVIDENCE_LIVE: process.env.EDY_EVIDENCE_LIVE === 'true' ? 'true' : 'false',
          EDY_CORS_LIVE: process.env.EDY_CORS_LIVE === 'true' ? 'true' : 'false',
          EDY_SEMANTIC_LIVE: process.env.EDY_SEMANTIC_LIVE === 'true' ? 'true' : 'false',
          EDY_COVERAGE_LIVE: process.env.EDY_COVERAGE_LIVE === 'true' ? 'true' : 'false',
          EDY_COVERAGE_PHASE: process.env.EDY_COVERAGE_PHASE === 'after' ? 'after' : 'before',
          SERVICE_ENABLED: 'true',
          VIRUSTOTAL_ENABLED: 'false',
          ALLOW_BROWSER_REVIEW: 'true',
          RATE_LIMIT_SECRET: 'local-test-rate-limit-secret-with-32-bytes',
        },
      },
    }),
  ],
});
