import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/family",
  timeout: 90_000,
  expect: { timeout: 8_000 },
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  reporter: [["list"], ["html", { outputFolder: "playwright-report", open: "never" }]],
  outputDir: "test-results/family-e2e",
  use: {
    baseURL: "http://127.0.0.1:4180",
    channel: "chrome",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
  },
  webServer: [
    ...(process.env.FAMILY_WORKER_REVIEW === 'true' ? [] : [{
      command: "powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/family/start-review-api.ps1",
      url: "http://127.0.0.1:8788/health",
      reuseExistingServer: true,
      timeout: 30_000,
    }]),
    {
      command: "powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/family/start-review-web.ps1",
      url: "http://127.0.0.1:4180",
      reuseExistingServer: true,
      timeout: 30_000,
    },
  ],
  projects: [
    // The test itself visits the viewport matrix; only one real external scan per run.
    { name: "family-browser", use: { ...devices["Desktop Chrome"], viewport: { width: 390, height: 844 } } },
  ],
});
