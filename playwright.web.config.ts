import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/web-pwa",
  timeout: 60_000,
  expect: { timeout: 8_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  reporter: [
    ["list"],
    ["html", { outputFolder: "playwright-report/web-pwa", open: "never" }],
  ],
  outputDir: "test-results/web-pwa",
  use: {
    baseURL: "http://127.0.0.1:4181",
    channel: "chrome",
    trace: "off",
    video: "off",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: "npm run web:local",
    url: "http://127.0.0.1:4181",
    reuseExistingServer: true,
    timeout: 60_000,
  },
  projects: [
    {
      name: "web-pwa",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 390, height: 844 },
      },
    },
  ],
});
