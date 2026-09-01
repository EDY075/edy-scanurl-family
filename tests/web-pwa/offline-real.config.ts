import { defineConfig } from "@playwright/test";
import { resolve } from "node:path";

// Opt-in local proof. Never starts a deploy or reads a user's Chrome profile.
// A unique directory prevents Playwright cleanup from erasing older evidence.
const runId = process.env.EDY_OFFLINE_RUN;
if (!runId || !/^\d{8}-\d{6}$/.test(runId))
  throw new Error("Set EDY_OFFLINE_RUN to a fresh YYYYMMDD-HHmmss run identifier.");

export default defineConfig({
  testDir: ".",
  testMatch: "offline-real.spec.ts",
  timeout: 120_000,
  expect: { timeout: 12_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  outputDir: resolve("test-results/offline-real", runId),
  reporter: [["list"]],
  use: {
    browserName: "chromium",
    baseURL: "http://127.0.0.1:4182",
    serviceWorkers: "allow",
    headless: true,
    trace: "off",
    video: "off",
    screenshot: "only-on-failure",
    locale: "pt-BR",
    timezoneId: "America/Sao_Paulo",
  },
  // The approved preview and real local Worker must already be running.
  // No remote fallback, route mocks, webServer rebuild or production access.
  projects: [
    { name: "mobile-390", use: { viewport: { width: 390, height: 844 } } },
    { name: "desktop-1366", use: { viewport: { width: 1366, height: 900 } } },
  ],
});
