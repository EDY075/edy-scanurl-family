import { expect, test, type Page, type Response } from "@playwright/test";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { ScanReport } from "../../apps/web/src/types";

const origin = "http://127.0.0.1:4182";
const target = "https://google.com/";
const offlineCopy = "O EDY ScanURL Family pode abrir sem internet, mas uma conexão é necessária para verificar novos sites.";

interface ScanPayload {
  scanId: string;
  status: string;
  report: ScanReport;
}

function isReportResponse(response: Response) {
  const url = new URL(response.url());
  return url.origin === origin && response.request().method() === "GET" &&
    /^\/family\/v1\/scans\/[a-f0-9-]+$/.test(url.pathname);
}

async function cacheInventory(page: Page) {
  // Inspect only this isolated test origin's public shell cache, not user stores.
  return page.evaluate(async () => {
    const entries = [];
    for (const key of await caches.keys()) {
      const cache = await caches.open(key);
      for (const request of await cache.keys()) {
        const response = await cache.match(request);
        const url = new URL(request.url);
        const sensitiveHeaders = ["authorization", "cookie", "set-cookie", "x-family-device", "x-family-challenge", "x-family-signature"];
        entries.push({
          path: url.pathname,
          sameOrigin: url.origin === location.origin,
          method: request.method,
          sensitiveHeaderPresent: sensitiveHeaders.some(name => request.headers.has(name) || response?.headers.has(name)),
        });
      }
    }
    return entries.sort((a, b) => a.path.localeCompare(b.path));
  });
}

async function confirmSafeCache(page: Page) {
  const entries = await cacheInventory(page);
  expect(entries.length).toBeGreaterThan(0);
  expect(entries.some(entry => entry.path === "/index.html")).toBe(true);
  for (const entry of entries) {
    expect(entry.sameOrigin).toBe(true);
    expect(entry.method).toBe("GET");
    expect(entry.sensitiveHeaderPresent).toBe(false);
    expect(/^\/(?:api|family|health)(?:\/|$)/.test(entry.path)).toBe(false);
    expect(/^\/(?:index\.html|manifest\.webmanifest|assets\/[a-zA-Z0-9_.-]+\.(?:js|css)|(?:favicon|apple-touch-icon|pwa)-concept04[a-zA-Z0-9_.-]*\.(?:svg|png))$/.test(entry.path)).toBe(true);
  }
  return entries;
}

async function realScan(page: Page, action: () => Promise<void>) {
  const startedAt = Date.now();
  const queued = page.waitForResponse(response =>
    response.url() === `${origin}/family/v1/scans` && response.request().method() === "POST",
  );
  const delivered = page.waitForResponse(isReportResponse, { timeout: 50_000 });
  await action();
  const post = await queued;
  expect(post.status()).toBe(202);
  expect(post.fromServiceWorker()).toBe(false);
  expect(post.headers()["cache-control"]).toContain("no-store");
  const job = await post.json() as { scanId: string; status: string };
  expect(job.status).toBe("QUEUED");
  const get = await delivered;
  expect(get.status()).toBe(200);
  expect(get.fromServiceWorker()).toBe(false);
  expect(get.headers()["cache-control"]).toContain("no-store");
  const payload = await get.json() as ScanPayload;
  expect(payload.status).toBe("SUCCEEDED");
  // Keep identifiers/challenges/signatures out of receipts and assertion output.
  expect(payload.scanId === job.scanId && payload.report.id === job.scanId).toBe(true);
  expect(payload.report.mode).toBe("real");
  expect(payload.report.domain).toBe("google.com");
  expect(Date.parse(payload.report.scannedAt)).toBeGreaterThanOrEqual(startedAt - 1000);
  expect(payload.report.sources.length).toBeGreaterThan(0);
  await expect(page.getByRole("heading", { name: "google.com", exact: true })).toBeVisible();
  return payload;
}

test("real offline shell → blocked scan → online retry without cached analysis", async ({ page, context, browser }, testInfo) => {
  test.skip(!process.env.EDY_OFFLINE_RUN, "Requires the explicit isolated offline config.");
  const runId = process.env.EDY_OFFLINE_RUN ?? "not-run";
  const directory = resolve("docs/web-pwa/screenshots/offline-real", runId, testInfo.project.name);
  await mkdir(directory, { recursive: true });
  const network = await context.newCDPSession(page);
  const setNetworkOffline = async (offline: boolean) => {
    await context.setOffline(offline);
    // Chromium151 + Playwright1.62 can lose navigator's emulated network state
    // on a new document, while transport stays blocked (upstream #42174).
    // Use Chromium's native network-state command as well, never JS overrides.
    // The uncached fetch assertion below independently proves transport denial.
    await network.send("Network.overrideNetworkState", {
      offline, latency: 0, downloadThroughput: -1, uploadThroughput: -1,
    });
  };
  let phase = "online-before";
  const scanPosts: string[] = [];
  let offlineFamilyRequests = 0;
  let contextNetworkRestored = false;
  const receipt: Record<string, unknown> = {
    at: new Date().toISOString(), project: testInfo.project.name,
    browser: browser.version(), origin, target,
    mechanism: "browserContext.setOffline(true) remains enabled through reload; native CDP Network.overrideNetworkState reapplied for Chromium151 new document; uncached fetch before reinforcement verifies transport denial; restored in finally; no routes, JS navigator patches or API mocks",
    runtime: "Existing local preview -> loopback gateway8790 -> real workerd -> real public providers; VirusTotal not configured locally",
  };
  context.on("request", request => {
    const url = new URL(request.url());
    if (url.origin !== origin) return;
    if (phase === "offline" && url.pathname.startsWith("/family/")) offlineFamilyRequests += 1;
    if (url.pathname === "/family/v1/scans" && request.method() === "POST") scanPosts.push(phase);
  });
  const screenshot = (name: string) => page.screenshot({ path: resolve(directory, `${name}.png`), fullPage: true });

  try {
    await test.step("Warm the actual shell and complete one genuine analysis", async () => {
      await page.goto("/");
      await expect(page.getByText("Serviço online", { exact: true })).toBeVisible();
      await page.evaluate(() => navigator.serviceWorker.ready.then(() => true));
      await page.reload();
      await expect.poll(() => page.evaluate(() => navigator.serviceWorker.controller?.state)).toBe("activated");
      const registration = await page.evaluate(async () => {
        const sw = await navigator.serviceWorker.ready;
        return { scope: sw.scope, active: sw.active?.state, scriptURL: sw.active?.scriptURL, controlled: !!navigator.serviceWorker.controller };
      });
      expect(registration).toEqual({ scope: `${origin}/`, active: "activated", scriptURL: `${origin}/sw.js`, controlled: true });
      receipt.serviceWorker = registration;
      await screenshot("01-online");
      await page.getByLabel("Guardar um resumo das próximas verificações").check();
      await page.getByLabel("Endereço da loja").fill(target);
    });
    const before = await realScan(page, () => page.getByRole("button", { name: "Verificar site", exact: true }).click());
    const cachedBefore = await confirmSafeCache(page);
    const historyBefore = await page.locator(".history-list").textContent();
    await page.getByRole("button", { name: "Verificar outro site", exact: true }).click();
    await page.getByLabel("Endereço da loja").fill(target);

    await test.step("Disconnect the Chromium context and reload through its service worker", async () => {
      phase = "offline";
      await setNetworkOffline(true);
      await expect.poll(() => page.evaluate(() => navigator.onLine)).toBe(false);
      const reload = await page.reload();
      expect(reload?.fromServiceWorker()).toBe(true);
      receipt.navigatorReportedOnlineBeforeNativeReinforcement = await page.evaluate(() => navigator.onLine);
      // Prove transport denial BEFORE reinforcing the new renderer's state.
      // This rejects a cosmetic offline flag with a still-connected network.
      const probe = await page.evaluate(async () => {
        try { await fetch("/health?offline-proof=1", { cache: "no-store" }); return "unexpected-network-response"; }
        catch { return "network-unavailable"; }
      });
      expect(probe).toBe("network-unavailable");
      // Reapply Chromium's native emulation to the new document, without ever
      // reconnecting the context or overriding navigator via JavaScript.
      await setNetworkOffline(true);
      await expect.poll(() => page.evaluate(() => navigator.onLine)).toBe(false);
      await expect(page.getByText("Você está offline", { exact: true })).toBeVisible();
      await expect(page.getByText(offlineCopy, { exact: false })).toBeVisible();
      receipt.afterOfflineReload = await page.evaluate(() => ({ online: navigator.onLine, notice: document.querySelector('.offline-notice')?.textContent ?? null, service: document.querySelector('.service-status')?.textContent, script: document.querySelector('script[type="module"]')?.getAttribute('src') }));
      await expect(page.locator(".results")).toHaveCount(0);
      expect(await page.locator(".history-list").textContent()).toBe(historyBefore);
      receipt.offline = { shell: "PASS", navigatorOnline: false, navigationFromServiceWorker: true, uncachedHealthRequestBlocked: true };
      await screenshot("02-offline-shell");
    });

    await test.step("Refuse google.com offline without sending an analysis or reusing an old result", async () => {
      await page.getByLabel("Endereço da loja").fill(target);
      await page.getByRole("button", { name: "Verificar site", exact: true }).click();
      await expect(page.getByRole("alert")).toContainText("Você está sem conexão");
      await expect(page.getByRole("alert")).toContainText("Conecte-se à internet para verificar um site.");
      await expect(page.locator(".results")).toHaveCount(0);
      expect(await page.locator(".history-list").textContent()).toBe(historyBefore);
      expect(offlineFamilyRequests).toBe(0);
      expect(scanPosts).toEqual(["online-before"]);
      expect(await confirmSafeCache(page)).toEqual(cachedBefore);
      receipt.offlineScan = { status: "PASS", familyRequests: offlineFamilyRequests, newScanPosts: 0, staleResultShownAsNew: false, historyUnchanged: true };
      await screenshot("03-offline-scan-block");
    });

    await test.step("Restore actual connectivity and use the existing retry", async () => {
      phase = "online-recovery";
      await setNetworkOffline(false);
      contextNetworkRestored = true;
      await expect.poll(() => page.evaluate(() => navigator.onLine)).toBe(true);
      await expect(page.getByText("Você está offline", { exact: true })).toHaveCount(0);
      await expect(page.getByText("Serviço online", { exact: true })).toBeVisible();
      await screenshot("04-online-recovered");
    });
    const recovered = await realScan(page, () => page.getByRole("button", { name: "Tentar novamente", exact: true }).click());
    expect(recovered.scanId !== before.scanId).toBe(true);
    expect(Date.parse(recovered.report.scannedAt)).toBeGreaterThanOrEqual(Date.parse(before.report.scannedAt));
    expect(scanPosts).toEqual(["online-before", "online-recovery"]);
    const cachedAfter = await confirmSafeCache(page);
    expect(cachedAfter).toEqual(cachedBefore);
    await expect.poll(() => page.evaluate(() => navigator.serviceWorker.controller?.state)).toBe("activated");
    await screenshot("05-real-result-after-recovery");
    receipt.recovery = { status: "PASS", newScanIdentifier: true, postStatus: 202, reportStatus: 200, reportMode: recovered.report.mode, reportDomain: recovered.report.domain, scannedAt: recovered.report.scannedAt, responseFromServiceWorker: false, apiCacheControl: "no-store", reinstallRequired: false };
    receipt.cacheAfterRealScans = cachedAfter;
    receipt.scanPostPhases = scanPosts;
    receipt.status = "PASS";
  } finally {
    // Restore even when an assertion, provider or screenshot fails.
    await setNetworkOffline(false);
    await network.detach();
    contextNetworkRestored = true;
    receipt.contextNetworkRestored = contextNetworkRestored;
    receipt.windowsNetworkChanged = false;
    receipt.status ??= "FAIL";
    await writeFile(resolve(directory, "receipt.json"), JSON.stringify(receipt, null, 2) + "\n", "utf8");
  }
});
