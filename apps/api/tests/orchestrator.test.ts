import { describe, expect, it } from "vitest";
import type { ScanProvider } from "../src/providers/contracts.js";
import { ScanOrchestrator } from "../src/services/scan-orchestrator.js";

describe("ScanOrchestrator", () => {
  it("does not prune queued or running jobs that can still perform egress", () => {
    const orchestrator = new ScanOrchestrator({ enabled: () => [] });
    const internals = orchestrator as unknown as { jobs: Map<string, unknown>; prune(now: number): void };
    internals.jobs.set("queued", { scanId: "queued", status: "QUEUED", progress: { completed: 0, total: 1, current: "QUEUED" }, createdAt: 0 });
    internals.jobs.set("running", { scanId: "running", status: "RUNNING", progress: { completed: 0, total: 1, current: "RUNNING" }, createdAt: 0 });
    internals.jobs.set("done", { scanId: "done", status: "SUCCEEDED", progress: { completed: 1, total: 1, current: "COMPLETE" }, createdAt: 0 });
    internals.prune(16 * 60_000);
    expect([...internals.jobs.keys()]).toEqual(["queued", "running"]);
  });
  it("turns provider exceptions into limited coverage instead of a stuck job", async () => {
    const failing: ScanProvider = {
      id: "test-provider",
      version: "1",
      category: "HTTP",
      execute: () => Promise.reject(new Error("unexpected adapter failure")),
    };
    const orchestrator = new ScanOrchestrator({ enabled: () => [failing] });
    const created = orchestrator.create("https://synthetic.example/path?secret=value");
    let result = orchestrator.get(created.scanId);
    for (let attempt = 0; attempt < 20 && ["QUEUED", "RUNNING"].includes(result?.status ?? ""); attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 5));
      result = orchestrator.get(created.scanId);
    }
    expect(result?.status).toBe("SUCCEEDED");
    expect(result?.coverageStatus).toBe("LIMITED");
    expect(result?.report?.verdict).toBe("INSUFFICIENT_DATA");
    expect(result?.report?.normalizedUrl).toBe("https://synthetic.example/");
  });
});
