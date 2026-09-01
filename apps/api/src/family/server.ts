import { isAbsolute } from "node:path";
import { createFamilyApp, validateFamilyAudience } from "./app.js";
import { FamilyStore } from "./store.js";

// Deliberately no dotenv loader: personal credentials must never bleed into Family.
const path = process.env.FAMILY_DB_PATH;
const production = process.env.NODE_ENV === "production";
const configuredHost = process.env.FAMILY_HOST?.trim();
const host = configuredHost === "" ? "127.0.0.1" : configuredHost ?? "127.0.0.1";
const portValue = process.env.PORT ?? "8788";
if (!/^\d{1,5}$/.test(portValue) || Number(portValue) < 1 || Number(portValue) > 65_535) throw new Error("FAMILY_PORT_INVALID");
const port = Number(portValue);
if (!path || !isAbsolute(path) || process.env.FAMILY_SINGLE_REPLICA !== "true") throw new Error("FAMILY_PERSISTENT_DB_AND_SINGLE_REPLICA_REQUIRED");
if (host !== "127.0.0.1" && !(production && process.env.FAMILY_HOSTED_ACCEPTED === "true" && host === "0.0.0.0")) throw new Error("FAMILY_HOSTED_ACCEPTANCE_REQUIRED");
const audience = validateFamilyAudience(process.env.FAMILY_AUDIENCE ?? "http://127.0.0.1:8788", production);
const store = new FamilyStore(path);
const app = createFamilyApp({ store, audience });
try { await app.listen({ host, port }); }
catch { store.close(); process.stderr.write("FAMILY_START_FAILED\n"); process.exitCode = 1; }
for (const signal of ["SIGTERM", "SIGINT"] as const) process.once(signal, () => {
  void app.close().then(() => { store.close(); }).catch(() => { process.exitCode = 1; });
});
