import { isAbsolute } from "node:path";
import { FamilyError, FamilyStore } from "./store.js";

// Administrative CLI only. No approval or revocation route exists in the HTTP app.
const [command, value] = process.argv.slice(2);
const path = process.env.FAMILY_DB_PATH;
if (!path || !isAbsolute(path)) throw new Error("FAMILY_DB_PATH_REQUIRED");
const store = new FamilyStore(path, Date.now, { admin: true });
try {
  if (command === "list") process.stdout.write(`${JSON.stringify(store.list())}\n`);
  else if (command === "enroll" && value) process.stdout.write(`${JSON.stringify(store.enroll(value))}\n`);
  else if ((command === "approve" || command === "revoke") && value && /^[a-f0-9]{64}$/.test(value)) {
    store[command](value); process.stdout.write("OK\n");
  } else throw new FamilyError("USAGE_LIST_ENROLL_APPROVE_REVOKE", 400);
} catch (error) {
  process.stderr.write(`${error instanceof FamilyError ? error.code : "FAMILY_ADMIN_FAILED"}\n`); process.exitCode = 1;
} finally { store.close(); }
