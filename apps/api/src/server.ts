import { loadLocalEnvironment } from "./config/load-local-env.js";
import { createApp } from "./app.js";
import { effectiveLocalHost } from "./providers/virus-total.js";

loadLocalEnvironment();
const app = createApp();
const port = Number.parseInt(process.env.PORT ?? "8787", 10);
const host = effectiveLocalHost();

try {
  await app.listen({ host, port });
} catch (error) {
  app.log.error(error);
  process.exitCode = 1;
}
