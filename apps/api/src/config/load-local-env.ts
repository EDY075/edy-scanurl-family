import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { loadEnvFile } from "node:process";
import { fileURLToPath } from "node:url";

export function loadLocalEnvironment(): void {
  const starts = [process.cwd(), dirname(fileURLToPath(import.meta.url))];
  const visited = new Set<string>();
  for (const start of starts) {
    let current = resolve(start);
    for (let depth = 0; depth < 8; depth += 1) {
      if (visited.has(current)) break;
      visited.add(current);
      const packagePath = join(current, "package.json");
      const envPath = join(current, ".env");
      if (existsSync(packagePath) && existsSync(envPath) && isProjectRoot(packagePath)) {
        loadEnvFile(envPath);
        return;
      }
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
}

function isProjectRoot(packagePath: string): boolean {
  try {
    const parsed = JSON.parse(readFileSync(packagePath, "utf8")) as { name?: unknown };
    return parsed.name === "edy-scanurl";
  } catch {
    return false;
  }
}
