import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { resolve, relative, extname } from "node:path";
import { createHash } from "node:crypto";
const root = resolve(import.meta.dirname, "../..");
const output = resolve(root, "apps/web/dist-web");
const violations = [];
function files(path) {
  return readdirSync(path).flatMap((name) => {
    const full = resolve(path, name);
    return statSync(full).isDirectory() ? files(full) : [full];
  });
}
const bundle = files(output);
// Source scan deliberately never opens .env, credential stores or key files.
// Record only paths/rules, never the matching value or source line.
const sourceFiles = ['apps/web/src', 'apps/worker/src', 'apps/api/src', 'packages/core/src', 'scripts']
  .flatMap(folder => files(resolve(root, folder)))
  .filter(path => ['.ts', '.tsx', '.js', '.mjs', '.ps1'].includes(extname(path)));
const sourceRules = {
  privateKeyMaterial: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\r\n]/,
  recognizedToken: /(?:sk-proj-|ghp_|AKIA)[A-Za-z0-9_-]{20,}/,
  literalProviderSecret: /(?:VIRUSTOTAL_API_KEY|CLOUDFLARE_API_TOKEN)\s*[:=]\s*["'][A-Za-z0-9_-]{24,}["']/,
};
for (const path of sourceFiles) {
  const content = readFileSync(path, 'utf8');
  for (const [rule, pattern] of Object.entries(sourceRules))
    if (pattern.test(content)) violations.push({ file: relative(root,path).replaceAll('\\','/'), rule });
}
for (const path of bundle) {
  const name = relative(output, path).replaceAll("\\", "/");
  if (/(?:^|\/)\.env|\.(?:jks|keystore|p12|pem|db|sqlite|map)$/i.test(name))
    violations.push({ file: name, rule: "forbidden-artifact" });
  if (
    ![".js", ".html", ".css", ".json", ".webmanifest"].includes(extname(path))
  )
    continue;
  const content = readFileSync(path, "utf8");
  const rules = {
    secretMarkers:
      /VIRUSTOTAL_API_KEY|CLOUDFLARE_API_TOKEN|RATE_LIMIT_SECRET|x-apikey|dash\.cloudflare\.com|-----BEGIN (?:RSA |EC )?PRIVATE KEY/,
    knownTokenFormats: /(?:sk-proj-|ghp_|AKIA)[A-Za-z0-9_-]{16,}/,
    legacyNative:
      /edy-family-device-review|FamilyDevicePlugin|CAPACITOR_PLATFORM/,
    testFixtures:
      /Synthetic test-only|Test-only evidence|UNMOCKED:|EDY_WEB_LIVE/,
    insecureApi:
      /https?:\/\/(?:127\.0\.0\.1|localhost|192\.168\.\d+\.\d+)(?::\d+)?/,
  };
  for (const [rule, pattern] of Object.entries(rules))
    if (pattern.test(content)) violations.push({ file: name, rule });
}
const html = readFileSync(resolve(output, "index.html"), "utf8");
const headers = readFileSync(resolve(output, "_headers"), "utf8");
for (const value of [
  "script-src 'self'",
  "style-src 'self'",
  "object-src 'none'",
  "connect-src 'self'",
])
  if (!html.includes(value))
    violations.push({ file: "index.html", rule: `missing-${value}` });
for (const value of [
  "frame-ancestors",
  "Permissions-Policy",
  "Referrer-Policy",
  "X-Content-Type-Options",
])
  if (!headers.includes(value))
    violations.push({ file: "_headers", rule: `missing-${value}` });
const manifest = JSON.parse(
  readFileSync(resolve(output, "manifest.webmanifest"), "utf8"),
);
if (
  manifest.display !== "standalone" ||
  !manifest.icons.some((icon) => icon.purpose === "maskable")
)
  violations.push({
    file: "manifest.webmanifest",
    rule: "manifest-incomplete",
  });
const apk = readFileSync(
  resolve(root, "dist/android/EDY-ScanURL-Family-release.apk"),
);
const apkHash = createHash("sha256").update(apk).digest("hex");
if (
  apkHash !== "689ccdd7d821b241d0440e588f76390008e746336d8b55db4e4428f9593ed535"
)
  violations.push({ file: "APK", rule: "unexpected-change" });
const report = {
  status: violations.length ? "FAIL" : "PASS",
  scope:
    "Source code, production build and preserved APK; pattern scan is not proof against all secrets. Credential files were not opened.",
  files: bundle.length,
  sourceFiles: sourceFiles.length,
  apkSha256: apkHash,
  apkPreserved: violations.every((item) => item.file !== "APK"),
  violations,
};
writeFileSync(
  resolve(root, "docs/web-pwa/security-check.json"),
  JSON.stringify(report, null, 2) + "\n",
);
console.log(JSON.stringify(report, null, 2));
if (violations.length) process.exitCode = 1;
