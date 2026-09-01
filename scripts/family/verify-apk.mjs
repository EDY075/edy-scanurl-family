import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve, relative } from 'node:path';
import { inflateRawSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '../..');
const apkPath = resolve(root, process.argv[2] || 'dist/android/EDY-ScanURL-Family-release-preactivation.apk');
const expectedOrigin = process.argv[3] || '';
if (expectedOrigin && (new URL(expectedOrigin).origin !== expectedOrigin || !expectedOrigin.startsWith('https://'))) throw new Error('PUBLIC_HTTPS_ORIGIN_REQUIRED');
if (!expectedOrigin && !apkPath.endsWith('-preactivation.apk')) throw new Error('RELEASE_ORIGIN_REQUIRED');
const apk = readFileSync(apkPath);
if (apk.length > 50 * 1024 * 1024) throw new Error('APK_SIZE_LIMIT');
let end = apk.length - 22;
while (end >= Math.max(0, apk.length - 65557) && apk.readUInt32LE(end) !== 0x06054b50) end--;
if (end < 0) throw new Error('ZIP_DIRECTORY_NOT_FOUND');
const entries = apk.readUInt16LE(end + 10);
let central = apk.readUInt32LE(end + 16);
const violations = [];
let hasFamilyUi = false;
let hasNative = false;
let hasPublicOrigin = false;
for (let i = 0; i < entries; i++) {
  if (apk.readUInt32LE(central) !== 0x02014b50) throw new Error('ZIP_DIRECTORY_INVALID');
  const method = apk.readUInt16LE(central + 10);
  const length = apk.readUInt32LE(central + 20);
  const expected = apk.readUInt32LE(central + 24);
  const nameLength = apk.readUInt16LE(central + 28);
  const extraLength = apk.readUInt16LE(central + 30);
  const commentLength = apk.readUInt16LE(central + 32);
  const local = apk.readUInt32LE(central + 42);
  const name = apk.subarray(central + 46, central + 46 + nameLength).toString('utf8');
  central += 46 + nameLength + extraLength + commentLength;
  if (expected > 20 * 1024 * 1024) throw new Error('ZIP_ENTRY_LIMIT');
  const start = local + 30 + apk.readUInt16LE(local + 26) + apk.readUInt16LE(local + 28);
  const compressed = apk.subarray(start, start + length);
  const data = method === 0 ? compressed : method === 8 ? inflateRawSync(compressed, { maxOutputLength: 20 * 1024 * 1024 }) : Buffer.alloc(0);
  if (data.length !== expected) throw new Error('ZIP_ENTRY_LENGTH');
  if (/(?:^|\/)\.env(?:\.|$)|\.(?:p12|jks|keystore|sqlite|db)$/i.test(name)) violations.push({ entry: name, kind: 'forbidden_file' });
  const text = data.toString('utf8');
  if (/VIRUSTOTAL_API_KEY|CLOUDFLARE_API_TOKEN|CLOUDFLARE_ACCOUNT_ID|dash\.cloudflare\.com|x-apikey|BEGIN (?:RSA |EC )?PRIVATE KEY|desktop-ildmiet|tail652716|Motor de análise|edy-family-device-review/.test(text)) violations.push({ entry: name, kind: 'forbidden_content_marker' });
  if (name.startsWith('assets/public/assets/') && name.endsWith('.js') && text.includes('Verificar outro site')) hasFamilyUi = true;
  if (name.endsWith('.dex') && text.includes('FamilyDevicePlugin')) hasNative = true;
  if (name.endsWith('.dex') && expectedOrigin && text.includes(expectedOrigin)) hasPublicOrigin = true;
}
const aapt = resolve(root, '.toolchains/android-sdk/build-tools/36.0.0/aapt2.exe');
const manifest = execFileSync(aapt, ['dump', 'xmltree', apkPath, '--file', 'AndroidManifest.xml'], { encoding: 'utf8', windowsHide: true });
if (!manifest.includes('com.edy.scanurl.family') || !manifest.includes('android.intent.action.SEND') || !manifest.includes('text/plain')) violations.push({ kind: 'package_or_share_target_missing' });
for (const key of ['debuggable', 'usesCleartextTraffic', 'allowBackup']) {
  const line = manifest.split('\n').find((entry) => entry.includes(`android:${key}`));
  if (line && /(?:true|0xffffffff|= -1)/i.test(line)) violations.push({ kind: `${key}_enabled` });
}
if (!hasNative || !hasFamilyUi) violations.push({ kind: 'family_components_missing' });
if (expectedOrigin && !hasPublicOrigin) violations.push({ kind: 'public_origin_missing_from_native_build' });
const report = { status: violations.length ? 'FAIL' : 'PASS', edition: 'Family', stage: expectedOrigin ? 'RELEASE' : 'RELEASE_PREACTIVATION', apk: relative(root, apkPath).replaceAll('\\', '/'), apiOrigin: expectedOrigin || null, publicOriginConfigured: hasPublicOrigin, bytes: apk.length, sha256: createHash('sha256').update(apk).digest('hex'), entries, nativeBridge: hasNative, familyUi: hasFamilyUi, noSecretMarkers: violations.length === 0, violations };
mkdirSync(resolve(root, 'docs/qa'), { recursive: true });
writeFileSync(resolve(root, expectedOrigin ? 'docs/qa/apk-release-verification.json' : 'docs/qa/apk-verification.json'), `${JSON.stringify(report, null, 2)}\n`);
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (violations.length) process.exitCode = 1;
