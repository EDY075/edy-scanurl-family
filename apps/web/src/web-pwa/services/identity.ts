export interface BrowserIdentity {
  privateKey: CryptoKey;
  publicKeySpki: string;
  deviceId: string;
}
export const base64 = (value: ArrayBuffer | Uint8Array<ArrayBuffer>) =>
  btoa(String.fromCharCode(...new Uint8Array(value)));
export const hashBytes = async (value: BufferSource) =>
  [...new Uint8Array(await crypto.subtle.digest("SHA-256", value))]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
export const hashText = (value: string) =>
  hashBytes(new TextEncoder().encode(value));
let identityPromise: Promise<BrowserIdentity> | undefined;

export function getBrowserIdentity(): Promise<BrowserIdentity> {
  identityPromise ??= loadIdentity().catch(() => {
    identityPromise = undefined;
    throw new Error("storage");
  });
  return identityPromise;
}

async function loadIdentity(): Promise<BrowserIdentity> {
  if (typeof crypto.subtle === "undefined" || typeof indexedDB === "undefined")
    throw new Error("storage");
  // Generate before opening a read/write transaction: no async gap inside it.
  const candidate = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  );
  const pair = await new Promise<CryptoKeyPair>((resolve, reject) => {
    let settled = false;
    const fail = () => {
      settled = true;
      reject(new Error("storage"));
    };
    const timeout = setTimeout(fail, 5000);
    const request = indexedDB.open("edy-family-web-device-v1", 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore("identity");
    };
    request.onblocked = () => {
      clearTimeout(timeout);
      fail();
    };
    request.onerror = () => {
      clearTimeout(timeout);
      fail();
    };
    request.onsuccess = () => {
      const db = request.result;
      if (settled) {
        db.close();
        return;
      }
      db.onversionchange = () => {
        db.close();
      };
      const transaction = db.transaction("identity", "readwrite");
      const store = transaction.objectStore("identity");
      const read = store.get("p256") as IDBRequest<CryptoKeyPair | undefined>;
      let result: CryptoKeyPair;
      read.onsuccess = () => {
        result = read.result ?? candidate;
        if (!read.result) store.put(result, "p256");
      };
      transaction.oncomplete = () => {
        clearTimeout(timeout);
        db.close();
        settled = true;
        resolve(result);
      };
      transaction.onabort = transaction.onerror = () => {
        clearTimeout(timeout);
        db.close();
        fail();
      };
    };
  });
  if (
    pair.privateKey.extractable ||
    pair.privateKey.type !== "private" ||
    pair.privateKey.algorithm.name !== "ECDSA"
  )
    throw new Error("storage");
  const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
  return {
    privateKey: pair.privateKey,
    publicKeySpki: base64(spki),
    deviceId: await hashBytes(spki),
  };
}

/** WebCrypto P1363 → Android/Worker DER wire format; never exports the key. */
export function signatureToDer(raw: ArrayBuffer): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(raw);
  if (bytes.length !== 64) throw new Error("authentication");
  const integer = (half: Uint8Array) => {
    let start = 0;
    while (start < half.length - 1 && half[start] === 0) start += 1;
    const value = [...half.slice(start)];
    if (value[0] >= 128) value.unshift(0);
    return [2, value.length, ...value];
  };
  const sequence = [
    ...integer(bytes.slice(0, 32)),
    ...integer(bytes.slice(32)),
  ];
  return new Uint8Array([48, sequence.length, ...sequence]);
}
