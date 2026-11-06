import type { JsonWebKey } from "../src/index.js";

// RFC 7515 Appendix A.1, split so that no complete token literal is stored.
export const A1_HEADER = ["eyJ0eXAiOiJKV1Qi", "LA0KICJhbGciOiJIUzI1NiJ9"].join("");
export const A1_PAYLOAD = [
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAs",
  "DQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
].join("");
export const A1_SIGNATURE = ["dBjftJeZ4CVP-mB9", "2K27uhbUJU1p1r_wW1gFWFOEjXk"].join("");
export const A1_KEY = [
  "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-",
  "EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
].join("");
export const A1_TOKEN = [A1_HEADER, A1_PAYLOAD, A1_SIGNATURE].join(".");

export const enc = new TextEncoder();

interface LooseSubtle {
  generateKey(algorithm: unknown, extractable: boolean, usages: string[]): Promise<unknown>;
  exportKey(format: string, key: unknown): Promise<unknown>;
  importKey(
    format: string,
    data: unknown,
    algorithm: unknown,
    extractable: boolean,
    usages: string[],
  ): Promise<unknown>;
  sign(algorithm: unknown, key: unknown, data: unknown): Promise<ArrayBuffer>;
}

export const subtle = globalThis.crypto.subtle as unknown as LooseSubtle;

export interface KeyPair {
  readonly publicKey: unknown;
  readonly privateKey: unknown;
}

export type Signer = (input: Uint8Array) => Promise<Uint8Array>;

export function b64u(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function b64uText(text: string): string {
  return b64u(enc.encode(text));
}

export function b64uJson(value: unknown): string {
  return b64uText(JSON.stringify(value));
}

export async function signToken(header: object, payload: object, signer: Signer): Promise<string> {
  const input = `${b64uJson(header)}.${b64uJson(payload)}`;
  const signature = await signer(enc.encode(input));
  return `${input}.${b64u(signature)}`;
}

export function fakeToken(header: object, payload: object = {}, signatureLength = 0): string {
  const signature = b64u(new Uint8Array(signatureLength).fill(1));
  return `${b64uJson(header)}.${b64uJson(payload)}.${signature}`;
}

export async function hmacSigner(secret: Uint8Array | string, hash = "SHA-256"): Promise<Signer> {
  const bytes = typeof secret === "string" ? enc.encode(secret) : secret;
  const key = await subtle.importKey("raw", bytes, { name: "HMAC", hash }, false, ["sign"]);
  return async (input) => new Uint8Array(await subtle.sign("HMAC", key, input));
}

export function keySigner(privateKey: unknown, params: unknown): Signer {
  return async (input) => new Uint8Array(await subtle.sign(params, privateKey, input));
}

const pairs = new Map<string, Promise<KeyPair>>();

export function rsaKeyPair(
  name: "RSASSA-PKCS1-v1_5" | "RSA-PSS",
  hash: string,
  bits: number,
): Promise<KeyPair> {
  const id = `${name}/${hash}/${bits}`;
  let pair = pairs.get(id);
  if (pair === undefined) {
    pair = subtle.generateKey(
      {
        name,
        hash,
        modulusLength: bits,
        publicExponent: new Uint8Array([1, 0, 1]),
      },
      true,
      ["sign", "verify"],
    ) as Promise<KeyPair>;
    pairs.set(id, pair);
  }
  return pair;
}

export function ecKeyPair(curve: string): Promise<KeyPair> {
  const id = `EC/${curve}`;
  let pair = pairs.get(id);
  if (pair === undefined) {
    pair = subtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, [
      "sign",
      "verify",
    ]) as Promise<KeyPair>;
    pairs.set(id, pair);
  }
  return pair;
}

export async function exportJwk(key: unknown): Promise<JsonWebKey> {
  return (await subtle.exportKey("jwk", key)) as JsonWebKey;
}

export async function spkiBytes(pair: KeyPair): Promise<Uint8Array> {
  return new Uint8Array((await subtle.exportKey("spki", pair.publicKey)) as ArrayBuffer);
}

export function pemFromDer(der: Uint8Array): string {
  let binary = "";
  for (const byte of der) {
    binary += String.fromCharCode(byte);
  }
  const lines = btoa(binary).match(/.{1,64}/g) ?? [];
  return ["-----BEGIN PUBLIC KEY-----", ...lines, "-----END PUBLIC KEY-----"].join("\n");
}

export async function publicPem(pair: KeyPair): Promise<string> {
  return pemFromDer(await spkiBytes(pair));
}
