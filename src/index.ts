/**
 * Public entry point of @trysac/jwt-inspector.
 *
 * Local JWT inspection and verification with WebCrypto (RFC 7519, RFC 7515,
 * RFC 8725). No network access and no Node.js-only imports.
 */

const MAX_TOKEN_CHARS = 16_384;
const MAX_KEY_CHARS = 16_384;
const MAX_JSON_DEPTH = 32;
const MAX_TOLERANCE_SEC = 300;
const MAX_ALGORITHMS = 16;
const RSA_MIN_BITS = 2048;
const RSA_MAX_BITS = 8192;
const RSA_OID = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth"];
const BASE64URL = /^[A-Za-z0-9_-]*$/;
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
const PEM_SPKI = /^-----BEGIN PUBLIC KEY-----([A-Za-z0-9+/=\s]*)-----END PUBLIC KEY-----$/;

const encoder = new TextEncoder();

/** Stable machine-readable error codes of {@link JwtError}. */
export type JwtErrorCode = "format" | "too_large" | "invalid_options";

/** The single error type thrown by this library. */
export class JwtError extends Error {
  /** Stable machine-readable code. */
  readonly code: JwtErrorCode;

  /**
   * @param code - Stable error code.
   * @param message - Fixed human readable text; never contains input data.
   */
  constructor(code: JwtErrorCode, message: string) {
    super(message.slice(0, 200));
    this.name = "JwtError";
    this.code = code;
  }
}

/** A parsed JSON object. */
export type JsonObject = Record<string, unknown>;

/** A decoded, unverified JWT. */
export interface DecodedJwt {
  /** JOSE header. */
  readonly header: JsonObject;
  /** Claims set. */
  readonly payload: JsonObject;
  /** Raw signature bytes. */
  readonly signature: Uint8Array;
  /** The exact signing input, `header.payload` as transmitted. */
  readonly signingInput: string;
}

/** Supported JWS algorithms (no none, no EdDSA, no ES512). */
export type Alg =
  | "HS256"
  | "HS384"
  | "HS512"
  | "RS256"
  | "RS384"
  | "RS512"
  | "PS256"
  | "PS384"
  | "PS512"
  | "ES256"
  | "ES384";

/** Names of the checks reported by {@link verifyJwt}. */
export type CheckName =
  | "format"
  | "alg"
  | "key"
  | "crit"
  | "signature"
  | "exp"
  | "nbf"
  | "iat"
  | "iss"
  | "aud";

/** A JSON Web Key (RFC 7517) as plain data. */
export interface JsonWebKey {
  alg?: string;
  crv?: string;
  d?: string;
  dp?: string;
  dq?: string;
  e?: string;
  ext?: boolean;
  k?: string;
  key_ops?: string[];
  kty?: string;
  n?: string;
  oth?: unknown[];
  p?: string;
  q?: string;
  qi?: string;
  use?: string;
  x?: string;
  y?: string;
}

/** Event handed to `onEvent` after each check. Carries no token data. */
export interface VerifyEvent {
  readonly check: CheckName;
  readonly ok: boolean;
}

/** Options of {@link verifyJwt}. */
export interface VerifyOptions {
  /** Verification key: a public JWK, an oct JWK, a PEM SPKI or an HMAC secret. */
  readonly key: JsonWebKey | string;
  /** Explicit, non-empty algorithm allowlist. */
  readonly algorithms: readonly Alg[];
  /** Clock in epoch seconds. Defaults to the system clock. */
  readonly now?: () => number;
  /** Clock tolerance in seconds, 0 to 300. Defaults to 0. */
  readonly clockToleranceSec?: number;
  /** Expected `iss`. */
  readonly issuer?: string;
  /** Expected `aud`. */
  readonly audience?: string;
  /** Observer called after each check. Exceptions are ignored. */
  readonly onEvent?: (event: VerifyEvent) => void;
}

/** Outcome of one check. */
export interface CheckResult {
  readonly name: CheckName;
  readonly ok: boolean;
  readonly message: string;
}

/** Outcome of {@link verifyJwt}. */
export interface VerifyResult {
  /** True only when every reported check passed. */
  readonly valid: boolean;
  readonly checks: readonly CheckResult[];
  readonly warnings: readonly string[];
}

/** Result of {@link inspectJwt}. Never contains the signature. */
export interface Inspection {
  readonly header: JsonObject;
  readonly payload: JsonObject;
  readonly algorithm: string | null;
  readonly keyId: string | null;
  readonly issuedAt: string | null;
  readonly notBefore: string | null;
  readonly expiresAt: string | null;
  readonly secondsToExpiry: number | null;
  readonly warnings: readonly string[];
}

type Family = "HS" | "RS" | "PS" | "ES";
type Hash = "SHA-256" | "SHA-384" | "SHA-512";

interface AlgSpec {
  readonly family: Family;
  readonly hash: Hash;
  readonly bytes: number;
  readonly curve: "P-256" | "P-384" | null;
}

const ALGS: Readonly<Record<Alg, AlgSpec>> = {
  HS256: { family: "HS", hash: "SHA-256", bytes: 32, curve: null },
  HS384: { family: "HS", hash: "SHA-384", bytes: 48, curve: null },
  HS512: { family: "HS", hash: "SHA-512", bytes: 64, curve: null },
  RS256: { family: "RS", hash: "SHA-256", bytes: 32, curve: null },
  RS384: { family: "RS", hash: "SHA-384", bytes: 48, curve: null },
  RS512: { family: "RS", hash: "SHA-512", bytes: 64, curve: null },
  PS256: { family: "PS", hash: "SHA-256", bytes: 32, curve: null },
  PS384: { family: "PS", hash: "SHA-384", bytes: 48, curve: null },
  PS512: { family: "PS", hash: "SHA-512", bytes: 64, curve: null },
  ES256: { family: "ES", hash: "SHA-256", bytes: 32, curve: "P-256" },
  ES384: { family: "ES", hash: "SHA-384", bytes: 48, curve: "P-384" },
};

function isAlg(value: unknown): value is Alg {
  return typeof value === "string" && Object.hasOwn(ALGS, value);
}

function defaultNow(): number {
  return Math.floor(Date.now() / 1000);
}

// ---------------------------------------------------------------- decoding

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** Strict, canonical, unpadded base64url. Returns null on any deviation. */
function decodeBase64Url(text: string): Uint8Array | null {
  if (!BASE64URL.test(text) || text.length % 4 === 1) {
    return null;
  }
  const standard = text.replaceAll("-", "+").replaceAll("_", "/");
  const padding = "=".repeat((4 - (standard.length % 4)) % 4);
  const bytes = Uint8Array.from(atob(`${standard}${padding}`), (ch) => ch.charCodeAt(0));
  return encodeBase64Url(bytes) === text ? bytes : null;
}

function depthWithinLimit(text: string): boolean {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (const ch of text) {
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
    } else if (ch === '"') {
      inString = true;
    } else if (ch === "{" || ch === "[") {
      depth += 1;
      if (depth > MAX_JSON_DEPTH) {
        return false;
      }
    } else if (ch === "}" || ch === "]") {
      depth -= 1;
    }
  }
  return true;
}

function parseJsonObject(bytes: Uint8Array): JsonObject | null {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
  if (!depthWithinLimit(text)) {
    return null;
  }
  let value: unknown;
  try {
    // JSON.parse keeps the lexically last duplicate member.
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  return value as JsonObject;
}

/**
 * Decodes a compact JWS without verifying it (RFC 7515 section 7.1).
 *
 * Segments must be strict, canonical, unpadded base64url; header and payload
 * must be UTF-8 JSON objects. Duplicate members keep the last value. The input
 * is never trimmed.
 *
 * @param token - The compact token, at most 16_384 characters.
 * @returns The decoded parts.
 * @throws {JwtError} `too_large` above 16_384 characters, `format` otherwise.
 */
export function decodeJwt(token: string): DecodedJwt {
  if (typeof token !== "string") {
    throw new JwtError("format", "token must be a string");
  }
  if (token.length > MAX_TOKEN_CHARS) {
    throw new JwtError("too_large", "token exceeds 16384 characters");
  }
  const parts = token.split(".");
  const [rawHeader, rawPayload, rawSignature] = parts;
  if (
    parts.length !== 3 ||
    rawHeader === undefined ||
    rawPayload === undefined ||
    rawSignature === undefined
  ) {
    throw new JwtError("format", "token must have exactly three segments");
  }
  const headerBytes = decodeBase64Url(rawHeader);
  const payloadBytes = decodeBase64Url(rawPayload);
  const signature = decodeBase64Url(rawSignature);
  if (headerBytes === null || payloadBytes === null || signature === null) {
    throw new JwtError("format", "segment is not strict base64url");
  }
  const header = parseJsonObject(headerBytes);
  if (header === null) {
    throw new JwtError("format", "header is not a JSON object");
  }
  const payload = parseJsonObject(payloadBytes);
  if (payload === null) {
    throw new JwtError("format", "payload is not a JSON object");
  }
  return {
    header,
    payload,
    signature,
    signingInput: `${rawHeader}.${rawPayload}`,
  };
}

// --------------------------------------------------------------- key rules

interface SubtleLike {
  importKey(
    format: string,
    keyData: unknown,
    algorithm: unknown,
    extractable: boolean,
    usages: string[],
  ): Promise<unknown>;
  verify(algorithm: unknown, key: unknown, signature: unknown, data: unknown): Promise<boolean>;
}

function subtle(): SubtleLike {
  return (globalThis as unknown as { crypto: { subtle: SubtleLike } }).crypto.subtle;
}

type KeyOutcome =
  | { readonly ok: true; readonly key: unknown }
  | { readonly ok: false; readonly message: string };

function fail(message: string): KeyOutcome {
  return { ok: false, message };
}

function bitLength(bytes: Uint8Array): number {
  let start = 0;
  while (start < bytes.length && bytes[start] === 0) {
    start += 1;
  }
  if (start === bytes.length) {
    return 0;
  }
  const first = bytes[start] ?? 0;
  return (bytes.length - start - 1) * 8 + (32 - Math.clz32(first));
}

function rsaSizeProblem(bits: number): string | null {
  if (bits < RSA_MIN_BITS) {
    return "RSA modulus is shorter than 2048 bits";
  }
  if (bits > RSA_MAX_BITS) {
    return "RSA modulus is longer than 8192 bits";
  }
  return null;
}

interface Tlv {
  readonly tag: number;
  readonly start: number;
  readonly end: number;
}

function readTlv(bytes: Uint8Array, offset: number, limit: number): Tlv | null {
  if (offset + 2 > limit) {
    return null;
  }
  const tag = bytes[offset] ?? 0;
  const first = bytes[offset + 1] ?? 0;
  let length = first;
  let position = offset + 2;
  if (first >= 0x80) {
    const count = first - 0x80;
    if (count === 0 || count > 4 || position + count > limit) {
      return null;
    }
    length = 0;
    for (let i = 0; i < count; i += 1) {
      length = length * 256 + (bytes[position + i] ?? 0);
    }
    position += count;
  }
  if (position + length > limit) {
    return null;
  }
  return { tag, start: position, end: position + length };
}

function sameBytes(a: Uint8Array, b: readonly number[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

/** Measures the RSA modulus of a DER SPKI before any import. */
function rsaModulusBits(der: Uint8Array): number | null {
  const spki = readTlv(der, 0, der.length);
  if (spki === null || spki.tag !== 0x30) {
    return null;
  }
  const algorithm = readTlv(der, spki.start, spki.end);
  if (algorithm === null || algorithm.tag !== 0x30) {
    return null;
  }
  const oid = readTlv(der, algorithm.start, algorithm.end);
  if (oid === null || oid.tag !== 0x06 || !sameBytes(der.subarray(oid.start, oid.end), RSA_OID)) {
    return null;
  }
  const bits = readTlv(der, algorithm.end, spki.end);
  if (bits === null || bits.tag !== 0x03 || bits.end - bits.start < 2) {
    return null;
  }
  const inner = readTlv(der, bits.start + 1, bits.end);
  if (inner === null || inner.tag !== 0x30) {
    return null;
  }
  const modulus = readTlv(der, inner.start, inner.end);
  if (modulus === null || modulus.tag !== 0x02) {
    return null;
  }
  return bitLength(der.subarray(modulus.start, modulus.end));
}

function importParams(alg: Alg): unknown {
  const spec = ALGS[alg];
  if (spec.family === "RS") {
    return { name: "RSASSA-PKCS1-v1_5", hash: spec.hash };
  }
  if (spec.family === "PS") {
    return { name: "RSA-PSS", hash: spec.hash };
  }
  return { name: "ECDSA", namedCurve: spec.curve };
}

async function importPublic(alg: Alg, format: "spki" | "jwk", data: unknown): Promise<KeyOutcome> {
  try {
    const key = await subtle().importKey(format, data, importParams(alg), false, ["verify"]);
    return { ok: true, key };
  } catch {
    return fail("key could not be imported for this algorithm");
  }
}

async function importHmac(spec: AlgSpec, secret: Uint8Array): Promise<KeyOutcome> {
  if (secret.length < spec.bytes) {
    return fail("HMAC secret is shorter than the hash output");
  }
  try {
    const key = await subtle().importKey("raw", secret, { name: "HMAC", hash: spec.hash }, false, [
      "verify",
    ]);
    return { ok: true, key };
  } catch {
    return fail("key could not be imported for this algorithm");
  }
}

async function fromPem(alg: Alg, text: string): Promise<KeyOutcome> {
  if (text.includes("PRIVATE KEY")) {
    return fail("private keys are never accepted");
  }
  const match = PEM_SPKI.exec(text.trim());
  const body = (match?.[1] ?? "").replace(/\s+/g, "");
  if (match === null || body.length % 4 !== 0 || !BASE64.test(body)) {
    return fail("key is not a PEM SPKI public key");
  }
  const der = Uint8Array.from(atob(body), (ch) => ch.charCodeAt(0));
  if (ALGS[alg].family !== "ES") {
    const bits = rsaModulusBits(der);
    if (bits === null) {
      return fail("key is not an RSA public key");
    }
    const problem = rsaSizeProblem(bits);
    if (problem !== null) {
      return fail(problem);
    }
  }
  return importPublic(alg, "spki", der);
}

async function fromJwk(alg: Alg, jwk: JsonWebKey): Promise<KeyOutcome> {
  const j = jwk as Record<string, unknown>;
  let size = 0;
  for (const value of Object.values(j)) {
    if (typeof value === "string") {
      size += value.length;
    }
  }
  if (size > MAX_KEY_CHARS) {
    return fail("key input is too large");
  }
  for (const member of PRIVATE_MEMBERS) {
    if (Object.hasOwn(j, member)) {
      return fail("private keys are never accepted");
    }
  }
  if (Object.hasOwn(j, "alg") && j.alg !== alg) {
    return fail("JWK alg does not match the token alg");
  }
  if (Object.hasOwn(j, "use") && j.use !== "sig") {
    return fail("JWK use must be sig");
  }
  const spec = ALGS[alg];
  if (spec.family === "HS") {
    if (j.kty !== "oct" || typeof j.k !== "string") {
      return fail("HMAC algorithms need an oct JWK");
    }
    const secret = decodeBase64Url(j.k);
    if (secret === null) {
      return fail("JWK k is not base64url");
    }
    return importHmac(spec, secret);
  }
  if (spec.family === "ES") {
    if (j.kty !== "EC" || j.crv !== spec.curve) {
      return fail("EC JWK curve does not match the algorithm");
    }
    if (typeof j.x !== "string" || typeof j.y !== "string") {
      return fail("EC JWK needs x and y");
    }
    return importPublic(alg, "jwk", {
      kty: "EC",
      crv: j.crv,
      x: j.x,
      y: j.y,
      ext: false,
    });
  }
  if (j.kty !== "RSA" || typeof j.n !== "string" || typeof j.e !== "string") {
    return fail("RSA algorithms need an RSA public JWK");
  }
  const modulus = decodeBase64Url(j.n);
  if (modulus === null || decodeBase64Url(j.e) === null) {
    return fail("JWK n or e is not base64url");
  }
  const problem = rsaSizeProblem(bitLength(modulus));
  if (problem !== null) {
    return fail(problem);
  }
  return importPublic(alg, "jwk", {
    kty: "RSA",
    n: j.n,
    e: j.e,
    ext: false,
  });
}

async function resolveKey(alg: Alg, input: JsonWebKey | string): Promise<KeyOutcome> {
  if (typeof input !== "string") {
    return fromJwk(alg, input);
  }
  if (input.length > MAX_KEY_CHARS) {
    return fail("key input is too large");
  }
  const spec = ALGS[alg];
  if (spec.family !== "HS") {
    return fromPem(alg, input);
  }
  if (input.includes("-----BEGIN")) {
    return fail("PEM text must not be used as an HMAC secret");
  }
  return importHmac(spec, encoder.encode(input));
}

// ------------------------------------------------------------ verification

interface ResolvedOptions {
  readonly key: JsonWebKey | string;
  readonly algorithms: ReadonlySet<Alg>;
  readonly tolerance: number;
  readonly now: () => number;
  readonly issuer: string | undefined;
  readonly audience: string | undefined;
  readonly onEvent: ((event: VerifyEvent) => void) | undefined;
}

function bad(message: string): never {
  throw new JwtError("invalid_options", message);
}

function resolveOptions(options: VerifyOptions): ResolvedOptions {
  if (typeof options !== "object" || options === null) {
    bad("options must be an object");
  }
  const { key, algorithms, clockToleranceSec, now, issuer, audience } = options;
  const { onEvent } = options;
  if (!Array.isArray(algorithms) || algorithms.length === 0 || algorithms.length > MAX_ALGORITHMS) {
    bad("algorithms must be a non-empty allowlist");
  }
  const allowed = new Set<Alg>();
  for (const entry of algorithms) {
    if (!isAlg(entry)) {
      bad("unsupported algorithm in the allowlist");
    }
    allowed.add(entry);
  }
  if (typeof key !== "string" && (typeof key !== "object" || key === null || Array.isArray(key))) {
    bad("key must be a JWK object or a string");
  }
  const tolerance = clockToleranceSec ?? 0;
  if (
    typeof tolerance !== "number" ||
    !Number.isFinite(tolerance) ||
    tolerance < 0 ||
    tolerance > MAX_TOLERANCE_SEC
  ) {
    bad("clockToleranceSec must be between 0 and 300");
  }
  if (now !== undefined && typeof now !== "function") {
    bad("now must be a function");
  }
  if (issuer !== undefined && typeof issuer !== "string") {
    bad("issuer must be a string");
  }
  if (audience !== undefined && typeof audience !== "string") {
    bad("audience must be a string");
  }
  if (onEvent !== undefined && typeof onEvent !== "function") {
    bad("onEvent must be a function");
  }
  return {
    key,
    algorithms: allowed,
    tolerance,
    now: now ?? defaultNow,
    issuer,
    audience,
    onEvent,
  };
}

type Recorder = (name: CheckName, ok: boolean, message: string) => boolean;

function checkAlg(header: JsonObject, allowed: ReadonlySet<Alg>, record: Recorder): Alg | null {
  const value = header.alg;
  if (typeof value !== "string") {
    record("alg", false, "alg header is missing or not a string");
    return null;
  }
  if (value.toLowerCase() === "none") {
    record("alg", false, "alg none is never accepted");
    return null;
  }
  if (!isAlg(value) || !allowed.has(value)) {
    record("alg", false, "alg is not in the allowlist");
    return null;
  }
  record("alg", true, "alg is in the allowlist");
  return value;
}

async function checkSignature(
  alg: Alg,
  key: unknown,
  decoded: DecodedJwt,
): Promise<{ ok: boolean; message: string }> {
  const spec = ALGS[alg];
  if (spec.family === "ES" && decoded.signature.length !== spec.bytes * 2) {
    return {
      ok: false,
      message: "ECDSA signature must be raw r||s of the curve size",
    };
  }
  let params: unknown;
  if (spec.family === "HS") {
    params = { name: "HMAC" };
  } else if (spec.family === "RS") {
    params = { name: "RSASSA-PKCS1-v1_5" };
  } else if (spec.family === "PS") {
    params = { name: "RSA-PSS", saltLength: spec.bytes };
  } else {
    params = { name: "ECDSA", hash: spec.hash };
  }
  let valid = false;
  try {
    valid = await subtle().verify(
      params,
      key,
      decoded.signature,
      encoder.encode(decoded.signingInput),
    );
  } catch {
    valid = false;
  }
  return {
    ok: valid,
    message: valid ? "signature is valid" : "signature does not match",
  };
}

/**
 * Verifies a JWT locally with WebCrypto and reports every check.
 *
 * Token defects (including oversize tokens) are failed checks, never
 * exceptions. Only invalid options throw.
 *
 * @param token - The compact token.
 * @param options - Key, algorithm allowlist and claim expectations.
 * @returns The per-check report.
 * @throws {JwtError} `invalid_options` when the options are unusable.
 */
export async function verifyJwt(token: string, options: VerifyOptions): Promise<VerifyResult> {
  const opts = resolveOptions(options);
  const nowSec = opts.now();
  if (typeof nowSec !== "number" || !Number.isFinite(nowSec)) {
    bad("now must return finite epoch seconds");
  }
  const checks: CheckResult[] = [];
  const warnings: string[] = [];
  const record: Recorder = (name, ok, message) => {
    checks.push({ name, ok, message });
    try {
      opts.onEvent?.({ check: name, ok });
    } catch {
      // A faulty observer never changes the verdict.
    }
    return ok;
  };
  const finish = (): VerifyResult => ({
    valid: checks.every((c) => c.ok),
    checks,
    warnings,
  });

  let decoded: DecodedJwt;
  try {
    decoded = decodeJwt(token);
  } catch (error) {
    const tooLarge = error instanceof JwtError && error.code === "too_large";
    record(
      "format",
      false,
      tooLarge ? "token exceeds the size limit" : "token is not a well-formed JWT",
    );
    return finish();
  }
  record("format", true, "token is a well-formed JWT");

  const alg = checkAlg(decoded.header, opts.algorithms, record);
  let signingKey: unknown;
  let keyOk = false;
  if (alg !== null) {
    const outcome = await resolveKey(alg, opts.key);
    keyOk = record(
      "key",
      outcome.ok,
      outcome.ok ? "key is acceptable for the algorithm" : outcome.message,
    );
    if (outcome.ok) {
      signingKey = outcome.key;
    }
  }
  const critPresent = Object.hasOwn(decoded.header, "crit");
  const critOk = record(
    "crit",
    !critPresent,
    critPresent ? "crit header parameter is not supported" : "no crit header parameter",
  );
  if (alg !== null && keyOk && critOk) {
    const outcome = await checkSignature(alg, signingKey, decoded);
    record("signature", outcome.ok, outcome.message);
  }

  const payload = decoded.payload;
  const tolerance = opts.tolerance;
  const rules: ReadonlyArray<readonly ["exp" | "nbf" | "iat", (value: number) => boolean, string]> =
    [
      ["exp", (v) => nowSec >= v + tolerance, "token has expired"],
      ["nbf", (v) => nowSec + tolerance < v, "token is not valid yet"],
      ["iat", (v) => v > nowSec + tolerance, "token was issued in the future"],
    ];
  for (const [name, fails, message] of rules) {
    if (!Object.hasOwn(payload, name)) {
      record(name, true, `${name} claim is absent`);
      continue;
    }
    const value = payload[name];
    if (typeof value !== "number" || !Number.isFinite(value)) {
      record(name, false, `${name} claim is not a number`);
    } else if (fails(value)) {
      record(name, false, message);
    } else {
      record(name, true, `${name} claim is satisfied`);
    }
  }
  if (opts.issuer !== undefined) {
    const ok = payload.iss === opts.issuer;
    record(
      "iss",
      ok,
      ok ? "iss matches the expected issuer" : "iss does not match the expected issuer",
    );
  }
  if (opts.audience !== undefined) {
    const aud = payload.aud;
    const ok = aud === opts.audience || (Array.isArray(aud) && aud.includes(opts.audience));
    record(
      "aud",
      ok,
      ok ? "aud contains the expected audience" : "aud does not contain the expected audience",
    );
  } else if (Object.hasOwn(payload, "aud")) {
    warnings.push("aud_not_checked");
  }
  return finish();
}

// -------------------------------------------------------------- inspection

function isoTime(value: unknown): string | null {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }
  const millis = value * 1000;
  if (Math.abs(millis) > 8.64e15) {
    return null;
  }
  return new Date(millis).toISOString();
}

/**
 * Decodes a token and summarises it without verifying the signature.
 *
 * @param token - The compact token.
 * @param now - Epoch seconds, or a clock returning them. Defaults to the system clock.
 * @returns The inspection, which never contains the signature.
 * @throws {JwtError} `format` or `too_large` for bad tokens, `invalid_options` for a bad clock.
 */
export function inspectJwt(token: string, now: number | (() => number) = defaultNow): Inspection {
  const { header, payload } = decodeJwt(token);
  const nowSec = typeof now === "function" ? now() : now;
  if (typeof nowSec !== "number" || !Number.isFinite(nowSec)) {
    bad("now must be finite epoch seconds");
  }
  const warnings: string[] = ["signature_not_verified"];
  const algorithm = typeof header.alg === "string" ? header.alg : null;
  if (algorithm !== null && algorithm.toLowerCase() === "none") {
    warnings.push("alg_none");
  }
  if (Object.hasOwn(header, "crit")) {
    warnings.push("crit_present");
  }
  const keyId = typeof header.kid === "string" ? header.kid : null;
  const times: Record<"exp" | "nbf" | "iat", string | null> = {
    exp: null,
    nbf: null,
    iat: null,
  };
  for (const name of ["exp", "nbf", "iat"] as const) {
    if (Object.hasOwn(payload, name)) {
      times[name] = isoTime(payload[name]);
      if (times[name] === null) {
        warnings.push(`${name}_invalid`);
      }
    }
  }
  let secondsToExpiry: number | null = null;
  if (!Object.hasOwn(payload, "exp")) {
    warnings.push("no_exp");
  } else if (times.exp !== null) {
    secondsToExpiry = Math.floor((payload.exp as number) - nowSec);
    if (secondsToExpiry <= 0) {
      warnings.push("expired");
    }
  }
  if (times.nbf !== null && nowSec < (payload.nbf as number)) {
    warnings.push("not_yet_valid");
  }
  return {
    header,
    payload,
    algorithm,
    keyId,
    issuedAt: times.iat,
    notBefore: times.nbf,
    expiresAt: times.exp,
    secondsToExpiry,
    warnings,
  };
}

function escapeControls(text: string): string {
  let out = "";
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    const control = code < 0x20 || (code >= 0x7f && code <= 0x9f);
    out += control ? `\\u${code.toString(16).padStart(4, "0")}` : ch;
  }
  return out;
}

function show(value: string | null): string {
  return value === null ? "-" : escapeControls(value);
}

/**
 * Renders an inspection. The signature is never part of the output.
 *
 * @param inspection - Result of {@link inspectJwt}.
 * @param format - `"text"` or `"json"`.
 * @returns The rendered string; control characters are escaped in text mode.
 * @throws {JwtError} `invalid_options` for an unknown format.
 */
export function formatInspection(inspection: Inspection, format: "text" | "json"): string {
  if (format === "json") {
    return JSON.stringify(inspection, null, 2);
  }
  if (format !== "text") {
    bad("format must be text or json");
  }
  const i = inspection;
  const expiry = i.secondsToExpiry === null ? "-" : String(i.secondsToExpiry);
  const lines = [
    `Algorithm: ${show(i.algorithm)}`,
    `Key ID: ${show(i.keyId)}`,
    `Issued at: ${show(i.issuedAt)}`,
    `Not before: ${show(i.notBefore)}`,
    `Expires at: ${show(i.expiresAt)}`,
    `Seconds to expiry: ${expiry}`,
    `Header: ${escapeControls(JSON.stringify(i.header))}`,
    `Payload: ${escapeControls(JSON.stringify(i.payload))}`,
    `Warnings: ${i.warnings.length === 0 ? "-" : i.warnings.join(", ")}`,
  ];
  return lines.join("\n");
}
