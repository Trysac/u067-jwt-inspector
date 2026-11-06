import { afterEach, describe, expect, it, vi } from "vitest";
import * as jwt from "../src/index.js";
import * as h from "./helpers.js";

const A1_TOKEN = h.A1_TOKEN;
const A1_JWK: jwt.JsonWebKey = { kty: "oct", k: h.A1_KEY };
const NOW = 1_700_000_000;
const now = (): number => NOW;
const secret = new Uint8Array(32).fill(7);
const secretJwk: jwt.JsonWebKey = { kty: "oct", k: h.b64u(secret) };

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

function codeOf(fn: () => unknown): string {
  try {
    fn();
    return "none";
  } catch (error) {
    return error instanceof jwt.JwtError ? error.code : "other";
  }
}

async function codeOfAsync(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
    return "none";
  } catch (error) {
    return error instanceof jwt.JwtError ? error.code : "other";
  }
}

function check(result: jwt.VerifyResult, name: jwt.CheckName): jwt.CheckResult | undefined {
  return result.checks.find((c) => c.name === name);
}

function failedNames(result: jwt.VerifyResult): string[] {
  return result.checks.filter((c) => !c.ok).map((c) => c.name);
}

async function hs256(payload: object, header: object = { alg: "HS256" }) {
  return h.signToken(header, payload, await h.hmacSigner(secret));
}

describe("JwtError", () => {
  it("carries a stable code and a bounded message", () => {
    const error = new jwt.JwtError("format", "x".repeat(500));
    expect(error).toBeInstanceOf(Error);
    expect(error.code).toBe("format");
    expect(error.name).toBe("JwtError");
    expect(error.message.length).toBe(200);
  });
});

describe("decodeJwt", () => {
  it("decodes the RFC 7515 Appendix A.1 token", () => {
    const decoded = jwt.decodeJwt(A1_TOKEN);
    expect(decoded.header).toEqual({ typ: "JWT", alg: "HS256" });
    expect(decoded.payload.iss).toBe("joe");
    expect(decoded.payload.exp).toBe(1300819380);
    expect(decoded.signature.length).toBe(32);
    expect(decoded.signingInput).toBe(`${h.A1_HEADER}.${h.A1_PAYLOAD}`);
  });

  it.each([
    ["two parts", [h.A1_HEADER, h.A1_PAYLOAD].join(".")],
    ["four parts", [h.A1_HEADER, h.A1_PAYLOAD, h.A1_SIGNATURE, h.A1_SIGNATURE].join(".")],
    ["five parts", [h.A1_HEADER, h.A1_PAYLOAD, h.A1_SIGNATURE, "a", "b"].join(".")],
    ["padding", `${h.A1_HEADER}.${h.A1_PAYLOAD}.${h.A1_SIGNATURE}=`],
    ["padded header", `${h.A1_HEADER}=.${h.A1_PAYLOAD}.${h.A1_SIGNATURE}`],
    ["plus sign", [h.A1_HEADER, "ab+d", h.A1_SIGNATURE].join(".")],
    ["slash", [h.A1_HEADER, "ab/d", h.A1_SIGNATURE].join(".")],
    ["non-JSON payload", [h.A1_HEADER, h.b64uText("not json"), h.A1_SIGNATURE].join(".")],
    ["array payload", [h.A1_HEADER, h.b64uText("[1,2]"), h.A1_SIGNATURE].join(".")],
    ["null payload", [h.A1_HEADER, h.b64uText("null"), h.A1_SIGNATURE].join(".")],
    ["array header", [h.b64uText("[]"), h.A1_PAYLOAD, h.A1_SIGNATURE].join(".")],
    ["leading space", ` ${A1_TOKEN}`],
    ["trailing newline", `${A1_TOKEN}\n`],
    ["impossible length", "a.e30."],
    ["non-canonical trailing bits", "QR.e30."],
    ["invalid UTF-8", "_w.e30."],
    ["empty header", ".e30."],
    ["byte order mark", `${h.b64u(new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]))}.e30.`],
    ["excessive nesting", `${h.b64uText("[".repeat(100))}.e30.`],
  ])("rejects %s with code format", (_name, token) => {
    expect(codeOf(() => jwt.decodeJwt(token))).toBe("format");
  });

  it("'=' padding, '+' or '/', a non-JSON or array payload and a leading ' ' throw JwtError code 'format'; 16_385 characters throw code 'too_large'", () => {
    const bad = [
      `${h.A1_HEADER}.${h.A1_PAYLOAD}.${h.A1_SIGNATURE}=`,
      [h.A1_HEADER, "ab+d", h.A1_SIGNATURE].join("."),
      [h.A1_HEADER, "ab/d", h.A1_SIGNATURE].join("."),
      [h.A1_HEADER, h.b64uText("not json"), h.A1_SIGNATURE].join("."),
      [h.A1_HEADER, h.b64uText("[1,2]"), h.A1_SIGNATURE].join("."),
      ` ${A1_TOKEN}`,
    ];
    for (const t of bad) expect(codeOf(() => jwt.decodeJwt(t))).toBe("format");
    expect(codeOf(() => jwt.decodeJwt("a".repeat(16_385)))).toBe("too_large");
  });

  it("rejects a non-string token", () => {
    expect(codeOf(() => jwt.decodeJwt(42 as unknown as string))).toBe("format");
  });

  it("enforces the 16_385 character limit", () => {
    expect(codeOf(() => jwt.decodeJwt("a".repeat(16_385)))).toBe("too_large");
    expect(codeOf(() => jwt.decodeJwt("a".repeat(16_384)))).toBe("format");
  });

  it("keeps the last duplicate member", () => {
    const token = `${h.b64uText('{"alg":"a","alg":"b"}')}.${h.b64uText('{"a":1,"a":2}')}.`;
    const decoded = jwt.decodeJwt(token);
    expect(decoded.header.alg).toBe("b");
    expect(decoded.payload.a).toBe(2);
  });

  it("accepts braces and escapes inside strings and an empty signature", () => {
    const payload = h.b64uText('{"a":"x\\"{[","b":[[1]]}');
    const decoded = jwt.decodeJwt(`e30.${payload}.`);
    expect(decoded.signature.length).toBe(0);
    expect(decoded.payload.b).toEqual([[1]]);
  });
});

describe("verifyJwt: the published A.1 token", () => {
  it("is valid with its published oct JWK", async () => {
    const result = await jwt.verifyJwt(A1_TOKEN, {
      key: A1_JWK,
      algorithms: ["HS256"],
      now: () => 1300819379,
    });
    expect(result.valid).toBe(true);
    expect(result.checks.map((c) => c.name)).toEqual([
      "format",
      "alg",
      "key",
      "crit",
      "signature",
      "exp",
      "nbf",
      "iat",
    ]);
    expect(result.warnings).toEqual([]);
  });

  it("fails exp at the expiry instant and passes with one second of tolerance", async () => {
    const base = { key: A1_JWK, algorithms: ["HS256" as const] };
    const expired = await jwt.verifyJwt(A1_TOKEN, {
      ...base,
      now: () => 1300819380,
    });
    expect(expired.valid).toBe(false);
    expect(check(expired, "exp")?.ok).toBe(false);
    expect(check(expired, "signature")?.ok).toBe(true);
    const tolerant = await jwt.verifyJwt(A1_TOKEN, {
      ...base,
      now: () => 1300819380,
      clockToleranceSec: 1,
    });
    expect(tolerant.valid).toBe(true);
  });

  it("uses the system clock when none is injected", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date(1300819379 * 1000));
    const result = await jwt.verifyJwt(A1_TOKEN, {
      key: A1_JWK,
      algorithms: ["HS256"],
    });
    expect(result.valid).toBe(true);
  });

  it("rejects a tampered payload, a tampered signature and a wrong secret", async () => {
    const options = {
      key: A1_JWK,
      algorithms: ["HS256" as const],
      now: () => 1300819379,
    };
    const otherPayload = h.b64uJson({ iss: "mallory", exp: 1300819999 });
    const tampered = [h.A1_HEADER, otherPayload, h.A1_SIGNATURE].join(".");
    expect(check(await jwt.verifyJwt(tampered, options), "signature")?.ok).toBe(false);
    const flipped = `${h.A1_SIGNATURE.slice(0, -1)}A`;
    const badSig = [h.A1_HEADER, h.A1_PAYLOAD, flipped].join(".");
    expect((await jwt.verifyJwt(badSig, options)).valid).toBe(false);
    const wrongKey = { kty: "oct", k: h.b64u(new Uint8Array(64).fill(1)) };
    const wrong = await jwt.verifyJwt(A1_TOKEN, { ...options, key: wrongKey });
    expect(check(wrong, "signature")?.ok).toBe(false);
  });
});

describe("verifyJwt: options and format", () => {
  it("fails the alg check for alg none with any allowlist", async () => {
    const token = h.fakeToken({ alg: "none" });
    for (const algorithms of [["HS256"], ["RS256", "ES256"], ["HS512", "PS384"]] as jwt.Alg[][]) {
      const result = await jwt.verifyJwt(token, {
        key: A1_JWK,
        algorithms,
        now,
      });
      expect(result.valid).toBe(false);
      expect(check(result, "alg")?.ok).toBe(false);
      expect(check(result, "signature")).toBeUndefined();
      expect(check(result, "key")).toBeUndefined();
    }
    const upper = await jwt.verifyJwt(h.fakeToken({ alg: "NoNe" }), {
      key: A1_JWK,
      algorithms: ["HS256"],
      now,
    });
    expect(check(upper, "alg")?.ok).toBe(false);
  });

  it("fails the alg check for unlisted, missing and non-string alg", async () => {
    const options = { key: A1_JWK, algorithms: ["RS256" as const], now };
    expect(check(await jwt.verifyJwt(A1_TOKEN, options), "alg")?.ok).toBe(false);
    for (const header of [{}, { alg: 5 }, { alg: "HS999" }]) {
      const result = await jwt.verifyJwt(h.fakeToken(header), options);
      expect(check(result, "alg")?.ok).toBe(false);
    }
  });

  const badOptions: Array<[string, unknown]> = [
    ["an empty allowlist", { key: A1_JWK, algorithms: [] }],
    ["a none allowlist", { key: A1_JWK, algorithms: ["none"] }],
    ["an unknown algorithm", { key: A1_JWK, algorithms: ["HS999"] }],
    ["a non-array allowlist", { key: A1_JWK, algorithms: "HS256" }],
    ["an oversized allowlist", { key: A1_JWK, algorithms: new Array(17).fill("HS256") }],
    ["clockToleranceSec 301", { key: A1_JWK, algorithms: ["HS256"], clockToleranceSec: 301 }],
    ["negative tolerance", { key: A1_JWK, algorithms: ["HS256"], clockToleranceSec: -1 }],
    ["NaN tolerance", { key: A1_JWK, algorithms: ["HS256"], clockToleranceSec: Number.NaN }],
    ["string tolerance", { key: A1_JWK, algorithms: ["HS256"], clockToleranceSec: "5" }],
    ["a missing key", { algorithms: ["HS256"] }],
    ["a numeric key", { key: 5, algorithms: ["HS256"] }],
    ["an array key", { key: [], algorithms: ["HS256"] }],
    ["a non-function clock", { key: A1_JWK, algorithms: ["HS256"], now: 5 }],
    ["a clock returning NaN", { key: A1_JWK, algorithms: ["HS256"], now: () => Number.NaN }],
    ["a numeric issuer", { key: A1_JWK, algorithms: ["HS256"], issuer: 5 }],
    ["a numeric audience", { key: A1_JWK, algorithms: ["HS256"], audience: 5 }],
    ["a non-function observer", { key: A1_JWK, algorithms: ["HS256"], onEvent: 5 }],
    ["null options", null],
    ["string options", "options"],
  ];
  it.each(badOptions)("throws invalid_options for %s", async (_name, options) => {
    const code = await codeOfAsync(jwt.verifyJwt(A1_TOKEN, options as jwt.VerifyOptions));
    expect(code).toBe("invalid_options");
  });

  it("turns token defects into a failed format check", async () => {
    const options = { key: A1_JWK, algorithms: ["HS256" as const], now };
    const short = await jwt.verifyJwt("a.b", options);
    expect(short.valid).toBe(false);
    expect(short.checks).toHaveLength(1);
    expect(short.checks[0]?.name).toBe("format");
    expect(short.checks[0]?.ok).toBe(false);
    const large = await jwt.verifyJwt("a".repeat(16_385), options);
    expect(large.checks[0]?.name).toBe("format");
    expect(large.checks[0]?.message).toContain("size");
    const notString = await jwt.verifyJwt(5 as unknown as string, options);
    expect(notString.valid).toBe(false);
  });
});

describe("verifyJwt: key binding", () => {
  it("rejects an RS256 public PEM used as an HS256 secret", async () => {
    const pair = await h.rsaKeyPair("RSASSA-PKCS1-v1_5", "SHA-256", 2048);
    const pem = await h.publicPem(pair);
    const token = await h.signToken({ alg: "HS256" }, { sub: "x" }, await h.hmacSigner(pem));
    const importSpy = vi.spyOn(globalThis.crypto.subtle, "importKey");
    const verifySpy = vi.spyOn(globalThis.crypto.subtle, "verify");
    const result = await jwt.verifyJwt(token, {
      key: pem,
      algorithms: ["RS256", "HS256"],
      now,
    });
    expect(check(result, "key")?.ok).toBe(false);
    expect(check(result, "signature")).toBeUndefined();
    expect(result.valid).toBe(false);
    expect(importSpy).not.toHaveBeenCalled();
    expect(verifySpy).not.toHaveBeenCalled();
  });

  it("verifies RS256 with a PEM and with a JWK carrying a matching alg", async () => {
    const pair = await h.rsaKeyPair("RSASSA-PKCS1-v1_5", "SHA-256", 2048);
    const token = await h.signToken(
      { alg: "RS256" },
      { sub: "x" },
      h.keySigner(pair.privateKey, { name: "RSASSA-PKCS1-v1_5" }),
    );
    const pem = await h.publicPem(pair);
    const jwk = await h.exportJwk(pair.publicKey);
    expect(jwk.alg).toBe("RS256");
    for (const key of [pem, jwk]) {
      const result = await jwt.verifyJwt(token, {
        key,
        algorithms: ["RS256"],
        now,
      });
      expect(result.valid).toBe(true);
    }
    const tampered = `${token.slice(0, -4)}AAAA`;
    const bad = await jwt.verifyJwt(tampered, {
      key: pem,
      algorithms: ["RS256"],
      now,
    });
    expect(check(bad, "signature")?.ok).toBe(false);
  });

  it("rejects a JWK with alg RS256 used for an RS384 header", async () => {
    const pair = await h.rsaKeyPair("RSASSA-PKCS1-v1_5", "SHA-256", 2048);
    const jwk = await h.exportJwk(pair.publicKey);
    const result = await jwt.verifyJwt(h.fakeToken({ alg: "RS384" }, {}, 256), {
      key: { ...jwk, alg: "RS256" },
      algorithms: ["RS384"],
      now,
    });
    expect(check(result, "key")?.ok).toBe(false);
    expect(check(result, "signature")).toBeUndefined();
  });

  it("verifies PS256 and rejects a wrong PSS salt length", async () => {
    const pair = await h.rsaKeyPair("RSA-PSS", "SHA-256", 2048);
    const jwk = await h.exportJwk(pair.publicKey);
    const good = await h.signToken(
      { alg: "PS256" },
      {},
      h.keySigner(pair.privateKey, { name: "RSA-PSS", saltLength: 32 }),
    );
    const options = { key: jwk, algorithms: ["PS256" as const], now };
    expect((await jwt.verifyJwt(good, options)).valid).toBe(true);
    const salted = await h.signToken(
      { alg: "PS256" },
      {},
      h.keySigner(pair.privateKey, { name: "RSA-PSS", saltLength: 20 }),
    );
    const result = await jwt.verifyJwt(salted, options);
    expect(check(result, "signature")?.ok).toBe(false);
  });

  it("verifies ES256 and ES384 and rejects a 63-byte ES256 signature", async () => {
    const p256 = await h.ecKeyPair("P-256");
    const jwk256 = await h.exportJwk(p256.publicKey);
    const ok256 = await h.signToken(
      { alg: "ES256" },
      {},
      h.keySigner(p256.privateKey, { name: "ECDSA", hash: "SHA-256" }),
    );
    const options = { key: jwk256, algorithms: ["ES256" as const], now };
    expect((await jwt.verifyJwt(ok256, options)).valid).toBe(true);
    const pem = await h.publicPem(p256);
    expect((await jwt.verifyJwt(ok256, { ...options, key: pem })).valid).toBe(true);

    const p384 = await h.ecKeyPair("P-384");
    const ok384 = await h.signToken(
      { alg: "ES384" },
      {},
      h.keySigner(p384.privateKey, { name: "ECDSA", hash: "SHA-384" }),
    );
    const jwk384 = await h.exportJwk(p384.publicKey);
    const result384 = await jwt.verifyJwt(ok384, {
      key: jwk384,
      algorithms: ["ES384"],
      now,
    });
    expect(result384.valid).toBe(true);

    const short = await h.signToken({ alg: "ES256" }, {}, async () => new Uint8Array(63));
    const verifySpy = vi.spyOn(globalThis.crypto.subtle, "verify");
    const shortResult = await jwt.verifyJwt(short, options);
    expect(check(shortResult, "signature")?.ok).toBe(false);
    expect(verifySpy).not.toHaveBeenCalled();

    const curveMismatch = await jwt.verifyJwt(ok256, {
      ...options,
      key: jwk384,
    });
    expect(check(curveMismatch, "key")?.ok).toBe(false);
    const pem384 = await h.publicPem(p384);
    const pemMismatch = await jwt.verifyJwt(ok256, { ...options, key: pem384 });
    expect(check(pemMismatch, "key")?.ok).toBe(false);
  });

  it("enforces the HMAC secret size per hash", async () => {
    const thirtyOne = await h.signToken(
      { alg: "HS256" },
      {},
      await h.hmacSigner(new Uint8Array(31).fill(7)),
    );
    const base = { algorithms: ["HS256" as const], now };
    expect(check(await jwt.verifyJwt(thirtyOne, { ...base, key: "a".repeat(31) }), "key")?.ok).toBe(
      false,
    );
    const short = { kty: "oct", k: h.b64u(new Uint8Array(31).fill(7)) };
    expect(check(await jwt.verifyJwt(thirtyOne, { ...base, key: short }), "key")?.ok).toBe(false);
    const exact = await h.signToken({ alg: "HS256" }, {}, await h.hmacSigner("a".repeat(32)));
    expect((await jwt.verifyJwt(exact, { ...base, key: "a".repeat(32) })).valid).toBe(true);
    const weak384 = await jwt.verifyJwt(h.fakeToken({ alg: "HS384" }, {}, 48), {
      key: secretJwk,
      algorithms: ["HS384"],
      now,
    });
    expect(check(weak384, "key")?.ok).toBe(false);
    const secret512 = new Uint8Array(64).fill(9);
    const token512 = await h.signToken(
      { alg: "HS512" },
      {},
      await h.hmacSigner(secret512, "SHA-512"),
    );
    const result512 = await jwt.verifyJwt(token512, {
      key: { kty: "oct", k: h.b64u(secret512) },
      algorithms: ["HS512"],
      now,
    });
    expect(result512.valid).toBe(true);
  });

  it("never imports private keys", async () => {
    const ec = await h.ecKeyPair("P-256");
    const privateJwk = await h.exportJwk(ec.privateKey);
    expect(privateJwk.d).toBeDefined();
    const rsa = await h.rsaKeyPair("RSASSA-PKCS1-v1_5", "SHA-256", 2048);
    const rsaPrivate = await h.exportJwk(rsa.privateKey);
    const privatePem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----";
    const esToken = h.fakeToken({ alg: "ES256" }, {}, 64);
    const rsToken = h.fakeToken({ alg: "RS256" }, {}, 256);
    const importSpy = vi.spyOn(globalThis.crypto.subtle, "importKey");
    const attempts = [
      await jwt.verifyJwt(esToken, { key: privateJwk, algorithms: ["ES256"], now }),
      await jwt.verifyJwt(esToken, { key: privatePem, algorithms: ["ES256"], now }),
      await jwt.verifyJwt(rsToken, { key: rsaPrivate, algorithms: ["RS256"], now }),
      await jwt.verifyJwt(rsToken, { key: privatePem, algorithms: ["RS256"], now }),
      await jwt.verifyJwt(rsToken, {
        key: { kty: "oct", k: h.b64u(secret), d: "AA" },
        algorithms: ["RS256"],
        now,
      }),
    ];
    for (const result of attempts) {
      expect(check(result, "key")?.ok).toBe(false);
      expect(result.valid).toBe(false);
    }
    expect(importSpy).not.toHaveBeenCalled();
  });

  it("rejects weak, oversize and malformed RSA keys before import", async () => {
    const weak = await h.rsaKeyPair("RSASSA-PKCS1-v1_5", "SHA-256", 1024);
    const token = await h.signToken(
      { alg: "RS256" },
      {},
      h.keySigner(weak.privateKey, { name: "RSASSA-PKCS1-v1_5" }),
    );
    const options = { algorithms: ["RS256" as const], now };
    const importSpy = vi.spyOn(globalThis.crypto.subtle, "importKey");
    const weakJwk = await jwt.verifyJwt(token, {
      ...options,
      key: await h.exportJwk(weak.publicKey),
    });
    expect(check(weakJwk, "key")?.ok).toBe(false);
    const weakPem = await jwt.verifyJwt(token, {
      ...options,
      key: await h.publicPem(weak),
    });
    expect(check(weakPem, "key")?.ok).toBe(false);
    const huge = await jwt.verifyJwt(token, {
      ...options,
      key: { kty: "RSA", n: h.b64u(new Uint8Array(1025).fill(255)), e: "AQAB" },
    });
    expect(check(huge, "key")?.ok).toBe(false);
    expect(check(huge, "key")?.message).toContain("8192");
    expect(importSpy).not.toHaveBeenCalled();
  });

  it("rejects oversize key input", async () => {
    const token = h.fakeToken({ alg: "HS256" }, {}, 32);
    const options = { algorithms: ["HS256" as const], now };
    for (const key of ["a".repeat(16_385), { kty: "oct", k: "A".repeat(16_385) }]) {
      const result = await jwt.verifyJwt(token, { ...options, key });
      expect(check(result, "key")?.ok).toBe(false);
    }
    const pemToken = h.fakeToken({ alg: "RS256" }, {}, 256);
    const pem = await jwt.verifyJwt(pemToken, {
      key: "a".repeat(16_385),
      algorithms: ["RS256"],
      now,
    });
    expect(check(pem, "key")?.ok).toBe(false);
  });

  it("rejects keys of the wrong family or shape", async () => {
    const rsa = await h.rsaKeyPair("RSASSA-PKCS1-v1_5", "SHA-256", 2048);
    const rsaJwk = await h.exportJwk(rsa.publicKey);
    const ec = await h.ecKeyPair("P-256");
    const ecPem = await h.publicPem(ec);
    const rsToken = h.fakeToken({ alg: "RS256" }, {}, 256);
    const hsToken = h.fakeToken({ alg: "HS256" }, {}, 32);
    const esToken = h.fakeToken({ alg: "ES256" }, {}, 64);
    const cases: Array<[string, jwt.Alg, jwt.JsonWebKey | string]> = [
      [rsToken, "RS256", "plain secret text"],
      [rsToken, "RS256", secretJwk],
      [hsToken, "HS256", rsaJwk],
      [rsToken, "RS256", ecPem],
      [rsToken, "RS256", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"],
      [rsToken, "RS256", "-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----"],
      [rsToken, "RS256", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"],
      [esToken, "ES256", "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----"],
      [rsToken, "RS256", { ...rsaJwk, use: "enc" }],
      [rsToken, "RS256", { kty: "RSA", n: 5 as unknown as string, e: "AQAB" }],
      [rsToken, "RS256", { kty: "RSA", n: "a+b", e: "AQAB" }],
      [esToken, "ES256", { kty: "EC", crv: "P-256" }],
      [esToken, "ES256", { kty: "EC", crv: "P-256", x: "AA", y: "AA" }],
      [hsToken, "HS256", { kty: "oct", k: "a+b" }],
      [hsToken, "HS256", { kty: "oct" }],
      [hsToken, "HS256", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"],
    ];
    for (const [token, alg, key] of cases) {
      const result = await jwt.verifyJwt(token, { key, algorithms: [alg], now });
      expect(check(result, "key")?.ok).toBe(false);
      expect(check(result, "signature")).toBeUndefined();
    }
  });

  it("fails truncated SPKI documents without throwing", async () => {
    const rsa = await h.rsaKeyPair("RSASSA-PKCS1-v1_5", "SHA-256", 2048);
    const der = await h.spkiBytes(rsa);
    const token = h.fakeToken({ alg: "RS256" }, {}, 256);
    for (const cut of [1, 3, 5, 12, 20, 30, 33, 100, 200]) {
      const result = await jwt.verifyJwt(token, {
        key: h.pemFromDer(der.subarray(0, cut)),
        algorithms: ["RS256"],
        now,
      });
      expect(check(result, "key")?.ok).toBe(false);
    }
  });

  it("fails the crit check and skips the signature", async () => {
    const token = await hs256({}, { alg: "HS256", crit: ["exp"], exp: 1 });
    const result = await jwt.verifyJwt(token, {
      key: secretJwk,
      algorithms: ["HS256"],
      now,
    });
    expect(check(result, "crit")?.ok).toBe(false);
    expect(check(result, "signature")).toBeUndefined();
    expect(result.valid).toBe(false);
  });
});

describe("verifyJwt: claims", () => {
  type Extra = {
    clockToleranceSec?: number;
    issuer?: string;
    audience?: string;
  };
  type Case = [string, object, Extra, string[]];
  const cases: Case[] = [
    ["exp in the past", { exp: NOW - 1 }, {}, ["exp"]],
    ["exp equal to now", { exp: NOW }, {}, ["exp"]],
    ["exp equal to now with tolerance", { exp: NOW }, { clockToleranceSec: 1 }, []],
    ["exp in the future", { exp: NOW + 1 }, {}, []],
    ["nbf in the future", { nbf: NOW + 1 }, {}, ["nbf"]],
    ["nbf with tolerance", { nbf: NOW + 1 }, { clockToleranceSec: 1 }, []],
    ["iat in the future", { iat: NOW + 1 }, {}, ["iat"]],
    ["iat with tolerance", { iat: NOW + 1 }, { clockToleranceSec: 1 }, []],
    ["string exp", { exp: "9999999999" }, {}, ["exp"]],
    ["string nbf", { nbf: "1" }, {}, ["nbf"]],
    ["string iat", { iat: "1" }, {}, ["iat"]],
    ["iss mismatch", { iss: "a" }, { issuer: "b" }, ["iss"]],
    ["iss missing", {}, { issuer: "b" }, ["iss"]],
    ["iss match", { iss: "b" }, { issuer: "b" }, []],
    ["aud string match", { aud: "x" }, { audience: "x" }, []],
    ["aud array containing", { aud: ["y", "x"] }, { audience: "x" }, []],
    ["aud array lacking", { aud: ["y"] }, { audience: "x" }, ["aud"]],
    ["aud number", { aud: 5 }, { audience: "x" }, ["aud"]],
    ["aud missing", {}, { audience: "x" }, ["aud"]],
  ];
  it.each(cases)("evaluates %s", async (_name, payload, extra, expected) => {
    const result = await jwt.verifyJwt(await hs256(payload), {
      key: secretJwk,
      algorithms: ["HS256"],
      now,
      ...extra,
    });
    expect(failedNames(result)).toEqual(expected);
    expect(result.valid).toBe(expected.length === 0);
  });

  it("reports issuer and audience mismatches separately while still evaluating exp", async () => {
    const token = await hs256({ iss: "other", aud: "other", exp: NOW - 10 });
    const result = await jwt.verifyJwt(token, {
      key: secretJwk,
      algorithms: ["HS256"],
      now,
      issuer: "https://issuer.example",
      audience: "https://api.example",
    });
    expect(failedNames(result).sort()).toEqual(["aud", "exp", "iss"]);
    expect(check(result, "signature")?.ok).toBe(true);
  });

  it("warns aud_not_checked only when aud is present without an expectation", async () => {
    const options = { key: secretJwk, algorithms: ["HS256" as const], now };
    const withAud = await jwt.verifyJwt(await hs256({ aud: "x" }), options);
    expect(withAud.valid).toBe(true);
    expect(withAud.warnings).toEqual(["aud_not_checked"]);
    const without = await jwt.verifyJwt(await hs256({}), options);
    expect(without.warnings).toEqual([]);
    const checked = await jwt.verifyJwt(await hs256({ aud: "x" }), {
      ...options,
      audience: "x",
    });
    expect(checked.warnings).toEqual([]);
  });
});

describe("verifyJwt: events and leaks", () => {
  it("emits one {check, ok} event per check without token data", async () => {
    const events: unknown[] = [];
    const result = await jwt.verifyJwt(A1_TOKEN, {
      key: A1_JWK,
      algorithms: ["HS256"],
      now: () => 1300819380,
      onEvent: (event) => {
        events.push(event);
      },
    });
    expect(events).toHaveLength(result.checks.length);
    for (const [index, event] of events.entries()) {
      expect(Object.keys(event as object).sort()).toEqual(["check", "ok"]);
      expect(event).toEqual({
        check: result.checks[index]?.name,
        ok: result.checks[index]?.ok,
      });
    }
    const secrets = [h.A1_HEADER, h.A1_PAYLOAD, h.A1_SIGNATURE, h.A1_KEY];
    const visible = JSON.stringify([events, result.checks.map((c) => c.message), result.warnings]);
    for (const secretText of secrets) {
      expect(visible).not.toContain(secretText);
    }
    expect(visible).not.toContain("joe");
  });

  it("keeps messages free of key material on failures", async () => {
    const result = await jwt.verifyJwt(A1_TOKEN, {
      key: { kty: "oct", k: h.b64u(new Uint8Array(8).fill(3)), d: "c2VjcmV0" },
      algorithms: ["HS256"],
      now,
    });
    const visible = JSON.stringify(result);
    expect(visible).not.toContain("c2VjcmV0");
    expect(visible).not.toContain(h.A1_SIGNATURE);
  });

  it("ignores a throwing observer", async () => {
    const result = await jwt.verifyJwt(A1_TOKEN, {
      key: A1_JWK,
      algorithms: ["HS256"],
      now: () => 1300819379,
      onEvent: () => {
        throw new Error("observer failure");
      },
    });
    expect(result.valid).toBe(true);
  });
});

describe("inspectJwt and formatInspection", () => {
  it("inspects the A.1 token", () => {
    const inspection = jwt.inspectJwt(A1_TOKEN, () => 1300819379);
    expect(inspection.algorithm).toBe("HS256");
    expect(inspection.keyId).toBeNull();
    expect(inspection.expiresAt).toBe("2011-03-22T18:43:00.000Z");
    expect(inspection.secondsToExpiry).toBe(1);
    expect(inspection.issuedAt).toBeNull();
    expect(inspection.warnings).toEqual(["signature_not_verified"]);
    expect(JSON.stringify(inspection)).not.toContain(h.A1_SIGNATURE);
  });

  it("reports times, key id and window warnings", () => {
    const token = h.fakeToken({ alg: "ES256", kid: "key-1" }, { iat: 1000, nbf: 2000, exp: 3000 });
    const inside = jwt.inspectJwt(token, 2500);
    expect(inside.keyId).toBe("key-1");
    expect(inside.issuedAt).toBe("1970-01-01T00:16:40.000Z");
    expect(inside.notBefore).toBe("1970-01-01T00:33:20.000Z");
    expect(inside.expiresAt).toBe("1970-01-01T00:50:00.000Z");
    expect(inside.secondsToExpiry).toBe(500);
    expect(inside.warnings).toEqual(["signature_not_verified"]);
    expect(jwt.inspectJwt(token, 1500).warnings).toContain("not_yet_valid");
    expect(jwt.inspectJwt(token, 3000).warnings).toContain("expired");
    expect(jwt.inspectJwt(token, 2000).warnings).not.toContain("not_yet_valid");
  });

  it("warns about alg none, crit, missing and invalid time claims", () => {
    const none = jwt.inspectJwt(h.fakeToken({ alg: "none", crit: ["x"] }), 1);
    expect(none.warnings).toEqual(expect.arrayContaining(["alg_none", "crit_present", "no_exp"]));
    expect(none.algorithm).toBe("none");
    const odd = jwt.inspectJwt(h.fakeToken({ alg: 5 }, { exp: "abc", nbf: 1e300, iat: "x" }), 1);
    expect(odd.algorithm).toBeNull();
    expect(odd.expiresAt).toBeNull();
    expect(odd.secondsToExpiry).toBeNull();
    expect(odd.warnings).toEqual(
      expect.arrayContaining(["exp_invalid", "nbf_invalid", "iat_invalid"]),
    );
  });

  it("uses the system clock by default and validates the clock", () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date(2500 * 1000));
    const token = h.fakeToken({ alg: "HS256" }, { exp: 3000 });
    expect(jwt.inspectJwt(token).secondsToExpiry).toBe(500);
    expect(codeOf(() => jwt.inspectJwt(token, () => Number.NaN))).toBe("invalid_options");
    expect(codeOf(() => jwt.inspectJwt("a.b", 1))).toBe("format");
  });

  it("renders json without the signature", () => {
    const inspection = jwt.inspectJwt(A1_TOKEN, () => 1300819379);
    const output = jwt.formatInspection(inspection, "json");
    expect(JSON.parse(output)).toEqual(inspection);
    expect(output).not.toContain(h.A1_SIGNATURE);
    expect(output).not.toContain(A1_TOKEN);
  });

  it("renders text and neutralises control characters", () => {
    const kid = `a${String.fromCharCode(10)}b${String.fromCharCode(0x85)}c`;
    const esc = String.fromCharCode(27);
    const token = h.fakeToken({ alg: "HS256", kid }, { note: `${esc}[31mred`, exp: 3000 });
    const text = jwt.formatInspection(jwt.inspectJwt(token, 2500), "text");
    const lines = text.split(String.fromCharCode(10));
    expect(lines).toHaveLength(9);
    expect(lines[0]).toBe("Algorithm: HS256");
    expect(lines[1]).toContain("u000a");
    expect(lines[1]).toContain("u0085");
    expect(text).not.toContain(esc);
    expect(text).not.toContain(String.fromCharCode(0x85));
    expect(text).toContain("Seconds to expiry: 500");
    const plain = jwt.formatInspection(jwt.inspectJwt(h.fakeToken({}), 1), "text");
    expect(plain).toContain("Algorithm: -");
    expect(plain).toContain("Seconds to expiry: -");
  });

  it("rejects unknown formats", () => {
    const inspection = jwt.inspectJwt(A1_TOKEN, 1);
    expect(codeOf(() => jwt.formatInspection(inspection, "xml" as never))).toBe("invalid_options");
  });
});
