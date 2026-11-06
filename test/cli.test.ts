import { afterEach, describe, expect, it, vi } from "vitest";
import * as cli from "../src/cli.js";
import * as h from "./helpers.js";

const secret = new Uint8Array(32).fill(7);

interface ExecOptions {
  files?: Record<string, string>;
  stdin?: string;
  now?: boolean;
  clock?: () => number;
}

async function exec(args: string[], options: ExecOptions = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const reads: string[] = [];
  const files = options.files ?? {};
  const { stdin } = options;
  const clock = options.clock ?? (() => 1300819379);
  const io: cli.CliIo = {
    stdout: (text) => {
      out.push(text);
    },
    stderr: (text) => {
      err.push(text);
    },
    readFile: (path) => {
      reads.push(path);
      const content = files[path];
      return content === undefined
        ? Promise.reject(new Error("missing"))
        : Promise.resolve(content);
    },
    ...(stdin === undefined ? {} : { stdin: () => Promise.resolve(stdin) }),
    ...(options.now === false ? {} : { now: clock }),
  };
  const code = await cli.run(args, io);
  return { code, stdout: out.join(""), stderr: err.join(""), reads };
}

const a1Files = { "key.jwk": JSON.stringify({ kty: "oct", k: h.A1_KEY }) };
const a1Args = ["verify", h.A1_TOKEN, "--key", "key.jwk", "--alg", "HS256"];

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("cli verify", () => {
  it("returns 0 for a valid token and reads the key through io.readFile", async () => {
    const result = await exec(a1Args, { files: a1Files });
    expect(result.code).toBe(0);
    expect(result.reads).toEqual(["key.jwk"]);
    expect(result.stdout).toContain("result: valid");
    expect(result.stdout).toContain("ok   signature");
  });

  it("returns 1 for an invalid token and 0 again with --leeway", async () => {
    const late = { files: a1Files, clock: () => 1300819380 };
    const expired = await exec(a1Args, late);
    expect(expired.code).toBe(1);
    expect(expired.stdout).toContain("FAIL exp");
    expect(expired.stdout).toContain("result: invalid");
    const tolerant = await exec([...a1Args, "--leeway", "1"], late);
    expect(tolerant.code).toBe(0);
  });

  it("accepts a stdin token ending in a newline", async () => {
    const args = ["verify", "-", "--key", "key.jwk", "--alg", "HS256"];
    expect((await exec(args, { files: a1Files, stdin: `${h.A1_TOKEN}\n` })).code).toBe(0);
    expect((await exec(args, { files: a1Files, stdin: `${h.A1_TOKEN}\r\n` })).code).toBe(0);
  });

  it("never calls fetch and never prints the signature or key material", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const runs = [
      await exec(a1Args, { files: a1Files }),
      await exec(a1Args, { files: a1Files, clock: () => 1300819380 }),
      await exec(["inspect", h.A1_TOKEN]),
      await exec(["verify", h.A1_TOKEN, "--key", "key.jwk", "--alg", "RS256"], {
        files: a1Files,
      }),
    ];
    expect(fetchSpy).not.toHaveBeenCalled();
    for (const run of runs) {
      const output = `${run.stdout}${run.stderr}`;
      expect(output).not.toContain(h.A1_SIGNATURE);
      expect(output).not.toContain(h.A1_KEY);
      expect(output).not.toContain(h.A1_TOKEN);
    }
  });

  it("checks issuer and audience expectations", async () => {
    const base = { files: a1Files };
    expect((await exec([...a1Args, "--iss", "joe"], base)).code).toBe(0);
    expect((await exec([...a1Args, "--iss", "mallory"], base)).code).toBe(1);
    expect((await exec([...a1Args, "--aud", "x"], base)).code).toBe(1);
  });

  it("verifies with a PEM key file and an allowlist of several algorithms", async () => {
    const pair = await h.rsaKeyPair("RSASSA-PKCS1-v1_5", "SHA-256", 2048);
    const token = await h.signToken(
      { alg: "RS256" },
      {},
      h.keySigner(pair.privateKey, { name: "RSASSA-PKCS1-v1_5" }),
    );
    const pem = `${await h.publicPem(pair)}\n`;
    const result = await exec(["verify", token, "--key", "pub.pem", "--alg", "RS256,ES256"], {
      files: { "pub.pem": pem },
    });
    expect(result.code).toBe(0);
    expect(`${result.stdout}${result.stderr}`).not.toContain("BEGIN PUBLIC KEY");
  });

  it("verifies with a raw secret file ending in a newline", async () => {
    const token = await h.signToken({ alg: "HS256" }, {}, await h.hmacSigner("a".repeat(32)));
    const args = ["verify", token, "--key", "s.txt", "--alg", "HS256"];
    const result = await exec(args, { files: { "s.txt": `${"a".repeat(32)}\n` } });
    expect(result.code).toBe(0);
  });

  it("reports an invalid token for alg none and an oversize key file", async () => {
    const none = await exec(
      ["verify", h.fakeToken({ alg: "none" }), "--key", "key.jwk", "--alg", "HS256"],
      { files: a1Files },
    );
    expect(none.code).toBe(1);
    const big = await exec(a1Args, { files: { "key.jwk": "a".repeat(16_385) } });
    expect(big.code).toBe(1);
    expect(big.stdout).toContain("FAIL key");
    const weak = await exec(
      [
        "verify",
        await h.signToken({ alg: "HS256" }, {}, await h.hmacSigner(secret)),
        "--key",
        "key.jwk",
        "--alg",
        "HS256",
      ],
      { files: a1Files },
    );
    expect(weak.code).toBe(1);
  });

  it("uses the system clock when io.now is absent", async () => {
    const result = await exec(a1Args, { files: a1Files, now: false });
    expect(result.code).toBe(1);
    expect(result.stdout).toContain("FAIL exp");
  });

  it("returns 2 for format errors", async () => {
    const shortToken = ["verify", "a.b", "--key", "key.jwk", "--alg", "HS256"];
    const result = await exec(shortToken, { files: a1Files });
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("format");
    expect(result.stdout).toBe("");
  });

  const usageCases: Array<[string, string[], ExecOptions]> = [
    ["no arguments", [], {}],
    ["an unknown command", ["sign", "x"], {}],
    ["an unknown option", [...a1Args, "--other", "1"], { files: a1Files }],
    ["an option without a value", ["verify", h.A1_TOKEN, "--key"], {}],
    ["a missing --key", ["verify", h.A1_TOKEN, "--alg", "HS256"], {}],
    ["a missing --alg", ["verify", h.A1_TOKEN, "--key", "key.jwk"], { files: a1Files }],
    [
      "alg none in --alg",
      ["verify", h.A1_TOKEN, "--key", "key.jwk", "--alg", "none"],
      { files: a1Files },
    ],
    ["a text leeway", [...a1Args, "--leeway", "abc"], { files: a1Files }],
    ["an empty leeway", [...a1Args, "--leeway", ""], { files: a1Files }],
    ["a leeway of 301", [...a1Args, "--leeway", "301"], { files: a1Files }],
    ["two tokens", ["verify", h.A1_TOKEN, h.A1_TOKEN], {}],
    ["no token", ["verify"], {}],
    [
      "stdin without a reader",
      ["verify", "-", "--key", "key.jwk", "--alg", "HS256"],
      { files: a1Files },
    ],
    ["an unreadable key file", a1Args, {}],
    ["a malformed JSON key file", a1Args, { files: { "key.jwk": "{not json" } }],
  ];
  it.each(usageCases)("returns 2 for %s", async (_name, args, options) => {
    const result = await exec(args, options);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("error:");
    expect(result.stdout).toBe("");
  });
});

describe("cli inspect and help", () => {
  it("inspects a token argument and a stdin token", async () => {
    const direct = await exec(["inspect", h.A1_TOKEN]);
    expect(direct.code).toBe(0);
    expect(direct.stdout).toContain("Algorithm: HS256");
    expect(direct.stdout).toContain("Seconds to expiry: 1");
    const piped = await exec(["inspect", "-"], { stdin: `${h.A1_TOKEN}\n` });
    expect(piped.code).toBe(0);
    expect(piped.stdout).not.toContain(h.A1_SIGNATURE);
  });

  it("returns 2 for bad tokens, options and a failing stdin", async () => {
    expect((await exec(["inspect", "a.b"])).code).toBe(2);
    expect((await exec(["inspect", ` ${h.A1_TOKEN}`])).code).toBe(2);
    expect((await exec(["inspect", h.A1_TOKEN, "--iss", "x"])).code).toBe(2);
    const io: cli.CliIo = {
      stdout: () => undefined,
      stderr: () => undefined,
      readFile: () => Promise.resolve(""),
      stdin: () => Promise.reject(new Error("closed")),
    };
    expect(await cli.run(["inspect", "-"], io)).toBe(2);
  });

  it("reports unexpected errors without leaking them", async () => {
    const result = await exec(["inspect", h.A1_TOKEN], {
      clock: () => {
        throw new Error("boom with details");
      },
    });
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("unexpected error");
    expect(result.stderr).not.toContain("details");
  });

  it("prints usage for --help", async () => {
    const result = await exec(["--help"]);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("usage:");
    expect((await exec(["-h"])).code).toBe(0);
  });
});
