/**
 * Command line front end. All I/O is injected through {@link CliIo}; this
 * module never touches the network.
 */
import * as jwt from "./index.js";

/** I/O capabilities used by {@link run}. */
export interface CliIo {
  stdout(text: string): void;
  stderr(text: string): void;
  stdin?: () => Promise<string>;
  readFile(path: string): Promise<string>;
  now?: () => number;
}

const MAX_KEY_FILE_CHARS = 16_384;
const VALUE_FLAGS = new Set(["--key", "--alg", "--iss", "--aud", "--leeway"]);
const USAGE = [
  "usage:",
  "  jwt-inspector inspect <token|->",
  "  jwt-inspector verify <token|-> --key <file> --alg RS256[,ES256] [--iss X] [--aud Y] [--leeway S]",
  "",
  "A token of - is read from standard input.",
].join("\n");

interface Parsed {
  readonly positionals: string[];
  readonly flags: Map<string, string>;
}

function parseArgs(argv: readonly string[]): Parsed | string {
  const flags = new Map<string, string>();
  const positionals: string[] = [];
  for (let i = 1; i < argv.length; i += 1) {
    const arg = argv[i] ?? "";
    if (arg.startsWith("--")) {
      if (!VALUE_FLAGS.has(arg)) {
        return "unknown option";
      }
      const value = argv[i + 1];
      if (value === undefined) {
        return `option ${arg} needs a value`;
      }
      flags.set(arg, value);
      i += 1;
    } else {
      positionals.push(arg);
    }
  }
  return { positionals, flags };
}

function usage(io: CliIo, message: string): number {
  io.stderr(`error: ${message}\n${USAGE}\n`);
  return 2;
}

function reportError(io: CliIo, error: unknown): number {
  const message =
    error instanceof jwt.JwtError ? `${error.code}: ${error.message}` : "unexpected error";
  io.stderr(`error: ${message}\n`);
  return 2;
}

async function readStdin(io: CliIo): Promise<string | null> {
  if (io.stdin === undefined) {
    return null;
  }
  try {
    return (await io.stdin()).trim();
  } catch {
    return null;
  }
}

function parseKey(text: string): jwt.JsonWebKey | string | null {
  if (text.length > MAX_KEY_FILE_CHARS) {
    // Passed through so that the library rejects it as a failed key check.
    return text;
  }
  const trimmed = text.trim();
  if (!trimmed.startsWith("{")) {
    return trimmed;
  }
  try {
    return JSON.parse(trimmed) as jwt.JsonWebKey;
  } catch {
    return null;
  }
}

function parseNumber(text: string): number | null {
  if (text.trim() === "") {
    return null;
  }
  const value = Number(text);
  return Number.isFinite(value) ? value : null;
}

function report(result: jwt.VerifyResult): string {
  const lines = result.checks.map((c) => `${c.ok ? "ok  " : "FAIL"} ${c.name}: ${c.message}`);
  for (const warning of result.warnings) {
    lines.push(`warning: ${warning}`);
  }
  lines.push(result.valid ? "result: valid" : "result: invalid");
  return `${lines.join("\n")}\n`;
}

function inspect(io: CliIo, parsed: Parsed, token: string): number {
  if (parsed.flags.size > 0) {
    return usage(io, "inspect takes no options");
  }
  try {
    const inspection = jwt.inspectJwt(token, io.now);
    io.stdout(`${jwt.formatInspection(inspection, "text")}\n`);
    return 0;
  } catch (error) {
    return reportError(io, error);
  }
}

async function verify(io: CliIo, parsed: Parsed, token: string): Promise<number> {
  const keyPath = parsed.flags.get("--key");
  const algs = parsed.flags.get("--alg");
  if (keyPath === undefined || algs === undefined) {
    return usage(io, "verify needs --key and --alg");
  }
  const leeway = parsed.flags.get("--leeway");
  const tolerance = leeway === undefined ? 0 : parseNumber(leeway);
  if (tolerance === null) {
    return usage(io, "--leeway must be a number of seconds");
  }
  let keyText: string;
  try {
    keyText = await io.readFile(keyPath);
  } catch {
    return usage(io, "cannot read the key file");
  }
  const key = parseKey(keyText);
  if (key === null) {
    return usage(io, "the key file is not valid JSON");
  }
  const issuer = parsed.flags.get("--iss");
  const audience = parsed.flags.get("--aud");
  const options: jwt.VerifyOptions = {
    key,
    algorithms: algs.split(",") as jwt.Alg[],
    clockToleranceSec: tolerance,
    ...(issuer === undefined ? {} : { issuer }),
    ...(audience === undefined ? {} : { audience }),
    ...(io.now === undefined ? {} : { now: io.now }),
  };
  let result: jwt.VerifyResult;
  try {
    result = await jwt.verifyJwt(token, options);
  } catch (error) {
    return reportError(io, error);
  }
  if (result.checks.some((c) => c.name === "format" && !c.ok)) {
    io.stderr("error: format: the token is not a well-formed JWT\n");
    return 2;
  }
  io.stdout(report(result));
  return result.valid ? 0 : 1;
}

/**
 * Runs the command line tool.
 *
 * @param argv - Arguments after the program name.
 * @param io - Injected I/O.
 * @returns 0 when valid, 1 when invalid, 2 on a format or usage error.
 */
export async function run(argv: string[], io: CliIo): Promise<number> {
  const command = argv[0];
  if (command === "--help" || command === "-h") {
    io.stdout(`${USAGE}\n`);
    return 0;
  }
  if (command !== "inspect" && command !== "verify") {
    return usage(io, "unknown or missing command");
  }
  const parsed = parseArgs(argv);
  if (typeof parsed === "string") {
    return usage(io, parsed);
  }
  const [raw] = parsed.positionals;
  if (raw === undefined || parsed.positionals.length !== 1) {
    return usage(io, "expected exactly one token argument");
  }
  const token = raw === "-" ? await readStdin(io) : raw;
  if (token === null) {
    return usage(io, "cannot read the token from standard input");
  }
  return command === "inspect" ? inspect(io, parsed, token) : verify(io, parsed, token);
}
