# jwt-inspector

[![npm version](https://img.shields.io/npm/v/@trysac/jwt-inspector.svg)](https://www.npmjs.com/package/@trysac/jwt-inspector)
[![license: MIT](https://img.shields.io/npm/l/@trysac/jwt-inspector.svg)](LICENSE)
[![CI](https://github.com/Trysac/u067-jwt-inspector/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u067-jwt-inspector/actions/workflows/ci.yml)

Inspect and verify JWTs locally with WebCrypto per RFC 7519, 7515 and 8725: explicit algorithm allowlist, key binding and a per-check report

## Problem

Developers paste production tokens into public websites to debug them, exposing live credentials. Many libraries
either verify or throw without saying which check failed, and permissive ones accept `alg: none` or algorithm
confusion. This tool inspects and verifies JWTs locally with WebCrypto, with an explicit algorithm allowlist bound
to the key type, a per-check report and no network access.

## Install

```sh
npm install @trysac/jwt-inspector
```

Requires Node.js 22 or newer. The package ships ES modules with TypeScript declarations.

## Usage

```ts
import { verifyJwt } from "@trysac/jwt-inspector";

const result = await verifyJwt(token, {
  key: { kty: "oct", k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow" },
  algorithms: ["HS256"],
  now: () => 1300819379,
});
console.log(result.valid); // true
console.log(result.checks); // [{ name: "format", ok: true, message: "..." }, { name: "alg", ... }, ...]
```

## API

| Export | Signature | Description |
|---|---|---|
| `decodeJwt` | `(token: string) => DecodedJwt` | Strict decode of header, payload and signature; throws `JwtError`. |
| `verifyJwt` | `(token, options: VerifyOptions) => Promise<VerifyResult>` | Per-check verification (format, alg, key, crit, signature, exp, nbf, iat, iss, aud); throws only `invalid_options`. |
| `inspectJwt` | `(token: string, now: number) => Inspection` | Header, payload, algorithm, key id, ISO times and warnings. |
| `formatInspection` | `(inspection, "text" \| "json") => string` | Renders an inspection without the signature. |
| `JwtError` | `class extends Error` | Has `code`: `format`, `too_large` or `invalid_options`. |

## CLI

```sh
jwt-inspector inspect <token|->
jwt-inspector verify <token|-> --key <file> --alg RS256[,ES256] [--iss X] [--aud Y] [--leeway S]
```

A token of `-` is read from standard input. Exit codes: `0` valid, `1` invalid, `2` format or usage error.

## Development

```sh
npm install
npm run check   # lint, format, types, tests with coverage, docs, secrets
```

See [AGENTS.md](AGENTS.md) for the full command list and [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## License

[MIT](LICENSE) © 2026 Miguel Gomez
