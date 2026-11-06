# jwt-inspector

[![npm version](https://img.shields.io/npm/v/@trysac/jwt-inspector.svg)](https://www.npmjs.com/package/@trysac/jwt-inspector)
[![license: MIT](https://img.shields.io/npm/l/@trysac/jwt-inspector.svg)](LICENSE)
[![CI](https://github.com/Trysac/u067-jwt-inspector/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u067-jwt-inspector/actions/workflows/ci.yml)

Inspect and verify JWTs locally with WebCrypto per RFC 7519, 7515 and 8725: explicit algorithm allowlist, key binding and a per-check report

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and why existing
packages do not solve it well. Keep it factual; link to an issue or decision record when there is one.

## Install

```sh
npm install @trysac/jwt-inspector
```

Requires Node.js 20 or newer. The package ships ES modules with TypeScript declarations.

## Usage

```ts
import { greet } from "@trysac/jwt-inspector";

// Build a greeting; surrounding whitespace is ignored.
const message = greet("  Ada ");
console.log(message); // "Hello, Ada!"

try {
  greet("   ");
} catch (error) {
  console.error((error as Error).message); // "name must not be empty"
}
```

## API

| Export | Signature | Description |
|---|---|---|
| `greet` | `(name: string) => string` | Placeholder API; replace it with the real one. |

## Development

```sh
npm install
npm run check   # lint, format, types, tests with coverage, docs, secrets
```

See [AGENTS.md](AGENTS.md) for the full command list and [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## License

[MIT](LICENSE) © 2026 Miguel Gomez
