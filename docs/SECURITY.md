# Security

This document is the threat model of `@trysac/jwt-inspector`. Vulnerabilities are reported as described in the
repository-level `SECURITY.md`.

## Scope

The library decodes, inspects and verifies JSON Web Tokens (RFC 7519) in compact JWS form (RFC 7515) on the local
machine, using only WebCrypto (`crypto.subtle`). It follows the practices of RFC 8725. It performs no network access:
there is no JWKS fetching, no key discovery and no telemetry.

## Threat model

| Threat | Defence | Test |
|---|---|---|
| `alg: none` and unsigned tokens accepted | The `alg` check fails for any header `alg` equal to `none` in any letter case, for every allowlist. `none` cannot be placed in the allowlist (`invalid_options`). No signature check runs afterwards. | `fails the alg check for alg none with any allowlist` |
| Algorithm confusion (RSA public key used as an HMAC secret, RFC 8725 section 2.1 and 3.1) | Keys are bound to the algorithm family. HMAC algorithms accept only an `oct` JWK or a raw string; strings containing `-----BEGIN` are never HMAC secrets. RS, PS and ES algorithms accept only public RSA or EC keys with a matching curve. A JWK `alg` must equal the header `alg`. | `rejects an RS256 public PEM used as an HS256 secret`, `rejects a JWK with alg RS256 used for an RS384 header`, `rejects keys of the wrong family or shape` |
| Weak keys | HMAC secrets must be at least the hash size (RFC 7518 section 3.2). RSA moduli must be 2048 to 8192 bits and are measured before import. The EC curve must match the algorithm. | `enforces the HMAC secret size per hash`, `rejects weak, oversize and malformed RSA keys before import` |
| Private keys pasted as verification keys | A JWK with `d` (or any other private member) and any `PRIVATE KEY` PEM fail the `key` check. `crypto.subtle.importKey` is never called for them. | `never imports private keys` |
| Resource exhaustion | Tokens and key inputs are limited to 16 384 characters (`too_large`, or a failed check in `verifyJwt`). JSON nesting is limited to 32 levels. The algorithm allowlist holds at most 16 entries. Clock tolerance is capped at 300 seconds. | `enforces the 16_385 character limit`, `rejects oversize key input`, `rejects truncated SPKI documents without throwing` |
| Malleable or ambiguous encodings | Segments must be strict, canonical, unpadded base64url; the input is never trimmed; header and payload must be UTF-8 JSON objects; duplicate members keep the last value. | `rejects %s with code format` |
| Unsupported or dangerous header extensions | Any `crit` header fails the `crit` check (RFC 7515 section 4.1.11); the signature is not attempted. | `fails the crit check and skips the signature` |
| Output and network leaks | Check messages, warnings and `onEvent` events are fixed strings and never contain the token, the signature or key material. The CLI never prints the signature segment, the key or the token, reads keys only through the injected `readFile`, and never calls `fetch`. `formatInspection` omits the signature and escapes control characters. | `emits one {check, ok} event per check without token data`, `never calls fetch and never prints the signature or key material`, `renders text and neutralises control characters` |

## Behaviour worth knowing

- A token with a failed `alg`, `key` or `crit` check never reaches the signature check, but the claim checks are still
  reported so that one run lists every problem.
- `aud_not_checked` is a warning, not a failure, when the token has an `aud` claim and no audience was expected. A
  strict relying party (RFC 7519 section 4.1.3) must pass `audience`.
- `inspectJwt` and `decodeJwt` never verify anything; their output is untrusted data.
- The tolerance applies to `exp`, `nbf` and `iat` only.

## Out of scope

JWKS retrieval, JWE, EdDSA, ES512, token creation, key rotation policy and revocation are not provided. Verifying a
token proves integrity and the claims checked here; authorization decisions stay with the caller.
