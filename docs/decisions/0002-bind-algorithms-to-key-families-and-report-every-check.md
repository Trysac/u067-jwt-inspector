# Bind algorithms to key families and report every check

Status: accepted (generated, pending human review)

## Context

Developers debug production tokens on public websites, and common JWT libraries either throw one generic error or accept alg none and algorithm confusion. The library must run locally with WebCrypto only, tell the user which check failed and never import unsafe keys.

## Decision

verifyJwt takes an explicit algorithm allowlist and binds each algorithm to one key family (oct for HS, public RSA for RS and PS, public EC with the matching curve for ES). Key rules (private-member rejection, minimum HMAC size, RSA modulus measured from the DER or JWK before import, JWK alg equality) run before crypto.subtle.importKey, and verification uses only crypto.subtle.verify. The result is an ordered list of named checks; token defects are failed checks and only invalid options throw. The CLI is a thin function with injected I/O.

## Consequences

Misconfiguration and attacks surface as named failed checks and no unsafe key reaches WebCrypto. Callers must pass a non-empty allowlist and keys of the right type, so keys shared across families are refused by design. PEM input is limited to SPKI, base64url is strictly canonical, and JWKS, JWE, EdDSA, ES512 and token creation are unsupported.
