# Project record: jwt-inspector

## Objective

Inspect and verify JWTs locally with WebCrypto per RFC 7519, 7515 and 8725: explicit algorithm allowlist, key binding and a per-check report

Let developers debug JWTs locally, with a per-check report, instead of pasting live tokens into public websites.

## Scope

In scope:

- The public API documented in the README.

Out of scope:

- JWKS fetching, JWE, EdDSA, ES512 and token creation.

## Timeline

| Date | Milestone |
|---|---|
| 2026 | Repository created; API and CLI implemented. |

## Effort metrics

Measured values only. Leave "pending measurement" until a real figure is recorded; never estimate here.

| Metric | Value | Source |
|---|---|---|
| Tokens (input / output) | 370665 / 120882 | factory ledger |
| Hours (human) | pending measurement | time log |
| Cost (USD) | 0.8539 | factory ledger |

## Factory run u067 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 2496 | 101244 | 4473 | 0 | 0.5177 |
| fix-1 | claude-sonnet-5-5 | no | 10 | 1292 | 8257 | 72242 | 0.0408 |
| audit | claude-sonnet-5-5 | no | 12 | 5084 | 52561 | 153928 | 0.1977 |
| fix-2 | claude-sonnet-5-5 | no | 12 | 4409 | 14007 | 102314 | 0.0894 |
| docs | claude-haiku-5-5 | no | 39651 | 8853 | 0 | 0 | 0.0084 |

Total: $0.8539. Prices: Anthropic list prices.
