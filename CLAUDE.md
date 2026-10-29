# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status
Milestones 1–4 are done: core, detectors, SDK and CLI, all tested. Next: **M5 – one AI-provider adapter** (`packages/middleware` doesn't exist yet). P1 detectors (phone, payment card) aren't built yet.

## What Scrappy is
Scrappy is a local-first TypeScript library. It finds sensitive values (credentials, PII, custom identifiers) in text or JSON headed for an AI provider and replaces them with typed placeholders such as `[EMAIL_1]`, so the AI still gets useful context. It is developer-first: an SDK, a CLI and AI-client middleware, all built on one core engine.

**Defining security property:** Scrappy never needs to send unsanitized input anywhere in order to protect it. Detection is deterministic and local, with no network calls or LLM calls in the detection path.

## Stack
- TypeScript, ESM-only packages with explicit `exports` fields (internal modules stay private)
- Node.js ≥ 22.18, which runs `.ts` files directly through type stripping, so the code is limited to erasable syntax: no enums, namespaces or parameter properties. TypeScript 7 (`tsc` is the native compiler).
- Relative imports use `.ts` extensions. `tsc` rewrites them to `.js` in `dist/`.
- Each package's `exports` has a `source` condition that points at `src/index.ts`. Tests and dev runs pass `--conditions=source`, so they need no build. Published consumers get `dist/`.
- pnpm workspace monorepo. No Nx, database, server, Redis or queues.

## Commands
- `pnpm install`
- `pnpm build`: runs `tsc -b`. This type-checks and builds every package (project references). Test files aren't part of the build.
- `pnpm typecheck`: runs the build, then type-checks the test files (`tsconfig.test.json`). `node --test` strips types without checking them, so run this before calling anything done.
- `pnpm test`: runs every test with Node's built-in `node:test` runner, no build needed.
- Single file: `node --conditions=source --test packages/core/test/session.test.ts`
- Single test: add `--test-name-pattern="dispose"`
- Run the CLI from source: `echo "a@b.io" | node --conditions=source apps/cli/src/main.ts sanitize`. The built bin is `apps/cli/dist/main.js`.

## Architecture
Pipeline (in `@scrappy/core`):
validate input/size → run detectors → collect candidate spans → validate/normalize → resolve overlaps → apply policy → redact → build `{ text, findings, stats }`

Packages:
- `packages/core`: orchestration, public types, span validation, conflict resolution, redaction, restoration, errors. It has **no** dependency on AI providers, the network or any framework. Policy logic stays here until a separate package is clearly worth it.
- `packages/detectors`: each detector implements `Detector { id, supportedTypes, detect(input): CandidateMatch[] }`. Detectors only return spans into the original input and never modify text. Core attaches the detector id itself, so `CandidateMatch` carries no `detector` field. `supportedTypes` is enforced in two ways. A detector whose types are all disabled by the policy is skipped. A candidate with an undeclared type is a `DETECTOR_FAILED` error, so the call fails closed.
- `packages/sdk`: the ergonomic API (`sanitize`, `createSession`, `sanitizeJson`). It wraps core and never adds a second detection engine.
- `apps/cli`: consumes the SDK and handles args, stdin/stdout, files, config validation and exit codes.
- `packages/middleware`: thin wrappers around an existing AI client, with provider-specific code in adapters. Start with one provider.
- `tests/fixtures`, `tests/adversarial`, `tests/integration`: shared corpora, plus precision and recall measured separately for each detector.

Detection, policy, transformation and provider integration are separate responsibilities. Keep them that way.

## Invariants (do not break)
- **Offsets:** half-open `[start, end)`, measured in JavaScript UTF-16 code units, always relative to the *original* input. Build the output from sorted spans (or replace right-to-left). Never re-apply original offsets to a string that has already been modified.
- **Overlaps:** resolved deterministically in `packages/core/src/policy.ts`. Invalid or disallowed spans are dropped first. Among overlapping spans the winner is the one with higher confidence, then the longer span, then the earlier start, then the detector id. **Confidence is the precedence**, so a specific detector (JWT 0.95) must score above a generic one (bearer 0.85). Likewise, URL credentials (0.95) score above email (0.9).
- **Detectors stay linear:** each regex starts at a literal or a boundary lookbehind, or the scan is done by hand (`email.ts`, `privateKeyDetector`). Add every new detector to the 1 MB adversarial test in `packages/detectors/test/detectors.test.ts`.
- **No leakage:** `Finding` never contains the matched original value. Original input and reversible mappings never appear in logs, error messages, telemetry, debug output, temp files or crash reports.
- **Irreversible is the default.** Reversible mode needs explicit opt-in at the API, CLI and middleware boundaries alike.
- **Reversible sessions:** the mapping lives only in the session's private memory and is never in the result or on disk. `dispose()` invalidates it. There is no global or shared mapping across requests, users or tenants. Placeholder consistency is keyed by a per-session HMAC, so irreversible sessions never hold original values.
- **Restore** is a separate, explicit call. It only replaces exact placeholders that this session issued and leaves unknown or malformed ones unchanged. It honors `allowedTypes` and `maxRestorations`, and it is unavailable in irreversible mode.
- **Consistency:** the same value always gets the same placeholder within an input, and within a session if one is used.
- **JSON:** walk string values recursively. Never stringify the payload and run regex over it. Never mutate the caller's object, and keep the types of unaffected values. Object keys and numbers are scanned too: a sensitive number becomes a placeholder string. Findings carry paths such as `$.customer.email`, built from the sanitized keys.
- **Middleware fails closed:** if sanitization fails, the request is not sent. Retry and fallback paths must not forward unsanitized content, provider errors are sanitized before they reach the app, and unsupported request fields are documented rather than assumed safe.
- **Bounded resources:** enforce input size limits and avoid regexes with catastrophic backtracking. Adversarial tests cover this.
- Don't hard-code country- or bank-specific account formats. Account and custom identifiers are configured by the user. Person-name and address detection (NER) is P2 and must not be presented as reliable.
- Tests never call a real AI provider or send data over the network.

## CLI contract
- stdout carries only sanitized content, so it is safe to pipe. stderr carries only safe diagnostics.
- Exit codes: `0` success, `1` input, config or processing error, `2` invalid usage.
- Input files are never overwritten by default, and config is validated before processing.
- `scrappy inspect` reports types, offsets and counts, never the matched values.
- The CLI has no reversible mode: a mapping that lives only for one process is useless there.

## Detector priorities
- **P0:** email, API keys and access tokens, private keys, passwords in assignments
- **P1:** phone, payment card (Luhn), JWT, configurable account numbers
- **P2:** names and addresses (optional local NER), custom identifiers

## Roadmap
1. Workspace, public types, detector and policy contracts, error model
2. Email and credential detectors, overlap resolution, stable placeholders, irreversible redaction
3. Reversible sessions, restore, `sanitizeJson`, isolation and leakage tests
4. SDK entry points and CLI
5. One AI-provider adapter covering error and retry paths
6. Hardening: adversarial tests, performance, docs, first release with known limitations
