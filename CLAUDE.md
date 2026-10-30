# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status
The CLI is published on npm as `scrappy-redact` (command: `scrappy`); 0.1.0 and 0.2.0 are live. 0.3.0 (opt-in IP masking, help, config) is live. **0.3.1** (security fix: credentials always win overlaps) is built, awaiting review. The GitHub repo is public at https://github.com/eyuDark/scrappy, with releases tagged `vX.Y.Z`. The npm account `eyud` has 2FA (auth-and-writes) set up with a security key, so publishing must be run by the user in a real terminal: `npm publish <tarball from pnpm pack>`. AI-provider middleware (M5) is deferred. Names and addresses (P2) aren't built.

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
- `pnpm install` (pnpm 11; `allowBuilds` in `pnpm-workspace.yaml` deliberately skips esbuild's install script)
- `pnpm build`: runs `tsc -b`. This type-checks and builds every package (project references). Test files aren't part of the build.
- `pnpm typecheck`: runs the build, then type-checks the test files (`tsconfig.test.json`). `node --test` strips types without checking them, so run this before calling anything done.
- `pnpm test`: runs every test with Node's built-in `node:test` runner, no build needed.
- Single file: `node --conditions=source --test packages/core/test/session.test.ts`
- Single test: add `--test-name-pattern="dispose"`
- Run the CLI from source: `echo "a@b.io" | node --conditions=source apps/cli/src/main.ts sanitize`.
- `pnpm --filter scrappy-redact bundle`: esbuild bundles the CLI and all workspace packages into one dependency-free file, `apps/cli/dist/scrappy.js`. That file is the published artifact. `tsc` output in `dist/` is only a side effect of type-checking.
- `pnpm --filter scrappy-redact pack`: `prepack` copies the root `README.md` and `LICENSE` into `apps/cli/` (gitignored there), then bundles. Publish with `pnpm publish`, never `npm publish`: pnpm rewrites the `workspace:` ranges. `apps/cli/test/package.test.ts` packs, installs offline and runs the tarball.

## Architecture
Pipeline (in `@scrappy/core`):
validate input/size → run detectors → collect candidate spans → validate/normalize → resolve overlaps → apply policy → redact → build `{ text, findings, stats }`

Packages:
- `packages/core`: orchestration, public types, span validation, conflict resolution, redaction, restoration, errors. It has **no** dependency on AI providers, the network or any framework. Policy logic stays here until a separate package is clearly worth it.
- `packages/detectors`: each detector implements `Detector { id, supportedTypes, detect(input): CandidateMatch[] }`. Detectors only return spans into the original input and never modify text. Core attaches the detector id itself, so `CandidateMatch` carries no `detector` field. `supportedTypes` is enforced in two ways. A detector whose types are all disabled by the policy is skipped. A candidate with an undeclared type is a `DETECTOR_FAILED` error, so the call fails closed.
- `packages/sdk`: the ergonomic API (`sanitize`, `createSession`, `sanitizeJson`). It wraps core and never adds a second detection engine.
- `apps/cli`: the published package `scrappy-redact`. It consumes the SDK as a devDependency (bundled in) and handles args, stdin/stdout, files, config validation and exit codes. `clipboard.ts` is the OS clipboard adapter. It tries an ordered list of tools for each platform: overrides `SCRAPPY_PASTE_CMD`/`SCRAPPY_COPY_CMD`; macOS pbpaste/pbcopy; Windows PowerShell; WSL Windows clipboard first; Linux Wayland: wl-clipboard, xclip, xsel; X11: xclip, xsel, wl-clipboard. If none work, it **always** falls back to `terminal.ts`: paste into the terminal plus Ctrl-D (raw mode, so long lines aren't cut at the ~4 KB tty limit). The result is printed to stdout, and OSC 52 is sent only to a real TTY. `terminal.ts`'s `inputReader` is the single stdin reader shared by session keys and pastes. Adapter tests drive `systemClipboard({ platform, env })` with fake tools on a temp PATH. CLI tests use an empty PATH for the "no tools" case. `session.ts` is the interactive `scrappy session`. `settings.ts` holds saved preferences in `$XDG_CONFIG_HOME/scrappy/config.json` (default `~/.config/scrappy/config.json`; `%APPDATA%` on Windows). It contains only `{ "ipMasking": bool }`, never input. CLI tests set `XDG_CONFIG_HOME` to a temp dir so the developer's own settings can't change results. `errors.ts` has `CliError`, the only error type whose message gets printed.
- `packages/middleware`: thin wrappers around an existing AI client, with provider-specific code in adapters. Start with one provider.
- `packages/sdk/test/corpus/`: realistic labeled samples (`[[TYPE|value]]` inline; `@fake:<prefix>:<n>` generates key-shaped values at runtime so GitHub secret scanning never sees one). `corpus.test.ts` runs them through `sanitize` with the default detectors and fails if any type's recall drops below its floor (100%, except PHONE 90% and SECRET 80%) or if there are more than 2 false positives. Add a sample there whenever a detector misses something real.

Detection, policy, transformation and provider integration are separate responsibilities. Keep them that way.

## Invariants (do not break)
- **Offsets:** half-open `[start, end)`, measured in JavaScript UTF-16 code units, always relative to the *original* input. Build the output from sorted spans (or replace right-to-left). Never re-apply original offsets to a string that has already been modified.
- **Overlaps:** resolved deterministically in `packages/core/src/policy.ts`. Invalid or disallowed spans are dropped first. Among overlapping spans, **credential types (PASSWORD, API_KEY, ACCESS_TOKEN, JWT, PRIVATE_KEY, SECRET) always beat non-credential types** (IP, phone, card, email…), whatever the confidence. Otherwise the loser is dropped whole, and an IP inside `password=10.0.0.1:hunter2` would leave `:hunter2` in plaintext (security review, fixed in 0.3.1). Between two credentials the **longer span wins** (then confidence), so e.g. `token=<JWT>.tail` is redacted whole. Between non-credentials: higher confidence, then the longer span. Ties: earlier start, then detector id. For equal spans confidence picks the label, so a specific detector (JWT 0.95) must score above a generic one (bearer 0.85).
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
- Reversible mode exists only in `scrappy session`. The mapping lives in that process's memory and is discarded on quit. The session prints counts and types, never values. Restored values go only to the clipboard.
- `--clipboard` writes sanitized output back to the clipboard and prints a summary to stderr, so stdout stays empty.
- IP masking (`IP_ADDRESS`) is opt-in: `ipAddressDetector` is exported but not in `defaultDetectors`. The CLI adds it for `--ip` or when the saved `ipMasking` setting is on. Candidates come from a regex; `node:net` `isIPv4`/`isIPv6` decide.
- `scrappy`, `scrappy help`, `--help` and `-h` all print the same help page (exit 0). Usage errors print one line plus a pointer to `scrappy help` (exit 2). `--version` is checked before help.

## Detector priorities
- **Done:** email, API keys and access tokens, private keys, passwords in assignments, JWT, payment cards (structure + issuer prefix + Luhn), phones (country-agnostic: `+` international, or a number within 20 chars after a phone keyword), unknown tokens (`SECRET`).
- **Opt-in:** IP addresses (IPv4/IPv6 via `node:net`), confidence 0.85.
- **Not built:** names and addresses (optional local NER). Account numbers stay user-configured through `customDetectors`.
- **Confidence ladder** (precedence within a tier; credentials outrank everything else first): private key 0.99 > JWT, URL credentials 0.95 > API key, email, card 0.9 > bearer, international phone 0.85 > password assignment, keyword phone 0.8 > unknown token 0.6.
- **Unknown-token rules** (`secrets.ts`): 24+ chars of `[A-Za-z0-9+/_-]`, with upper, lower and a digit before the end, and less than half the token made of words (`[A-Z]?[a-z]{3,}`). Recall on random base62 is checked to stay at or above 95%. Known accepted false positives: base64 hashes, and URL fragments with ALL-CAPS words.

## Roadmap
1. Workspace, public types, detector and policy contracts, error model
2. Email and credential detectors, overlap resolution, stable placeholders, irreversible redaction
3. Reversible sessions, restore, `sanitizeJson`, isolation and leakage tests
4. SDK entry points and CLI
5. One AI-provider adapter covering error and retry paths
6. Hardening: adversarial tests, performance, docs, first release with known limitations
