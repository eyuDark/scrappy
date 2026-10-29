import type { CandidateMatch, Detector } from "@scrappy/core";
import { createPatternDetector } from "./pattern.ts";

// Every pattern starts with a literal or a boundary lookbehind, so a failed attempt can't rescan the same run.

export const jwtDetector = createPatternDetector({
  id: "jwt",
  type: "JWT",
  confidence: 0.95,
  pattern: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/,
});

export const apiKeyDetector = createPatternDetector({
  id: "api-key",
  type: "API_KEY",
  confidence: 0.9,
  pattern: new RegExp(
    "(?<![A-Za-z0-9_-])(?:" +
      [
        "sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}", // Anthropic, OpenAI
        "gh[pousr]_[A-Za-z0-9]{36,}", // GitHub
        "github_pat_[A-Za-z0-9_]{22,}",
        "glpat-[A-Za-z0-9_-]{20,}", // GitLab
        "xox[abprs]-[A-Za-z0-9-]{10,}", // Slack
        "AKIA[0-9A-Z]{16}(?![0-9A-Z])", // AWS access key id
        "AIza[0-9A-Za-z_-]{35}", // Google
        "[rs]k_(?:live|test)_[A-Za-z0-9]{16,}", // Stripe
      ].join("|") +
      ")",
  ),
});

export const bearerTokenDetector = createPatternDetector({
  id: "bearer-token",
  type: "ACCESS_TOKEN",
  confidence: 0.85,
  pattern: /(?<![A-Za-z0-9_-])[Bb]earer[ \t]+(?<value>[A-Za-z0-9._~+/=-]{16,})/,
});

/** The password part of `scheme://user:password@host`. Outranks the email detector on `password@host`. */
export const urlCredentialsDetector = createPatternDetector({
  id: "url-credentials",
  type: "PASSWORD",
  confidence: 0.95,
  pattern: /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,30}:\/\/[^\s/:@]+:(?<value>[^\s/@]+)@/,
});

const ASSIGNMENT =
  /(?<![A-Za-z0-9])(?:password|passwd|pwd|pass|secret|client[_-]?secret|api[_-]?key|access[_-]?token|auth[_-]?token|token)["']?[ \t]*[:=][ \t]*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s"',;&}]+))/dgi;
const PLACEHOLDER = /^\[[A-Z_]+_\d+\]$/;

/** Values assigned to secret-looking keys: `password=...`, `"api_key": "..."`, `DB_PASSWORD: ...`. */
export const passwordAssignmentDetector: Detector = {
  id: "password-assignment",
  supportedTypes: ["PASSWORD"],
  detect(input) {
    const out: CandidateMatch[] = [];
    for (const m of input.matchAll(ASSIGNMENT)) {
      const group = [1, 2, 3].find((g) => m[g] !== undefined);
      const span = group && m.indices?.[group];
      if (!span || PLACEHOLDER.test(m[group]!)) continue;
      out.push({ type: "PASSWORD", start: span[0], end: span[1], confidence: 0.8 });
    }
    return out;
  },
};

const PEM_BEGIN = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/g;
const PEM_END = /-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/g;

/** PEM/PGP private key blocks. A block with no END line is redacted to the end of the input. */
export const privateKeyDetector: Detector = {
  id: "private-key",
  supportedTypes: ["PRIVATE_KEY"],
  detect(input) {
    const out: CandidateMatch[] = [];
    const begin = new RegExp(PEM_BEGIN);
    const end = new RegExp(PEM_END);
    for (let b = begin.exec(input); b; b = begin.exec(input)) {
      end.lastIndex = begin.lastIndex;
      const e = end.exec(input);
      // Truncated keys are still secret; with no END left, no later block can close either.
      out.push({ type: "PRIVATE_KEY", start: b.index, end: e ? end.lastIndex : input.length, confidence: 0.99 });
      if (!e) break;
      begin.lastIndex = end.lastIndex;
    }
    return out;
  },
};

/**
 * Random-looking tokens with no known prefix: 24+ chars mixing upper, lower and digits, with a digit
 * before the end (identifiers end in "2024"/"V2"), and mostly NOT made of words. Identifiers and URL
 * paths are built from words (Cipher, Poly, Reference); random tokens rarely hold 3 lowercase letters
 * in a row. Hex hashes and UUIDs have no uppercase. Low confidence, so known detectors win overlaps.
 */
export const unknownTokenDetector = createPatternDetector({
  id: "unknown-token",
  type: "SECRET",
  confidence: 0.6,
  pattern: /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/_=-])/,
  validate(value) {
    const token = value.replace(/=+$/, "");
    if (!/[a-z]/.test(token) || !/[A-Z]/.test(token) || !/\d/.test(token.replace(/\d+$/, ""))) return false;
    const wordChars = (token.match(/[A-Z]?[a-z]{3,}/g) ?? []).join("").length;
    return wordChars / token.length < 0.5;
  },
});
