import { createHmac, randomBytes } from "node:crypto";
import { ScrappyError } from "./errors.ts";
import { sanitizeJsonValue } from "./json.ts";
import { isSensitiveType, resolveCandidates, resolvePolicy, type AttributedMatch } from "./policy.ts";
import type {
  CandidateMatch,
  Detector,
  Finding,
  RestoreOptions,
  RestoreResult,
  SanitizationSession,
  SanitizeJsonResult,
  SanitizeResult,
  SensitiveType,
  SessionOptions,
} from "./types.ts";

const PLACEHOLDER = /\[[A-Z_]+_\d+\]/g;

export function createSession(options: SessionOptions): SanitizationSession {
  if (typeof options !== "object" || options === null) throw new ScrappyError("INVALID_OPTIONS", "options");
  const { detectors, mode = "irreversible" } = options;
  const isDetector = (d: Detector) =>
    typeof d?.id === "string" && typeof d.detect === "function" && Array.isArray(d.supportedTypes) && d.supportedTypes.every(isSensitiveType);
  if (!Array.isArray(detectors) || !detectors.every(isDetector)) {
    throw new ScrappyError("INVALID_OPTIONS", "detectors");
  }
  if (mode !== "irreversible" && mode !== "reversible") throw new ScrappyError("INVALID_OPTIONS", "mode");
  const policy = resolvePolicy(options.policy);
  const activeDetectors = detectors.filter((d: Detector) => d.supportedTypes.some((t) => policy.enabledTypes.has(t)));

  // Values are keyed by a per-session HMAC, so irreversible sessions never hold originals.
  const secret = randomBytes(32);
  const placeholders = new Map<string, string>();
  const counters = new Map<SensitiveType, number>();
  const originals = mode === "reversible" ? new Map<string, { type: SensitiveType; value: string }>() : undefined;
  let disposed = false;

  const assertActive = () => {
    if (disposed) throw new ScrappyError("SESSION_DISPOSED");
  };

  const placeholderFor = (type: SensitiveType, value: string, literalsInInput: ReadonlySet<string>) => {
    const key = createHmac("sha256", secret).update(type).update("\0").update(value).digest("base64");
    let placeholder = placeholders.get(key);
    if (placeholder) return placeholder;
    let n = counters.get(type) ?? 0;
    // Skip numbers whose placeholder text already appears literally, so restore can't confuse them.
    do placeholder = `[${type}_${++n}]`;
    while (literalsInInput.has(placeholder));
    counters.set(type, n);
    placeholders.set(key, placeholder);
    originals?.set(placeholder, { type, value });
    return placeholder;
  };

  const sanitize = (input: string): SanitizeResult => {
    assertActive();
    if (typeof input !== "string") throw new ScrappyError("INVALID_INPUT");
    if (input.length > policy.maxInputLength) throw new ScrappyError("INPUT_TOO_LARGE");

    const candidates: AttributedMatch[] = [];
    for (const detector of activeDetectors) {
      let found: unknown;
      try {
        found = detector.detect(input);
      } catch {
        // Fail closed, and drop the cause: its message may quote the input.
        throw new ScrappyError("DETECTOR_FAILED", detector.id);
      }
      if (!Array.isArray(found)) throw new ScrappyError("DETECTOR_FAILED", detector.id);
      for (const c of found as CandidateMatch[]) {
        if (typeof c !== "object" || c === null || !detector.supportedTypes.includes(c.type)) throw new ScrappyError("DETECTOR_FAILED", detector.id);
        candidates.push({ ...c, detector: detector.id });
      }
    }

    const literals = new Set(input.match(PLACEHOLDER));
    const findings: Finding[] = [];
    let text = "";
    let last = 0;
    for (const span of resolveCandidates(input, candidates, policy)) {
      const replacement = placeholderFor(span.type, input.slice(span.start, span.end), literals);
      text += input.slice(last, span.start) + replacement;
      last = span.end;
      const { type, start, end, confidence, detector } = span;
      findings.push({ id: `f${findings.length + 1}`, type, start, end, confidence, detector, replacement });
    }
    text += input.slice(last);

    return { text, findings, stats: { inputLength: input.length, outputLength: text.length, findingCount: findings.length } };
  };

  const sanitizeJson = (value: unknown): SanitizeJsonResult => {
    assertActive();
    return sanitizeJsonValue(value, sanitize);
  };

  const restore = (text: string, restoreOptions: RestoreOptions = {}): RestoreResult => {
    assertActive();
    if (!originals) throw new ScrappyError("RESTORE_UNAVAILABLE");
    if (typeof text !== "string") throw new ScrappyError("INVALID_INPUT");
    const { allowedTypes, maxRestorations = Infinity } = restoreOptions;
    if (allowedTypes !== undefined && (!Array.isArray(allowedTypes) || !allowedTypes.every(isSensitiveType))) {
      throw new ScrappyError("INVALID_OPTIONS", "allowedTypes");
    }
    if (typeof maxRestorations !== "number" || !(maxRestorations >= 0)) throw new ScrappyError("INVALID_OPTIONS", "maxRestorations");

    const allowed = allowedTypes && new Set(allowedTypes);
    let restoredCount = 0;
    const restored = text.replace(PLACEHOLDER, (match) => {
      const original = originals.get(match);
      if (!original || (allowed && !allowed.has(original.type)) || restoredCount >= maxRestorations) return match;
      restoredCount++;
      return original.value;
    });
    return { text: restored, restoredCount };
  };

  const dispose = () => {
    disposed = true;
    placeholders.clear();
    counters.clear();
    originals?.clear();
    secret.fill(0);
  };

  return { mode, sanitize, sanitizeJson, restore, dispose };
}

/** One-shot, irreversible unless `mode` says otherwise; nothing is retained after the call. */
export function sanitize(input: string, options: SessionOptions): SanitizeResult {
  const session = createSession(options);
  try {
    return session.sanitize(input);
  } finally {
    session.dispose();
  }
}

export function sanitizeJson(value: unknown, options: SessionOptions): SanitizeJsonResult {
  const session = createSession(options);
  try {
    return session.sanitizeJson(value);
  } finally {
    session.dispose();
  }
}
