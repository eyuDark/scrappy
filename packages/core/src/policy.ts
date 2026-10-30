import { ScrappyError } from "./errors.ts";
import { SENSITIVE_TYPES, type CandidateMatch, type SanitizePolicy, type SensitiveType } from "./types.ts";

export const DEFAULT_MAX_INPUT_LENGTH = 1_000_000;
export const DEFAULT_MIN_CONFIDENCE = 0.5;

/** A candidate tagged by core with the id of the detector that produced it. */
export type AttributedMatch = CandidateMatch & { detector: string };

export interface ResolvedPolicy {
  enabledTypes: ReadonlySet<SensitiveType>;
  minConfidence: number;
  allowlist: ReadonlySet<string>;
  maxInputLength: number;
}

export function isSensitiveType(value: unknown): value is SensitiveType {
  return (SENSITIVE_TYPES as readonly unknown[]).includes(value);
}

export function resolvePolicy(policy: SanitizePolicy = {}): ResolvedPolicy {
  if (typeof policy !== "object" || policy === null) throw new ScrappyError("INVALID_OPTIONS", "policy");
  const { enabledTypes = SENSITIVE_TYPES, minConfidence = DEFAULT_MIN_CONFIDENCE, allowlist = [], maxInputLength = DEFAULT_MAX_INPUT_LENGTH } = policy;

  if (!Array.isArray(enabledTypes) || !enabledTypes.every(isSensitiveType)) {
    throw new ScrappyError("INVALID_OPTIONS", "policy.enabledTypes");
  }
  if (typeof minConfidence !== "number" || !(minConfidence >= 0 && minConfidence <= 1)) {
    throw new ScrappyError("INVALID_OPTIONS", "policy.minConfidence");
  }
  if (!Array.isArray(allowlist) || !allowlist.every((v) => typeof v === "string")) {
    throw new ScrappyError("INVALID_OPTIONS", "policy.allowlist");
  }
  if (!Number.isSafeInteger(maxInputLength) || maxInputLength <= 0) {
    throw new ScrappyError("INVALID_OPTIONS", "policy.maxInputLength");
  }
  return { enabledTypes: new Set(enabledTypes), minConfidence, allowlist: new Set(allowlist), maxInputLength };
}

/** Credentials outrank every other type in overlaps, so an IP or phone inside a password can't split it. */
const CREDENTIAL_TYPES: ReadonlySet<SensitiveType> = new Set(["PASSWORD", "API_KEY", "ACCESS_TOKEN", "JWT", "PRIVATE_KEY", "SECRET"]);
const tier = (c: AttributedMatch) => (CREDENTIAL_TYPES.has(c.type) ? 1 : 0);
const length = (c: AttributedMatch) => c.end - c.start;

const isHigh = (c: number) => c >= 0xd800 && c <= 0xdbff;
const isLow = (c: number) => c >= 0xdc00 && c <= 0xdfff;

/**
 * Drops invalid or disallowed spans, then picks non-overlapping winners deterministically. Credentials
 * beat other types; between two credentials the longer span wins (so no credential text stays visible),
 * otherwise higher confidence wins, then the longer span. Ties: earlier start, detector id, type.
 * Returns winners sorted by start.
 */
export function resolveCandidates(input: string, candidates: readonly AttributedMatch[], policy: ResolvedPolicy): AttributedMatch[] {
  const valid: AttributedMatch[] = [];
  for (const c of candidates) {
    if (!Number.isInteger(c.start) || !Number.isInteger(c.end) || c.start < 0 || c.end > input.length || c.start >= c.end) continue;
    if (!policy.enabledTypes.has(c.type) || !(c.confidence >= policy.minConfidence)) continue;
    let { start, end } = c;
    // Never split a surrogate pair: widen to the whole code point.
    if (start > 0 && isLow(input.charCodeAt(start)) && isHigh(input.charCodeAt(start - 1))) start--;
    if (end < input.length && isHigh(input.charCodeAt(end - 1)) && isLow(input.charCodeAt(end))) end++;
    if (policy.allowlist.has(input.slice(start, end))) continue;
    valid.push({ ...c, start, end });
  }

  valid.sort(
    (a, b) =>
      tier(b) - tier(a) ||
      (tier(a) === 1 ? length(b) - length(a) || b.confidence - a.confidence : b.confidence - a.confidence || length(b) - length(a)) ||
      a.start - b.start ||
      compare(a.detector, b.detector) ||
      compare(a.type, b.type),
  );

  const taken = new Uint8Array(input.length);
  const winners: AttributedMatch[] = [];
  for (const c of valid) {
    if (taken.subarray(c.start, c.end).includes(1)) continue;
    taken.fill(1, c.start, c.end);
    winners.push(c);
  }
  return winners.sort((a, b) => a.start - b.start);
}

const compare = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
