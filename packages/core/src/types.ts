export const SENSITIVE_TYPES = [
  "EMAIL",
  "PHONE",
  "PERSON",
  "ADDRESS",
  "ACCOUNT_NUMBER",
  "PAYMENT_CARD",
  "API_KEY",
  "ACCESS_TOKEN",
  "JWT",
  "PRIVATE_KEY",
  "PASSWORD",
  "CUSTOM",
] as const;

export type SensitiveType = (typeof SENSITIVE_TYPES)[number];

export type RedactionMode = "irreversible" | "reversible";

/** A span reported by a detector. Offsets are half-open UTF-16 code-unit offsets into the original input. */
export interface CandidateMatch {
  type: SensitiveType;
  start: number;
  end: number;
  /** 0..1. Also acts as precedence when candidates overlap. */
  confidence: number;
}

export interface Detector {
  readonly id: string;
  readonly supportedTypes: readonly SensitiveType[];
  /** Returns spans into `input`. Must not modify text. */
  detect(input: string): CandidateMatch[];
}

export interface SanitizePolicy {
  /** Types to redact. Default: all. */
  enabledTypes?: readonly SensitiveType[];
  /** Candidates below this confidence are ignored. Default: 0.5. */
  minConfidence?: number;
  /** Exact values that are never redacted. */
  allowlist?: readonly string[];
  /** Maximum input length in UTF-16 code units. Default: 1_000_000. */
  maxInputLength?: number;
}

/** Never contains the original matched value. */
export interface Finding {
  id: string;
  type: SensitiveType;
  start: number;
  end: number;
  confidence: number;
  detector: string;
  replacement: string;
}

export interface SanitizeResult {
  text: string;
  findings: Finding[];
  stats: {
    inputLength: number;
    outputLength: number;
    findingCount: number;
  };
}

export interface JsonFinding extends Finding {
  /** Path to the member, built from sanitized keys, e.g. `$.customer.email`. Offsets are relative to that key or string. */
  path: string;
  target: "key" | "value";
}

export interface SanitizeJsonResult {
  value: unknown;
  findings: JsonFinding[];
  stats: { findingCount: number };
}

export interface SessionOptions {
  detectors: readonly Detector[];
  /** Default: "irreversible". Reversible mode must be requested explicitly. */
  mode?: RedactionMode;
  policy?: SanitizePolicy;
}

export interface RestoreOptions {
  allowedTypes?: readonly SensitiveType[];
  maxRestorations?: number;
}

export interface RestoreResult {
  text: string;
  restoredCount: number;
}

export interface SanitizationSession {
  readonly mode: RedactionMode;
  sanitize(input: string): SanitizeResult;
  sanitizeJson(value: unknown): SanitizeJsonResult;
  /** Reversible mode only. Replaces exact placeholders issued by this session. */
  restore(text: string, options?: RestoreOptions): RestoreResult;
  /** Drops all mappings. The session cannot be used afterwards. */
  dispose(): void;
}
