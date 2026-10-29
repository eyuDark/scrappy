import { SENSITIVE_TYPES, ScrappyError, type CandidateMatch, type Detector, type SensitiveType } from "@scrappy/core";

export interface PatternDetectorOptions {
  id: string;
  type: SensitiveType;
  /** Redacts the named group `value` if present, otherwise the whole match. Must be safe from catastrophic backtracking. */
  pattern: RegExp | string;
  /** Used only when `pattern` is a string. */
  flags?: string;
  /** Default: 0.8. */
  confidence?: number;
  /** Extra check on the matched value, e.g. a checksum. */
  validate?: (value: string) => boolean;
}

export function createPatternDetector(options: PatternDetectorOptions): Detector {
  const { id, type, pattern, confidence = 0.8, validate } = options;
  if (typeof id !== "string" || id === "") throw new ScrappyError("INVALID_OPTIONS", "id");
  if (!(SENSITIVE_TYPES as readonly string[]).includes(type)) throw new ScrappyError("INVALID_OPTIONS", `${id}.type`);
  if (typeof confidence !== "number" || !(confidence >= 0 && confidence <= 1)) throw new ScrappyError("INVALID_OPTIONS", `${id}.confidence`);

  let regex: RegExp;
  try {
    const source = typeof pattern === "string" ? pattern : pattern.source;
    const flags = typeof pattern === "string" ? (options.flags ?? "") : pattern.flags;
    regex = new RegExp(source, [...new Set(flags + "gd")].join(""));
  } catch {
    throw new ScrappyError("INVALID_OPTIONS", `${id}.pattern`);
  }

  return {
    id,
    supportedTypes: [type],
    detect(input) {
      const out: CandidateMatch[] = [];
      for (const m of input.matchAll(regex)) {
        const span = m.groups && "value" in m.groups ? m.indices?.groups?.value : m.indices?.[0];
        if (!span || span[0] === span[1]) continue;
        const [start, end] = span;
        if (validate && !validate(input.slice(start, end))) continue;
        out.push({ type, start, end, confidence });
      }
      return out;
    },
  };
}
