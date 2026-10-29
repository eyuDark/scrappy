import { ScrappyError } from "./errors.ts";
import type { JsonFinding, SanitizeJsonResult, SanitizeResult } from "./types.ts";

const MAX_DEPTH = 256;
const IDENTIFIER = /^[A-Za-z_$][\w$]*$/;

/**
 * Walks a JSON-compatible value and sanitizes every string, object key and number.
 * Returns a new value; the input is never mutated. Unaffected values keep their type.
 */
export function sanitizeJsonValue(root: unknown, sanitize: (text: string) => SanitizeResult): SanitizeJsonResult {
  const findings: JsonFinding[] = [];
  const ancestors = new Set<object>();

  const record = (result: SanitizeResult, path: string, target: JsonFinding["target"]) => {
    for (const f of result.findings) findings.push({ ...f, id: `f${findings.length + 1}`, path, target });
  };

  const walk = (value: unknown, path: string, depth: number): unknown => {
    if (value === null || typeof value === "boolean") return value;
    if (typeof value === "string") {
      const result = sanitize(value);
      record(result, path, "value");
      return result.text;
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value)) throw new ScrappyError("UNSUPPORTED_VALUE", path);
      // A sensitive number (e.g. an account id) becomes a placeholder string; others stay numbers.
      const result = sanitize(String(value));
      if (result.findings.length === 0) return value;
      record(result, path, "value");
      return result.text;
    }
    if (typeof value !== "object") throw new ScrappyError("UNSUPPORTED_VALUE", path);
    if (depth >= MAX_DEPTH) throw new ScrappyError("MAX_DEPTH_EXCEEDED", path);
    if (ancestors.has(value)) throw new ScrappyError("CYCLIC_VALUE", path);

    ancestors.add(value);
    try {
      if (Array.isArray(value)) return value.map((item, i) => walk(item, `${path}[${i}]`, depth + 1));

      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) throw new ScrappyError("UNSUPPORTED_VALUE", path);

      const out: Record<string, unknown> = {};
      for (const [key, child] of Object.entries(value)) {
        // Keys can hold sensitive values too (e.g. maps keyed by email).
        const safeKey = sanitize(key);
        const childPath = IDENTIFIER.test(safeKey.text) ? `${path}.${safeKey.text}` : `${path}[${JSON.stringify(safeKey.text)}]`;
        record(safeKey, childPath, "key");
        // defineProperty so a "__proto__" key stays an own property instead of changing the prototype.
        Object.defineProperty(out, safeKey.text, { value: walk(child, childPath, depth + 1), enumerable: true, writable: true, configurable: true });
      }
      return out;
    } finally {
      ancestors.delete(value);
    }
  };

  const value = walk(root, "$", 0);
  return { value, findings, stats: { findingCount: findings.length } };
}
