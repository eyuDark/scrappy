import assert from "node:assert/strict";
import { test } from "node:test";
import { ScrappyError, sanitize, type CandidateMatch, type Detector, type SensitiveType } from "@scrappy/core";

/** Detector that reports every occurrence of each literal. */
const literal = (id: string, type: SensitiveType, values: string[], confidence = 0.9): Detector => ({
  id,
  supportedTypes: [type],
  detect(input) {
    const out: CandidateMatch[] = [];
    for (const v of values) for (let i = input.indexOf(v); i !== -1; i = input.indexOf(v, i + 1)) out.push({ type, start: i, end: i + v.length, confidence });
    return out;
  },
});
const spans = (spans: Omit<CandidateMatch, "detector">[]): Detector => ({ id: "fixed", supportedTypes: ["CUSTOM", "PASSWORD"], detect: () => spans.map((s) => ({ ...s })) });

test("replaces spans with typed placeholders and reports findings without values", () => {
  const input = "Contact john@example.com or jane@example.com.";
  const result = sanitize(input, { detectors: [literal("email", "EMAIL", ["john@example.com", "jane@example.com"])] });

  assert.equal(result.text, "Contact [EMAIL_1] or [EMAIL_2].");
  assert.deepEqual(result.findings, [
    { id: "f1", type: "EMAIL", start: 8, end: 24, confidence: 0.9, detector: "email", replacement: "[EMAIL_1]" },
    { id: "f2", type: "EMAIL", start: 28, end: 44, confidence: 0.9, detector: "email", replacement: "[EMAIL_2]" },
  ]);
  assert.deepEqual(result.stats, { inputLength: input.length, outputLength: result.text.length, findingCount: 2 });
  assert.ok(!JSON.stringify(result.findings).includes("john"));
});

test("repeated values share one placeholder", () => {
  const result = sanitize("a@x.io, b@x.io, a@x.io", { detectors: [literal("email", "EMAIL", ["a@x.io", "b@x.io"])] });
  assert.equal(result.text, "[EMAIL_1], [EMAIL_2], [EMAIL_1]");
});

test("overlaps: higher confidence wins, then the longer span, deterministically", () => {
  const input = "token=eyJhbGc.eyJzdWI.sig";
  const detectors = [literal("generic", "API_KEY", ["eyJhbGc.eyJzdWI.sig"], 0.6), literal("jwt", "JWT", ["eyJhbGc.eyJzdWI"], 0.95)];
  assert.equal(sanitize(input, { detectors }).text, "token=[JWT_1].sig");

  const tie = [literal("short", "API_KEY", ["eyJhbGc"]), literal("long", "JWT", ["eyJhbGc.eyJzdWI"])];
  assert.equal(sanitize(input, { detectors: tie }).text, "token=[JWT_1].sig");
  assert.equal(sanitize(input, { detectors: [...tie].reverse() }).text, "token=[JWT_1].sig");
});

test("adjacent spans are both replaced against original offsets", () => {
  const result = sanitize("AAABBB", { detectors: [spans([{ type: "CUSTOM", start: 0, end: 3, confidence: 1 }, { type: "PASSWORD", start: 3, end: 6, confidence: 1 }])] });
  assert.equal(result.text, "[CUSTOM_1][PASSWORD_1]");
});

test("invalid spans are dropped", () => {
  const bad = [
    { type: "CUSTOM", start: -1, end: 2, confidence: 1 },
    { type: "CUSTOM", start: 2, end: 2, confidence: 1 },
    { type: "CUSTOM", start: 3, end: 99, confidence: 1 },
    { type: "CUSTOM", start: 0.5, end: 2, confidence: 1 },
    { type: "CUSTOM", start: 0, end: 2, confidence: Number.NaN },
  ] as const;
  assert.equal(sanitize("hello", { detectors: [spans([...bad])] }).text, "hello");
});

test("policy: enabledTypes, minConfidence and allowlist", () => {
  const detectors = [literal("e", "EMAIL", ["a@x.io", "ops@x.io"]), literal("p", "PHONE", ["555-0100"], 0.4)];
  const input = "a@x.io ops@x.io 555-0100";
  assert.equal(sanitize(input, { detectors, policy: { enabledTypes: ["PHONE"], minConfidence: 0 } }).text, "a@x.io ops@x.io [PHONE_1]");
  assert.equal(sanitize(input, { detectors }).text, "[EMAIL_1] [EMAIL_2] 555-0100");
  assert.equal(sanitize(input, { detectors, policy: { allowlist: ["ops@x.io"] } }).text, "[EMAIL_1] ops@x.io 555-0100");
});

test("a disabled type does not block an overlapping enabled one", () => {
  const detectors = [literal("big", "CUSTOM", ["id=a@x.io"], 1), literal("e", "EMAIL", ["a@x.io"])];
  assert.equal(sanitize("id=a@x.io", { detectors, policy: { enabledTypes: ["EMAIL"] } }).text, "id=[EMAIL_1]");
});

test("placeholder numbers skip text that already appears literally in the input", () => {
  const result = sanitize("[EMAIL_1] was a@x.io", { detectors: [literal("e", "EMAIL", ["a@x.io"])] });
  assert.equal(result.text, "[EMAIL_1] was [EMAIL_2]");
});

test("spans never split a surrogate pair", () => {
  const input = "x😀y";
  const result = sanitize(input, { detectors: [spans([{ type: "CUSTOM", start: 2, end: 3, confidence: 1 }])] });
  assert.equal(result.text, "x[CUSTOM_1]y");
  assert.deepEqual([result.findings[0]?.start, result.findings[0]?.end], [1, 3]);
});

test("offsets are UTF-16 code units into the original input", () => {
  const input = "😀 a@x.io";
  const [f] = sanitize(input, { detectors: [literal("e", "EMAIL", ["a@x.io"])] }).findings;
  assert.equal(input.slice(f!.start, f!.end), "a@x.io");
});

test("fails closed when a detector throws, without leaking the input", () => {
  const secret = "hunter2-very-secret";
  const throwing: Detector = { id: "boom", supportedTypes: ["CUSTOM"], detect: (input) => { throw new Error(`cannot parse ${input}`); } };
  assert.throws(
    () => sanitize(secret, { detectors: [throwing] }),
    (e: unknown) => e instanceof ScrappyError && e.code === "DETECTOR_FAILED" && !e.message.includes(secret) && e.cause === undefined,
  );
  const malformed = { id: "bad", supportedTypes: ["CUSTOM"], detect: () => [{ type: "NOPE" }] } as unknown as Detector;
  assert.throws(() => sanitize("x", { detectors: [malformed] }), { code: "DETECTOR_FAILED" });
});

test("fails closed when a detector reports a type it did not declare", () => {
  const liar: Detector = { id: "liar", supportedTypes: ["EMAIL"], detect: () => [{ type: "PASSWORD", start: 0, end: 1, confidence: 1 }] };
  assert.throws(() => sanitize("x", { detectors: [liar] }), { code: "DETECTOR_FAILED", message: /liar/ });
});

test("detectors whose types are all disabled by policy do not run", () => {
  const phoneOnly: Detector = { id: "phone", supportedTypes: ["PHONE"], detect: () => { throw new Error("should not run"); } };
  const detectors = [phoneOnly, literal("e", "EMAIL", ["a@x.io"])];
  assert.equal(sanitize("a@x.io", { detectors, policy: { enabledTypes: ["EMAIL"] } }).text, "[EMAIL_1]");
});

test("rejects oversized and non-string input", () => {
  assert.throws(() => sanitize("abcdef", { detectors: [], policy: { maxInputLength: 5 } }), { code: "INPUT_TOO_LARGE" });
  assert.throws(() => sanitize(42 as unknown as string, { detectors: [] }), { code: "INVALID_INPUT" });
});

test("validates options before processing", () => {
  const bad: unknown[] = [
    { detectors: "nope" },
    { detectors: [], mode: "maybe" },
    { detectors: [], policy: { minConfidence: 2 } },
    { detectors: [], policy: { enabledTypes: ["SSN"] } },
    { detectors: [], policy: { maxInputLength: 0 } },
    { detectors: [], policy: { allowlist: [1] } },
  ];
  for (const options of bad) assert.throws(() => sanitize("x", options as never), { code: "INVALID_OPTIONS" });
});
