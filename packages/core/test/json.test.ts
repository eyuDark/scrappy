import assert from "node:assert/strict";
import { test } from "node:test";
import { createSession, sanitizeJson, type CandidateMatch, type Detector } from "@scrappy/core";

const email: Detector = {
  id: "email",
  supportedTypes: ["EMAIL"],
  detect(input) {
    const out: CandidateMatch[] = [];
    for (const m of input.matchAll(/[a-z]+@x\.io/g)) out.push({ type: "EMAIL", start: m.index, end: m.index + m[0].length, confidence: 0.9 });
    return out;
  },
};
const account: Detector = {
  id: "account",
  supportedTypes: ["ACCOUNT_NUMBER"],
  detect: (input) => (/^1002\d\d$/.test(input) ? [{ type: "ACCOUNT_NUMBER", start: 0, end: input.length, confidence: 0.9 }] : []),
};
const detectors = [email, account];

test("sanitizes nested strings, keeps structure and unaffected types, reports paths", () => {
  const input = { customer: { email: "a@x.io", vip: true, visits: 3, tags: ["b@x.io", null] }, "order id": "a@x.io" };
  const snapshot = structuredClone(input);
  const result = sanitizeJson(input, { detectors });

  assert.deepEqual(result.value, { customer: { email: "[EMAIL_1]", vip: true, visits: 3, tags: ["[EMAIL_2]", null] }, "order id": "[EMAIL_1]" });
  assert.deepEqual(input, snapshot, "input must not be mutated");
  assert.deepEqual(
    result.findings.map(({ id, path, target, replacement }) => ({ id, path, target, replacement })),
    [
      { id: "f1", path: "$.customer.email", target: "value", replacement: "[EMAIL_1]" },
      { id: "f2", path: "$.customer.tags[0]", target: "value", replacement: "[EMAIL_2]" },
      { id: "f3", path: '$["order id"]', target: "value", replacement: "[EMAIL_1]" },
    ],
  );
});

test("sanitizes object keys and sensitive numbers", () => {
  const result = sanitizeJson({ "a@x.io": { account: 100284, count: 100 } }, { detectors });
  assert.deepEqual(result.value, { "[EMAIL_1]": { account: "[ACCOUNT_NUMBER_1]", count: 100 } });
  assert.deepEqual(
    result.findings.map(({ path, target }) => [path, target]),
    [
      ['$["[EMAIL_1]"]', "key"],
      ['$["[EMAIL_1]"].account', "value"],
    ],
  );
});

test("a __proto__ key stays an own property", () => {
  const value = sanitizeJson(JSON.parse('{"__proto__": {"x": "a@x.io"}}'), { detectors }).value as object;
  assert.equal(Object.getPrototypeOf(value), Object.prototype);
  assert.deepEqual(Object.getOwnPropertyDescriptor(value, "__proto__")?.value, { x: "[EMAIL_1]" });
});

test("rejects non-JSON values, cycles and excessive depth with safe errors", () => {
  const cyclic: Record<string, unknown> = { a: "a@x.io" };
  cyclic.self = cyclic;
  assert.throws(() => sanitizeJson(cyclic, { detectors }), { code: "CYCLIC_VALUE" });
  for (const bad of [new Date(), () => 1, 1n, undefined, Number.NaN, new Map(), { nested: Symbol("s") }]) {
    assert.throws(() => sanitizeJson(bad, { detectors }), { code: "UNSUPPORTED_VALUE" });
  }
  let deep: unknown = "a@x.io";
  for (let i = 0; i < 300; i++) deep = [deep];
  assert.throws(() => sanitizeJson(deep, { detectors }), { code: "MAX_DEPTH_EXCEEDED" });
});

test("shared (non-cyclic) references are fine", () => {
  const shared = { e: "a@x.io" };
  assert.deepEqual(sanitizeJson([shared, shared], { detectors }).value, [{ e: "[EMAIL_1]" }, { e: "[EMAIL_1]" }]);
});

test("a reversible session restores JSON-sanitized values", () => {
  const session = createSession({ detectors, mode: "reversible" });
  session.sanitizeJson({ to: "a@x.io" });
  assert.equal(session.restore("Reply to [EMAIL_1]").text, "Reply to a@x.io");
});
