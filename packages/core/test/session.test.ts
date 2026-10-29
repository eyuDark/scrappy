import assert from "node:assert/strict";
import { test } from "node:test";
import { createSession, type CandidateMatch, type Detector, type SensitiveType } from "@scrappy/core";

const literal = (type: SensitiveType, values: string[]): Detector => ({
  id: type.toLowerCase(),
  supportedTypes: [type],
  detect(input) {
    const out: CandidateMatch[] = [];
    for (const v of values) for (let i = input.indexOf(v); i !== -1; i = input.indexOf(v, i + 1)) out.push({ type, start: i, end: i + v.length, confidence: 0.9 });
    return out;
  },
});
const detectors = [literal("EMAIL", ["john@example.com"]), literal("PASSWORD", ["hunter2"])];

test("reversible: restores only placeholders this session issued", () => {
  const session = createSession({ detectors, mode: "reversible" });
  const safe = session.sanitize("john@example.com uses hunter2");
  assert.equal(safe.text, "[EMAIL_1] uses [PASSWORD_1]");

  const reply = "Ask [EMAIL_1] to rotate [PASSWORD_1]. Not [EMAIL_9], [email_1] or [EMAIL_1";
  assert.deepEqual(session.restore(reply), { text: "Ask john@example.com to rotate hunter2. Not [EMAIL_9], [email_1] or [EMAIL_1", restoredCount: 2 });
});

test("restore honors allowedTypes and maxRestorations", () => {
  const session = createSession({ detectors, mode: "reversible" });
  session.sanitize("john@example.com hunter2");
  assert.equal(session.restore("[EMAIL_1] [PASSWORD_1]", { allowedTypes: ["EMAIL"] }).text, "john@example.com [PASSWORD_1]");
  assert.deepEqual(session.restore("[EMAIL_1] [EMAIL_1]", { maxRestorations: 1 }), { text: "john@example.com [EMAIL_1]", restoredCount: 1 });
  assert.throws(() => session.restore("x", { allowedTypes: ["NOPE" as SensitiveType] }), { code: "INVALID_OPTIONS" });
});

test("placeholders stay consistent across calls in one session", () => {
  const session = createSession({ detectors });
  assert.equal(session.sanitize("john@example.com").text, "[EMAIL_1]");
  assert.equal(session.sanitize("again john@example.com").text, "again [EMAIL_1]");
});

test("irreversible is the default and cannot restore", () => {
  const session = createSession({ detectors });
  assert.equal(session.mode, "irreversible");
  session.sanitize("john@example.com");
  assert.throws(() => session.restore("[EMAIL_1]"), { code: "RESTORE_UNAVAILABLE" });
});

test("sessions are isolated from each other", () => {
  const a = createSession({ detectors, mode: "reversible" });
  const b = createSession({ detectors, mode: "reversible" });
  a.sanitize("john@example.com");
  assert.deepEqual(b.restore("[EMAIL_1]"), { text: "[EMAIL_1]", restoredCount: 0 });
});

test("dispose invalidates the session", () => {
  const session = createSession({ detectors, mode: "reversible" });
  session.sanitize("john@example.com");
  session.dispose();
  assert.throws(() => session.restore("[EMAIL_1]"), { code: "SESSION_DISPOSED" });
  assert.throws(() => session.sanitize("x"), { code: "SESSION_DISPOSED" });
});

test("restored values never reach the sanitize result", () => {
  const session = createSession({ detectors, mode: "reversible" });
  const result = session.sanitize("john@example.com hunter2");
  assert.ok(!/john|hunter2/.test(JSON.stringify(result)));
});
