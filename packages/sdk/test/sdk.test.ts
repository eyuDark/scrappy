import assert from "node:assert/strict";
import { test } from "node:test";
import { createPatternDetector, createSession, defaultDetectors, sanitize, sanitizeJson } from "@scrappy/sdk";

const account = createPatternDetector({ id: "account", type: "ACCOUNT_NUMBER", pattern: /\baccount (?<value>\d{6})\b/i });
const detectors = [...defaultDetectors, account];

test("vertical slice: account number and email in one sentence", () => {
  const result = sanitize("Payment failed for account 100284. Contact john@example.com.", { detectors });
  assert.equal(result.text, "Payment failed for account [ACCOUNT_NUMBER_1]. Contact [EMAIL_1].");
  assert.deepEqual(result.findings.map((f) => f.type), ["ACCOUNT_NUMBER", "EMAIL"]);
});

test("default detectors apply when none are given; six-digit numbers are left alone", () => {
  assert.equal(sanitize("Email john@example.com failed, code 100284.").text, "Email [EMAIL_1] failed, code 100284.");
});

test("reversible round trip through a fake AI reply", () => {
  const session = createSession({ mode: "reversible", detectors });
  try {
    const safe = session.sanitize("Refund account 100284 for jane@corp.io");
    const reply = `Refunded [ACCOUNT_NUMBER_1]; I emailed ${safe.findings.find((f) => f.type === "EMAIL")?.replacement}.`;
    assert.equal(session.restore(reply, { allowedTypes: ["EMAIL"] }).text, "Refunded [ACCOUNT_NUMBER_1]; I emailed jane@corp.io.");
  } finally {
    session.dispose();
  }
});

test("sanitizeJson with defaults", () => {
  const { value } = sanitizeJson({ headers: { authorization: "Bearer abcDEF123456789xyz" }, user: "ops@corp.io" });
  assert.deepEqual(value, { headers: { authorization: "Bearer [ACCESS_TOKEN_1]" }, user: "[EMAIL_1]" });
});
