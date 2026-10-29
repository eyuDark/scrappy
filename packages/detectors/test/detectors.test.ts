import assert from "node:assert/strict";
import { test } from "node:test";
import { sanitize, type Detector } from "@scrappy/core";
import {
  apiKeyDetector,
  bearerTokenDetector,
  createPatternDetector,
  defaultDetectors,
  emailDetector,
  jwtDetector,
  passwordAssignmentDetector,
  privateKeyDetector,
  urlCredentialsDetector,
} from "@scrappy/detectors";

const matches = (detector: Detector, input: string) => detector.detect(input).map((c) => input.slice(c.start, c.end));
const run = (input: string) => sanitize(input, { detectors: defaultDetectors }).text;

// Fake credentials, assembled at runtime so secret scanners don't flag the test file.
const fake = (prefix: string, n: number) => prefix + "A1b2C3d4E5".repeat(Math.ceil(n / 10)).slice(0, n);
const JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

test("email", () => {
  assert.deepEqual(matches(emailDetector, "mail john.doe+ci@mail.example.co.uk, then."), ["john.doe+ci@mail.example.co.uk"]);
  assert.deepEqual(matches(emailDetector, "<a@b.io>;x@y.dev."), ["a@b.io", "x@y.dev"]);
  assert.deepEqual(matches(emailDetector, "...lead@x.io"), ["lead@x.io"]);
  for (const negative of ["@handle", "user@localhost", "a@b.c", "a@b..io", "a@ b.io", "price @ 5.00", "node@22.18"]) {
    assert.deepEqual(matches(emailDetector, negative), [], negative);
  }
});

test("api keys", () => {
  for (const key of [fake("sk-ant-api03-", 40), fake("sk-proj-", 40), fake("ghp_", 36), fake("github_pat_", 40), fake("glpat-", 20), fake("xoxb-", 24), "AKIAIOSFODNN7EXAMPLE", fake("AIza", 35), fake("sk_live_", 24)]) {
    assert.deepEqual(matches(apiKeyDetector, `key: ${key} end`), [key], key);
  }
  for (const negative of ["sk-short", fake("xsk-proj-", 40), "AKIAIOSFODNN7EXAMPLEX", "task-management-service-handler"]) {
    assert.deepEqual(matches(apiKeyDetector, negative), [], negative);
  }
});

test("jwt and bearer tokens", () => {
  assert.deepEqual(matches(jwtDetector, `token=${JWT};`), [JWT]);
  assert.deepEqual(matches(jwtDetector, "eyJ alone and xeyJa.eyJb.c"), []);
  assert.deepEqual(matches(bearerTokenDetector, "Authorization: Bearer abcDEF123456789xyz"), ["abcDEF123456789xyz"]);
  assert.deepEqual(matches(bearerTokenDetector, "a bearer of bad news"), []);
  // The more specific JWT wins over the generic bearer span.
  assert.equal(run(`Authorization: Bearer ${JWT}`), "Authorization: Bearer [JWT_1]");
});

test("password assignments", () => {
  const cases: [string, string][] = [
    ["password=hunter2", "hunter2"],
    ['{"password": "correct horse battery"}', "correct horse battery"],
    ["DB_PASSWORD: s3cr3t!", "s3cr3t!"],
    ["x-api-key: abc123def", "abc123def"],
    ["client_secret='q:w;e'", "q:w;e"],
    ["https://x.io/?token=abc&next=1", "abc"],
  ];
  for (const [input, value] of cases) assert.deepEqual(matches(passwordAssignmentDetector, input), [value], input);
  for (const negative of ["password_hint: dog", "passed: 5", "tokenizer=bpe", "password=[PASSWORD_1]", "my password is long"]) {
    assert.deepEqual(matches(passwordAssignmentDetector, negative), [], negative);
  }
});

test("url credentials keep the host and redact only the password", () => {
  assert.deepEqual(matches(urlCredentialsDetector, "postgres://app:p%40ss:w0rd@db.internal:5432/x"), ["p%40ss:w0rd"]);
  assert.equal(run("DATABASE_URL=postgres://app:pw123@db.example.com/main"), "DATABASE_URL=postgres://app:[PASSWORD_1]@db.example.com/main");
});

test("private keys, including truncated ones", () => {
  const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nIBAAK\n-----END RSA PRIVATE KEY-----";
  assert.equal(run(`before\n${key}\nafter`), "before\n[PRIVATE_KEY_1]\nafter");
  assert.equal(run("log: -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk"), "log: [PRIVATE_KEY_1]");
  assert.deepEqual(matches(privateKeyDetector, "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----"), []);
});

test("custom pattern detector redacts the `value` group and runs validate", () => {
  const account = createPatternDetector({ id: "account", type: "ACCOUNT_NUMBER", pattern: /account (?<value>\d{6})\b/i });
  assert.deepEqual(matches(account, "Account 100284 and account 12"), ["100284"]);
  const even = createPatternDetector({ id: "even", type: "CUSTOM", pattern: "\\d+", validate: (v) => Number(v) % 2 === 0 });
  assert.deepEqual(matches(even, "1 2 3 44"), ["2", "44"]);
  assert.throws(() => createPatternDetector({ id: "bad", type: "CUSTOM", pattern: "(" }), { code: "INVALID_OPTIONS" });
  assert.throws(() => createPatternDetector({ id: "bad", type: "SSN" as never, pattern: "x" }), { code: "INVALID_OPTIONS" });
});

test("adversarial: 1 MB pathological inputs finish quickly", () => {
  const n = 1_000_000;
  const inputs = {
    letters: "a".repeat(n),
    ats: "a@".repeat(n / 2),
    dots: "a@" + "b.".repeat(n / 2 - 1),
    jwtPrefix: "eyJ".repeat(n / 3),
    jwtDots: "eyJa.".repeat(n / 5),
    pem: "-----BEGIN PRIVATE KEY-----".repeat(n / 27),
    assignments: "password=".repeat(n / 9),
    schemes: "a://b:".repeat(n / 6),
    placeholders: "[A_".repeat(n / 3),
  };
  for (const [name, input] of Object.entries(inputs)) {
    const started = performance.now();
    sanitize(input, { detectors: defaultDetectors });
    const ms = performance.now() - started;
    assert.ok(ms < 2000, `${name} took ${Math.round(ms)}ms`);
  }
});
