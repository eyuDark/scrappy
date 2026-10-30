import assert from "node:assert/strict";
import { test } from "node:test";
import { sanitize, type Detector } from "@scrappy/core";
import {
  apiKeyDetector,
  bearerTokenDetector,
  createPatternDetector,
  defaultDetectors,
  emailDetector,
  ipAddressDetector,
  jwtDetector,
  passwordAssignmentDetector,
  paymentCardDetector,
  phoneDetector,
  privateKeyDetector,
  unknownTokenDetector,
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

test("payment cards: Luhn-valid numbers with a known issuer prefix", () => {
  for (const card of ["4111 1111 1111 1111", "5555-5555-5555-4444", "378282246310005", "6011111111111117", "4242424242424242", "2223003122003222"]) {
    assert.deepEqual(matches(paymentCardDetector, `card: ${card}.`), [card], card);
  }
  for (const negative of [
    "order 1234567812345678", // fails Luhn
    "4111 1111 1111 1112", // fails Luhn
    "epoch 1730189663021", // no issuer starts with 1
    "isbn 978-0-306-40615-7",
    "+251 911 234 567",
    "4111-1111 1111-1111", // mixed separators
    "411111111111111111111111", // 24 digits: too long
  ]) {
    assert.deepEqual(matches(paymentCardDetector, negative), [], negative);
  }
});

test("phones: international numbers, or any number shortly after a phone keyword", () => {
  const cases: [string, string][] = [
    ["sms to +251 911 234 567 ok", "+251 911 234 567"],
    ["dial +1 (415) 555-0134.", "+1 (415) 555-0134"],
    ["uk office +44 20 7946 0958", "+44 20 7946 0958"],
    ["+14155550134", "+14155550134"],
    ["Please call me back at 0911 234 567 today", "0911 234 567"],
    ["Phone: (415) 555-0134", "(415) 555-0134"],
    ["SUPPORT_PHONE=0911234567", "0911234567"],
    ["WhatsApp 0922 345 678", "0922 345 678"],
    ["tel:+251-911-234-567", "+251-911-234-567"],
  ];
  for (const [input, phone] of cases) assert.deepEqual(matches(phoneDetector, input), [phone], input);
  for (const negative of [
    "called about order #48213 on Oct 28",
    "Selam (support lead, ext. 2207)",
    "version +1.42.0",
    "retry in +30s",
    "timestamp 1730189663021",
    "phone: none on file",
    "call 3 times",
    "+1 2", // too few digits
  ]) {
    assert.deepEqual(matches(phoneDetector, negative), [], negative);
  }
});

test("unknown tokens: random-looking strings without a known prefix", () => {
  for (const [input, token] of [
    ["notify?sig=Zt7Kp2Qw9Xr4Lm8Vn3Bc6Hy1Jd5Fg0Sa&x=1", "Zt7Kp2Qw9Xr4Lm8Vn3Bc6Hy1Jd5Fg0Sa"],
    ["X-Internal-Auth: Hq3Zm8Wv1Ks6Tb0Ny4Jr7Lc2Pf9Dx5", "Hq3Zm8Wv1Ks6Tb0Ny4Jr7Lc2Pf9Dx5"],
    ["blob u7Hk2P/9qXz+Lr4Vw1Ns8Ty3Mb6Gd0Fe== end", "u7Hk2P/9qXz+Lr4Vw1Ns8Ty3Mb6Gd0Fe=="],
  ]) {
    assert.deepEqual(matches(unknownTokenDetector, input!), [token], input);
  }
  for (const negative of [
    "sha=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
    "req=3f6c2a9e-8b1d-4c7a-9e2f-1a2b3c4d5e6f",
    "api:1.42.0@sha256:5e8f2d6a1c3b7e9f0a2d4c6b8e1f3a5c7d9b0e2f4a6c8d0b2e4f6a8c0d2e4f6a",
    "resolver getUserByIdAndOrganizationScope2024 resolved",
    "class ThisIsAVeryLongPascalCaseName42 {}",
    "SCREAMING_SNAKE_CASE_CONFIG_VALUE_2024",
    "/srv/app/src/routes/token.ts:58:5",
    "Tracking number 1Z999AA10123456784",
    "short Ab1Cd2Ef3Gh4",
    // Found by scanning real code (@types/node) with 0.2.0 candidates:
    "algorithm: CipherChaCha20Poly1305Types,",
    "see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8ClampedArray)",
    "https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_set_options.html",
    "https://chromedevtools.github.io/devtools-protocol/1-3/Runtime/#type",
    // Known false positive, accepted: "1/man3/SSL_CIPHER_get_name". Counting all-caps runs as words
    // fixes it but drops random-token recall below 95%.
  ]) {
    assert.deepEqual(matches(unknownTokenDetector, negative), [], negative);
  }
});

test("unknown tokens: catches at least 95% of random base62 tokens", (t) => {
  // Deterministic PRNG so the sample is the same on every run.
  let seed = 42;
  const next = () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let caught = 0;
  for (let i = 0; i < 200; i++) {
    const token = Array.from({ length: 32 }, () => alphabet[Math.floor(next() * alphabet.length)]).join("");
    if (matches(unknownTokenDetector, `key ${token} end`).length === 1) caught++;
  }
  assert.ok(caught >= 190, `caught ${caught}/200`);
  t.diagnostic(`recall on random base62: ${caught}/200`);
});

test("ip addresses: IPv4 and IPv6, ports and brackets stay outside the span", () => {
  const cases: [string, string][] = [
    ["client_ip=196.188.12.44 ok", "196.188.12.44"],
    ["host=10.0.4.17:8080", "10.0.4.17"],
    ["loopback 127.0.0.1.", "127.0.0.1"],
    ["v6 2001:db8:85a3::8a2e:370:7334 up", "2001:db8:85a3::8a2e:370:7334"],
    ["bind [::1]:3000", "::1"],
    ["full 2001:0db8:0000:0000:0000:ff00:0042:8329", "2001:0db8:0000:0000:0000:ff00:0042:8329"],
    ["mapped ::ffff:192.0.2.128 end", "::ffff:192.0.2.128"],
    ["zone fe80::1%eth0 link", "fe80::1%eth0"],
  ];
  for (const [input, ip] of cases) assert.deepEqual(matches(ipAddressDetector, input), [ip], input);
  for (const negative of [
    "release v1.42.0.3",
    "build 1.2.3.4.5",
    "bad 999.1.1.1",
    "at 12:30:45 today",
    "mac aa:bb:cc:dd:ee:ff",
    "words dead:beef:cafe",
    "price 3.14",
    "ratio 1:2",
  ]) {
    assert.deepEqual(matches(ipAddressDetector, negative), [], negative);
  }
});

test("ip addresses are opt-in: not part of the default detectors", () => {
  assert.equal(run("from 196.188.12.44"), "from 196.188.12.44");
  assert.ok(!defaultDetectors.includes(ipAddressDetector));
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
    digits: "4".repeat(n),
    spacedDigits: "4 ".repeat(n / 2),
    dashedDigits: "4-".repeat(n / 2),
    plusDigits: "+1 ".repeat(n / 3),
    phoneKeywords: "phone call ".repeat(n / 11),
    keywordThenDigits: "tel 1 2 ".repeat(n / 8),
    oneHugeToken: "aB3".repeat(n / 3),
    manyShortTokens: "aB3dE6gH9jK2mN5pQ8sT1vW4 ".repeat(n / 25),
    slashRuns: "aB3/".repeat(n / 4),
    dottedNumbers: "1.".repeat(n / 2),
    colonHex: "a:".repeat(n / 2),
    doubleColons: "::".repeat(n / 2),
  };
  for (const [name, input] of Object.entries(inputs)) {
    const started = performance.now();
    sanitize(input, { detectors: [...defaultDetectors, ipAddressDetector] });
    const ms = performance.now() - started;
    assert.ok(ms < 2000, `${name} took ${Math.round(ms)}ms`);
  }
});
