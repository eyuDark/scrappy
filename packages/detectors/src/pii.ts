import type { CandidateMatch, Detector } from "@scrappy/core";
import { createPatternDetector } from "./pattern.ts";

// Issuer prefixes: Visa, Mastercard (51-55, 2221-2720), Amex, Discover, JCB, Diners, UnionPay.
const ISSUER = /^(?:4|5[1-5]|222[1-9]|22[3-9]\d|2[3-6]\d\d|27[01]\d|2720|3[47]|6011|64[4-9]|65|352[89]|35[3-8]\d|3[68]|30[0-5]|62)/;

function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2 === 1 && (d *= 2) > 9) d -= 9;
    sum += d;
  }
  return sum % 10 === 0;
}

export const paymentCardDetector = createPatternDetector({
  id: "payment-card",
  type: "PAYMENT_CARD",
  confidence: 0.9,
  pattern: /(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])/,
  validate(value) {
    const digits = value.replace(/[ -]/g, "");
    const separators = new Set(value.replace(/\d/g, ""));
    return separators.size <= 1 && ISSUER.test(digits) && luhn(digits);
  },
});

const PHONE =
  /(?<![\w+])(?<intl>\+[1-9][\d ().-]{6,20}\d)|(?<![A-Za-z])(?:phone|tel|mobile|cell|call|whatsapp|telegram|sms)(?![a-z])[^\d\n+]{0,20}?(?<local>\+?\(?\d[\d ().-]{5,18}\d)/dgi;

/** International `+` numbers anywhere, or any number within a few words after a phone keyword. Country-agnostic. */
export const phoneDetector: Detector = {
  id: "phone",
  supportedTypes: ["PHONE"],
  detect(input) {
    const out: CandidateMatch[] = [];
    for (const m of input.matchAll(PHONE)) {
      const intl = m.groups?.intl !== undefined;
      const span = intl ? m.indices?.groups?.intl : m.indices?.groups?.local;
      if (!span) continue;
      const digits = input.slice(span[0], span[1]).replace(/\D/g, "").length;
      if (digits < (intl ? 8 : 7) || digits > 15) continue;
      out.push({ type: "PHONE", start: span[0], end: span[1], confidence: intl ? 0.85 : 0.8 });
    }
    return out;
  },
};
