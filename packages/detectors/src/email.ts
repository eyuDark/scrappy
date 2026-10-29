import type { CandidateMatch, Detector } from "@scrappy/core";

// shortcut: ASCII addresses only, upgrade when internationalized (IDN/UTF-8) addresses matter.
const isLocal = (c: number) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 46 || c === 95 || c === 37 || c === 43 || c === 45;
const isDomain = (c: number) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 46 || c === 45;

/** Expands outward from each "@" instead of using a regex, so scanning stays linear on any input. */
export const emailDetector: Detector = {
  id: "email",
  supportedTypes: ["EMAIL"],
  detect(input) {
    const out: CandidateMatch[] = [];
    let floor = 0;
    for (let at = input.indexOf("@"); at !== -1; at = input.indexOf("@", at + 1)) {
      let start = at;
      while (start > floor && isLocal(input.charCodeAt(start - 1))) start--;
      while (start < at && input[start] === ".") start++;
      let end = at + 1;
      while (end < input.length && isDomain(input.charCodeAt(end))) end++;
      while (end > at + 1 && (input[end - 1] === "." || input[end - 1] === "-")) end--;
      floor = at + 1;
      if (start === at) continue;

      const labels = input.slice(at + 1, end).split(".");
      const tld = labels.at(-1) ?? "";
      if (labels.length < 2 || labels.some((l) => l === "") || !/^[A-Za-z]{2,63}$/.test(tld)) continue;
      out.push({ type: "EMAIL", start, end, confidence: 0.9 });
      floor = end;
    }
    return out;
  },
};
