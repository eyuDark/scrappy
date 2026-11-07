import type { CandidateMatch, Detector } from "@scrappy/core";

// shortcut: a curated TLD list, not the full IANA one; add a TLD here when a real domain slips through.
// Any 2-letter TLD counts (country codes) except common file extensions, so readme.md and app.js are left alone.
const FILE_EXTENSIONS = new Set(["js", "ts", "md", "py", "rs", "sh", "cs", "rb", "go", "kt", "hs", "ml", "el", "mk", "db", "gz", "xz", "so", "jl", "vb", "fs"]);
const TLDS = new Set([
  "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name", "pro", "aero", "coop", "jobs", "mobi", "museum", "travel", "asia",
  "app", "dev", "cloud", "tech", "online", "site", "website", "xyz", "top", "shop", "store", "blog", "page", "live", "news", "ltd", "inc", "llc",
  "company", "services", "solutions", "systems", "network", "digital", "agency", "studio", "design", "media", "group", "team", "email", "host",
  "art", "wiki", "work", "world", "today", "global", "academy", "finance", "bank", "health", "software", "tools", "run", "codes", "support",
  // Internal and reserved names: the hosts people most want hidden.
  "local", "localdomain", "internal", "intranet", "corp", "lan", "home", "test", "example", "invalid", "arpa",
]);
const isTld = (tld: string) => (tld.length === 2 ? !FILE_EXTENSIONS.has(tld) : TLDS.has(tld));

// Bounded labels keep the scan linear. A lowercase TLD skips code such as Math.PI; a trailing sentence dot is not part of the match.
const DOMAIN = /(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?<tld>[a-z]{2,63})(?![\w-]|\.[A-Za-z0-9])/g;

/** Hostnames such as `db01.acme.internal` or `vpn.acme.io`. Opt-in: not in `defaultDetectors`. Ports and paths stay outside the span. */
export const domainDetector: Detector = {
  id: "domain",
  supportedTypes: ["DOMAIN"],
  detect(input) {
    const out: CandidateMatch[] = [];
    for (const m of input.matchAll(DOMAIN)) {
      if (!isTld(m.groups!.tld!)) continue;
      out.push({ type: "DOMAIN", start: m.index, end: m.index + m[0].length, confidence: 0.75 });
    }
    return out;
  },
};
