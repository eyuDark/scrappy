import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { sanitize, type Finding } from "@scrappy/sdk";

// Corpus files label sensitive values inline as [[TYPE|value]]; `@fake:<prefix>:<n>` expands to a
// fake credential at runtime so GitHub secret scanning never sees a key-shaped string in the repo.
const CORPUS = new URL("./corpus/", import.meta.url);
const LABEL = /\[\[([A-Z_]+)\|([\s\S]*?)\]\]/g;
const fake = (prefix: string, n: number) => prefix + "A1b2C3d4E5".repeat(Math.ceil(n / 10)).slice(0, n);

// Targets set before the detectors were written. Recall = labeled values fully covered by a finding.
const MIN_RECALL: Record<string, number> = { PHONE: 0.9, SECRET: 0.8 };
const DEFAULT_MIN_RECALL = 1;
const MAX_FALSE_POSITIVES = 2;

interface Label { type: string; start: number; end: number; file: string }

function load(file: string) {
  const raw = readFileSync(new URL(file, CORPUS), "utf8");
  const labels: Label[] = [];
  let text = "";
  let last = 0;
  for (const m of raw.matchAll(LABEL)) {
    const [, type, rawValue] = m;
    const fakeSpec = /^@fake:(.*):(\d+)$/.exec(rawValue!);
    const value = fakeSpec ? fake(fakeSpec[1]!, Number(fakeSpec[2])) : rawValue!;
    text += raw.slice(last, m.index);
    labels.push({ type: type!, start: text.length, end: text.length + value.length, file });
    text += value;
    last = m.index + m[0].length;
  }
  return { text: text + raw.slice(last), labels };
}

test("corpus: recall per type and false positives with default detectors", (t) => {
  const hits = new Map<string, { found: number; total: number }>();
  const misses: string[] = [];
  const falsePositives: string[] = [];

  for (const file of readdirSync(CORPUS).sort()) {
    const { text, labels } = load(file);
    const { findings } = sanitize(text);
    const covers = (f: Finding, l: Label) => f.start <= l.start && f.end >= l.end;
    const overlaps = (f: Finding, l: Label) => f.start < l.end && l.start < f.end;

    for (const label of labels) {
      const stat = hits.get(label.type) ?? { found: 0, total: 0 };
      stat.total++;
      if (findings.some((f) => covers(f, label))) stat.found++;
      else misses.push(`${file}: ${label.type} ${JSON.stringify(text.slice(label.start, label.end))}`);
      hits.set(label.type, stat);
    }
    for (const f of findings) {
      if (!labels.some((l) => overlaps(f, l))) falsePositives.push(`${file}: ${f.type} ${JSON.stringify(text.slice(f.start, f.end))}`);
    }
  }

  for (const [type, { found, total }] of [...hits].sort()) t.diagnostic(`${type.padEnd(13)} recall ${found}/${total}`);
  for (const m of misses) t.diagnostic(`missed   ${m}`);
  for (const fp of falsePositives) t.diagnostic(`false+   ${fp}`);

  for (const [type, { found, total }] of hits) {
    const floor = MIN_RECALL[type] ?? DEFAULT_MIN_RECALL;
    assert.ok(found / total >= floor, `${type} recall ${found}/${total} is below ${floor}`);
  }
  assert.ok(falsePositives.length <= MAX_FALSE_POSITIVES, `${falsePositives.length} false positives (max ${MAX_FALSE_POSITIVES})`);
});
