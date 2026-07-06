#!/usr/bin/env python3
"""Score the CVE corpus: compare analyzer SARIF results against the `// ruleid:` annotations in the
PoC files. A PoC marks its vulnerable line with `// ruleid: <query-id>` on the line ABOVE the sink.
Detection = a SARIF result within +/-1 line of the annotated sink (rule id not required to match, but
reported). Also lists findings with NO nearby annotation (candidate false positives)."""
import json, os, re, sys
from collections import defaultdict

sarif_path, src_root = sys.argv[1], sys.argv[2]

# --- expected: (relpath, sink_line) -> ruleid, from `// ruleid:` comments (sink is the NEXT line) ---
expected = {}          # (file, line) -> expected rule id
by_file = defaultdict(list)
for dp, _, fs in os.walk(src_root):
    for f in fs:
        if not f.endswith(".php"):
            continue
        rel = os.path.relpath(os.path.join(dp, f), src_root)
        lines = open(os.path.join(dp, f), encoding="utf-8", errors="replace").read().splitlines()
        for i, ln in enumerate(lines):
            m = re.search(r"ruleid:\s*(\S+)", ln)
            if m:
                expected[(rel, i + 2)] = m.group(1)      # sink on next line (1-indexed +1)
                by_file[rel].append((i + 2, m.group(1)))

# --- actual: SARIF results (rule, file, line) ---------------------------------------------------
d = json.load(open(sarif_path))
actual = []
for x in d["runs"][0]["results"]:
    loc = x["locations"][0]["physicalLocation"]
    actual.append((x["ruleId"], loc["artifactLocation"]["uri"], loc["region"]["startLine"]))

def hit(rel, line):
    return [a for a in actual if a[1] == rel and abs(a[2] - line) <= 1]

detected = missed = 0
print(f"\n{'='*72}\n CVE CORPUS DETECTION REPORT\n{'='*72}")
for rel in sorted(by_file):
    print(f"\n{rel}")
    for line, exp in sorted(by_file[rel]):
        h = hit(rel, line)
        if h:
            detected += 1
            got = ",".join(sorted({a[0] for a in h}))
            mark = "OK " if exp in got or exp == "any" else "OK*"   # OK* = caught by a different rule
            print(f"  [{mark}] L{line:<4} expected={exp:<28} got={got}")
        else:
            missed += 1
            print(f"  [MISS] L{line:<4} expected={exp:<28} (not detected)")

# --- findings with no matching annotation (candidate noise) -------------------------------------
annotated = {(rel, l) for (rel, l) in expected}
extra = [a for a in actual if not any(a[1] == rel and abs(a[2] - l) <= 1 for (rel, l) in annotated)]
tot = detected + missed
print(f"\n{'-'*72}")
print(f" DETECTED {detected}/{tot} annotated CVE sinks    |    {len(extra)} un-annotated findings")
if extra:
    print(" un-annotated (triage — extra sink lines in a multi-sink PoC, or noise):")
    for r, f, l in sorted(extra):
        print(f"    [{r}] {f}:{l}")
print(f"{'='*72}")
sys.exit(0 if missed == 0 else 1)
