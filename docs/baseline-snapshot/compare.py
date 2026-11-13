#!/usr/bin/env python3
"""Compare a Magneto run against the S0 baseline snapshot.

Usage: compare.py <run-output-dir> <run.log>

Exit 0 = identical to baseline (the `off`-mode acceptance criterion in SPEC S1/S4).
Exit 1 = divergence; details printed per check.
"""
import json
import re
import sys
from pathlib import Path

SNAPSHOT = Path(__file__).resolve().parent

NORMALIZATIONS = [
    (re.compile(r"elapsed time: [\d.]+s"), "elapsed time: <T>"),
    (re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ +\w+ +\d+ --- "), ""),
    (re.compile(r"/[^\s,\]]*?/output"), "<OUTPUT>"),
    (re.compile(r"/[^\s,\]]*?/test-tool-demo"), "<PROJECT>"),
]


def key_lines(log_path):
    out = []
    for raw in Path(log_path).read_text(errors="replace").splitlines():
        if not re.search(r"TimeUtil|input args|has been written", raw):
            continue
        line = raw
        for pattern, repl in NORMALIZATIONS:
            line = pattern.sub(repl, line)
        out.append(line.strip())
    return out


def normalized_chains(path):
    data = json.loads(Path(path).read_text())
    return sorted(json.dumps(c, sort_keys=True) for c in data)


def report(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    return ok


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    out_dir, log_path = Path(sys.argv[1]), sys.argv[2]

    results = []

    for name in ("dependency-chain.json", "puring-method-call-chain.json"):
        baseline = (SNAPSHOT / "output" / name).read_text()
        current_path = out_dir / name
        if not current_path.exists():
            results.append(report(name, False, "missing in run output"))
            continue
        current = current_path.read_text()
        results.append(report(name, baseline == current,
                              "" if baseline == current else "byte content differs"))

    baseline_norm = (SNAPSHOT / "output" / "method-call-chain.normalized.json").read_text()
    current_path = out_dir / "method-call-chain.json"
    if not current_path.exists():
        results.append(report("method-call-chain.json (set)", False, "missing in run output"))
    else:
        baseline_set = sorted(json.dumps(c, sort_keys=True) for c in json.loads(baseline_norm))
        current_set = normalized_chains(current_path)
        sets_equal = baseline_set == current_set
        results.append(report("method-call-chain.json (set)", sets_equal,
                              f"{len(current_set)} chains"
                              + ("" if sets_equal else ", chain set differs (order-insensitive)")))

    baseline_log = [ln for ln in key_lines(SNAPSHOT / "run.key.log") if ln]
    current_log = key_lines(log_path)
    if baseline_log == current_log:
        results.append(report("key log", True, f"{len(current_log)} lines"))
    else:
        added = [ln for ln in current_log if ln not in baseline_log]
        removed = [ln for ln in baseline_log if ln not in current_log]
        results.append(report("key log", False,
                              f"{len(added)} added, {len(removed)} removed"))
        for ln in added[:20]:
            print(f"    + {ln}")
        for ln in removed[:20]:
            print(f"    - {ln}")

    print()
    print("IDENTICAL TO BASELINE" if all(results) else "DIVERGES FROM BASELINE")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
