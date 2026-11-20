#!/usr/bin/env python3
"""汇总 run_projection_experiment.sh 各次重复的产物，产出步骤级 CSV 与含方差的聚合指标。

用法：aggregate_projection_results.py --mode-dir <out>/<mode> --mode <mode> --reps <N>

产物：
  <mode-dir>/steps.csv      步骤级明细。source=projection-jsonl 来自埋点（仅 full 模式产出），
                            source=report-json 来自 report.json 的成功步（所有模式都有）
  <mode-dir>/chains.csv     链级结果：success_step / fuzz_chain_time_ms
  <mode-dir>/summary.json   跨重复的聚合指标，含均值与样本标准差

LLM 调用次数的口径（两种模式来源不同，已在 summary 里注明）：
  full            —— 埋点 llm_calls 之和，含单次合成与完整 fuzz 的全部真实请求
  off / classify  —— run.log 中 "the gpt answer:" 的出现次数。off/classify 模式下
                     每一步都走完整 fuzzing()，该日志每次 LLM 调用恰好打印一次；
                     不能给 off 模式加埋点日志，否则就破坏了它与基线的逐行一致性。
"""
import argparse
import csv
import json
import math
import re
from pathlib import Path

GPT_ANSWER_MARKER = "the gpt answer:"

JSONL_COLUMNS = ["mode", "rep", "source", "chain_id", "vul_name", "step", "kind", "breakpoint",
                 "fuzz_skipped", "trial_result", "upgraded", "step_time_ms", "llm_calls",
                 "complexity", "branch"]

REPORT_COLUMNS = ["mode", "rep", "source", "chain_index", "vul_name", "success_step_index",
                  "consume_time_ms", "projection_kind", "projection_fuzz_skipped",
                  "projection_upgraded", "projection_llm_calls"]

CHAIN_COLUMNS = ["mode", "rep", "chain_index", "vul_name", "chain_len", "success_step",
                 "fuzz_chain_time_ms"]


def mean(values):
    return sum(values) / len(values) if values else None


def stdev(values):
    """样本标准差（n-1）。少于 2 个样本时返回 None——单次重复谈不上方差。"""
    if len(values) < 2:
        return None
    mu = mean(values)
    return math.sqrt(sum((v - mu) ** 2 for v in values) / (len(values) - 1))


def stat_block(values):
    return {"n": len(values), "mean": mean(values), "stdev": stdev(values),
            "min": min(values) if values else None,
            "max": max(values) if values else None}


def read_json(path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def collect(mode_dir, mode, reps):
    step_rows, chain_rows, per_rep = [], [], []

    for rep in range(1, reps + 1):
        rep_dir = mode_dir / f"rep{rep}"
        out_dir = rep_dir / "output"
        info = {"rep": rep, "exit_status": None, "llm_calls": None, "llm_source": None}

        status_file = rep_dir / "exit-status"
        if status_file.exists():
            try:
                info["exit_status"] = int(status_file.read_text().strip())
            except ValueError:
                pass

        # ---- 埋点（仅 full 模式产出）----
        jsonl = out_dir / "projection-steps.jsonl"
        jsonl_calls = 0
        if jsonl.exists():
            for line in jsonl.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                row = {"mode": mode, "rep": rep, "source": "projection-jsonl"}
                for col in JSONL_COLUMNS[3:]:
                    row[col] = r.get(col)
                step_rows.append(row)
                jsonl_calls += r.get("llm_calls") or 0
            info["llm_calls"] = jsonl_calls
            info["llm_source"] = "projection-jsonl"

        # ---- 权威口径：output/llm-calls.txt（真实 API 请求数，所有模式一致）----
        calls_file = out_dir / "llm-calls.txt"
        if calls_file.exists():
            try:
                info["llm_calls"] = int(calls_file.read_text().strip())
                info["llm_source"] = "llm-calls.txt (real API requests)"
            except ValueError:
                pass

        # ---- run.log 里的 LLM 调用计数（旧口径，含缓存命中，仅在无 llm-calls.txt 时用）----
        run_log = rep_dir / "run.log"
        if run_log.exists():
            info["log_gpt_answers"] = sum(1 for line in run_log.open(errors="replace")
                                          if GPT_ANSWER_MARKER in line)
            if info["llm_calls"] is None:
                info["llm_calls"] = info["log_gpt_answers"]
                info["llm_source"] = "run.log marker (含缓存命中，偏高)"

        # ---- report.json ----
        report = read_json(out_dir / "report.json")
        if report:
            info["analysis_time_ms"] = report.get("analysisTime")
            info["fuzz_time_ms"] = report.get("fuzzTime")
            info["total_success_step"] = report.get("totalSuccessStep")

            for ci, chain in enumerate(report.get("fuzzChainList") or []):
                chain_len = len(chain.get("methodCallList") or [])
                for vul, res in (chain.get("fuzzResultMap") or {}).items():
                    chain_rows.append({
                        "mode": mode, "rep": rep, "chain_index": ci, "vul_name": vul,
                        "chain_len": chain_len,
                        "success_step": res.get("successStep"),
                        "fuzz_chain_time_ms": res.get("fuzzChainTime"),
                    })
                    for si, step in enumerate(res.get("fuzzStepList") or []):
                        step_rows.append({
                            "mode": mode, "rep": rep, "source": "report-json",
                            "chain_index": ci, "vul_name": vul, "success_step_index": si,
                            "consume_time_ms": step.get("consumeTime"),
                            "projection_kind": step.get("projectionKind"),
                            "projection_fuzz_skipped": step.get("projectionFuzzSkipped"),
                            "projection_upgraded": step.get("projectionUpgraded"),
                            "projection_llm_calls": step.get("projectionLlmCalls"),
                        })

        # ---- projection.json：断点率 ----
        projection = read_json(out_dir / "projection.json")
        if projection:
            steps = [s for c in projection for s in c.get("steps", [])]
            info["projection_steps"] = len(steps)
            info["projection_breakpoints"] = sum(1 for s in steps if s.get("breakpoint"))
            kinds = {}
            for s in steps:
                kinds[s.get("kind")] = kinds.get(s.get("kind"), 0) + 1
            info["kind_histogram"] = kinds

        per_rep.append(info)

    return step_rows, chain_rows, per_rep


def write_csv(path, rows, columns):
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode-dir", required=True)
    ap.add_argument("--mode", required=True)
    ap.add_argument("--reps", type=int, required=True)
    args = ap.parse_args()

    mode_dir = Path(args.mode_dir)
    step_rows, chain_rows, per_rep = collect(mode_dir, args.mode, args.reps)

    columns = JSONL_COLUMNS + [c for c in REPORT_COLUMNS if c not in JSONL_COLUMNS]
    write_csv(mode_dir / "steps.csv", step_rows, columns)
    write_csv(mode_dir / "chains.csv", chain_rows, CHAIN_COLUMNS)

    ok_reps = [r for r in per_rep if r.get("exit_status") == 0]
    jsonl = [r for r in step_rows if r["source"] == "projection-jsonl"]

    summary = {
        "mode": args.mode,
        "reps_requested": args.reps,
        "reps_completed": len(ok_reps),
        "llm_call_counting": {
            "preferred": "output/llm-calls.txt — 真实 API 请求数，缓存命中不计，所有模式同一口径",
            "fallback_jsonl": "sum of llm_calls in projection-steps.jsonl (仅 full)",
            "fallback_log": 'occurrences of "the gpt answer:" in run.log — 含缓存命中，偏高，不可跨模式比较',
        },
        "per_rep": per_rep,
        "across_reps": {
            "total_success_step": stat_block([r["total_success_step"] for r in ok_reps
                                              if r.get("total_success_step") is not None]),
            "fuzz_time_ms": stat_block([r["fuzz_time_ms"] for r in ok_reps
                                        if r.get("fuzz_time_ms") is not None]),
            "llm_calls": stat_block([r["llm_calls"] for r in ok_reps
                                     if r.get("llm_calls") is not None]),
        },
        "chain_level": {
            "success_step": stat_block([c["success_step"] for c in chain_rows
                                        if c.get("success_step") is not None]),
            "fuzz_chain_time_ms": stat_block([c["fuzz_chain_time_ms"] for c in chain_rows
                                              if c.get("fuzz_chain_time_ms") is not None]),
        },
        "projection": {
            "skipped_steps": sum(1 for r in jsonl if r.get("fuzz_skipped")),
            "upgraded_steps": sum(1 for r in jsonl if r.get("upgraded")),
            "total_steps_instrumented": len(jsonl),
            "llm_calls_total_from_jsonl": sum(r.get("llm_calls") or 0 for r in jsonl),
        } if jsonl else None,
    }

    (mode_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))

    print(f"[{args.mode}] reps {len(ok_reps)}/{args.reps} ok | "
          f"step rows {len(step_rows)} (jsonl {len(jsonl)}) | chain rows {len(chain_rows)}")
    ts = summary["across_reps"]["total_success_step"]
    if ts["mean"] is not None:
        sd = "n/a" if ts["stdev"] is None else f"{ts['stdev']:.2f}"
        print(f"[{args.mode}] total_success_step mean={ts['mean']:.2f} stdev={sd} "
              f"range=[{ts['min']},{ts['max']}]")


if __name__ == "__main__":
    main()
