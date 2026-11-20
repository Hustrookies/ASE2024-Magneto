#!/usr/bin/env python3
"""对比同一案例下 off / full（或 classify）多轮重复的实验结果。

用法：
  compare_modes.py <experiment-dir> [<experiment-dir> ...]

每个 <experiment-dir> 下应有若干 <mode>/summary.json（由 run_projection_experiment.sh 产出）。
输出：跨模式的指标对照表 + SPEC S5 验收第 1 项的判定（full 成功率是否不低于 off）。

单次运行的成败在本课题上是不稳定的（见 docs/s4-evidence/VERIFICATION.md 的归因记录），
所以这里一律报均值与样本标准差，并对每轮做配对比较，而不是只看一次结果。
"""
import json
import sys
from pathlib import Path


def load_modes(exp_dir):
    modes = {}
    for summary_path in sorted(Path(exp_dir).glob("*/summary.json")):
        modes[summary_path.parent.name] = json.loads(summary_path.read_text())
    return modes


def fmt(stat):
    if not stat or stat.get("mean") is None:
        return "n/a"
    sd = stat.get("stdev")
    sd_txt = "n/a" if sd is None else f"{sd:.2f}"
    return f"{stat['mean']:.2f} ± {sd_txt}  [{stat['min']}, {stat['max']}] n={stat['n']}"


def chain_success_series(mode_dir):
    """按 (rep, chain_index, vul) 取 success_step，用于 off/full 的配对比较。"""
    path = Path(mode_dir) / "chains.csv"
    if not path.exists():
        return {}
    import csv
    out = {}
    with path.open() as fh:
        for row in csv.DictReader(fh):
            key = (row["rep"], row["chain_index"], row["vul_name"])
            out[key] = int(row["success_step"]) if row["success_step"] else 0
    return out


def report(exp_dir):
    modes = load_modes(exp_dir)
    if not modes:
        print(f"{exp_dir}: 没有找到任何 summary.json")
        return None

    print("=" * 100)
    print(f"案例: {exp_dir}")
    print(f"模式: {', '.join(modes)}")
    print("=" * 100)

    rows = [
        ("完成轮数", lambda s: f"{s['reps_completed']}/{s['reps_requested']}"),
        ("总成功步数/轮", lambda s: fmt(s["across_reps"]["total_success_step"])),
        ("fuzz 总耗时 ms/轮", lambda s: fmt(s["across_reps"]["fuzz_time_ms"])),
        ("LLM 调用数/轮", lambda s: fmt(s["across_reps"]["llm_calls"])),
    ]

    header = f"{'指标':<22}" + "".join(f"{m:>34}" for m in modes)
    print(header)
    print("-" * len(header))
    for label, extract in rows:
        line = f"{label:<22}"
        for m in modes:
            try:
                line += f"{extract(modes[m]):>34}"
            except (KeyError, TypeError):
                line += f"{'n/a':>34}"
        print(line)

    for m, s in modes.items():
        proj = s.get("projection")
        if proj:
            print(f"\n[{m}] 投影埋点: 步骤 {proj['total_steps_instrumented']} | "
                  f"跳过 {proj['skipped_steps']} | 升级 {proj['upgraded_steps']} | "
                  f"LLM 调用 {proj['llm_calls_total']}")
        rep0 = (s.get("per_rep") or [{}])[0]
        if rep0.get("kind_histogram"):
            total = sum(rep0["kind_histogram"].values())
            bp = rep0.get("projection_breakpoints", 0)
            print(f"[{m}] 静态分类: 步骤 {total} | 断点 {bp} ({100 * bp / max(total, 1):.0f}%) | "
                  f"{rep0['kind_histogram']}")

    # ---- 配对比较：同一 (rep, chain, vul) 下 基线臂 vs 其它各臂 的 success_step ----
    baseline = "off" if "off" in modes else sorted(modes)[0]
    base_series = chain_success_series(Path(exp_dir) / baseline)
    verdicts = {}

    for arm in sorted(modes):
        if arm == baseline:
            continue
        arm_series = chain_success_series(Path(exp_dir) / arm)
        common = sorted(set(base_series) & set(arm_series))
        if not common:
            continue

        print(f"\n{'-' * 100}")
        print(f"配对比较 {baseline} vs {arm}（同一 rep + 同一链）: {len(common)} 对")
        better = worse = same = 0
        for key in common:
            delta = arm_series[key] - base_series[key]
            if delta > 0:
                better += 1
            elif delta < 0:
                worse += 1
            else:
                same += 1
        print(f"  {arm} 更好: {better}   持平: {same}   {arm} 更差: {worse}")

        base_mean = sum(base_series[k] for k in common) / len(common)
        arm_mean = sum(arm_series[k] for k in common) / len(common)
        print(f"  配对均值 success_step: {baseline}={base_mean:.3f}  {arm}={arm_mean:.3f}  "
              f"差值={arm_mean - base_mean:+.3f}")

        verdict = "PASS" if arm_mean >= base_mean else "NEEDS ATTRIBUTION"
        print(f"\n  SPEC S5 验收 1（{arm} 成功率不低于 {baseline}）: {verdict}")
        if verdict != "PASS":
            print("  需逐条归因：先看 upgraded 计数区分「投影误判」与「fuzz/LLM 随机波动」，")
            print("  再看标准差与配对差异分布——单次差异不构成结论。")
        verdicts[arm] = {"baseline": baseline, "verdict": verdict,
                         "base_mean": base_mean, "arm_mean": arm_mean,
                         "pairs": len(common), "better": better, "same": same, "worse": worse}

    return verdicts


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    results = {}
    for exp in sys.argv[1:]:
        results[exp] = report(exp)
        print()

    print("=" * 100)
    print("阶段 A 总验收（SPEC S5 验收 1）汇总")
    print("=" * 100)
    for exp, verdicts in results.items():
        if not verdicts:
            print(f"  {Path(exp).name:<28} 无可比较的臂")
            continue
        for arm, v in verdicts.items():
            print(f"  {Path(exp).name:<20} {v['baseline']} vs {arm:<16} {v['verdict']:<18} "
                  f"{v['base_mean']:.3f} -> {v['arm_mean']:.3f} "
                  f"(配对 {v['pairs']}，更好 {v['better']}/持平 {v['same']}/更差 {v['worse']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
