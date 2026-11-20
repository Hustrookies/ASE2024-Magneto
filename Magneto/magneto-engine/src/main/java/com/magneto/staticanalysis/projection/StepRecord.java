package com.magneto.staticanalysis.projection;

import cn.hutool.json.JSONConfig;
import cn.hutool.json.JSONObject;
import lombok.Getter;
import lombok.Setter;

/**
 * SPEC 3.3 的步骤级埋点记录。每个 fuzz 步骤一行，S5 的实验脚本按行汇总成 CSV。
 *
 * 字段名固定为 SPEC 写定的 snake_case，且字段集恒定（关闭 ignoreNullValue）——
 * 改名或漏字段会静默破坏实验脚本的汇总。
 */
@Getter
@Setter
public class StepRecord {

    private static final JSONConfig JSON_CONFIG = JSONConfig.create().setIgnoreNullValue(false);

    private String chainId;

    private String vulName;

    /** reverseChainList 下标，与 StepProjection.stepIndex 一致。 */
    private int step;

    /** 静态判定结果。运行时升级不改它——kind 与 breakpoint 的差异正是阶段 B 要统计的误判样本。 */
    private ProjectionKind kind;

    private boolean breakpoint;

    /** 本步是否跳过了定向 fuzz（直接合成 + 单次试运行成功）。 */
    private boolean fuzzSkipped;

    /** 直接合成的试运行结果。未尝试时为 false。 */
    private boolean trialResult;

    /** 试运行失败后被抬升为断点。 */
    private boolean upgraded;

    private long stepTimeMs;

    /** 本步实际发生的 LLM 调用次数。跳过的步骤应为 0，这是 S5 的核心指标。 */
    private int llmCalls;

    private Integer complexity;

    private Integer branch;

    public String toJsonLine() {
        JSONObject json = new JSONObject(JSON_CONFIG);
        json.set("chain_id", chainId);
        json.set("vul_name", vulName);
        json.set("step", step);
        json.set("kind", kind == null ? null : kind.name());
        json.set("breakpoint", breakpoint);
        json.set("fuzz_skipped", fuzzSkipped);
        json.set("trial_result", trialResult);
        json.set("upgraded", upgraded);
        json.set("step_time_ms", stepTimeMs);
        json.set("llm_calls", llmCalls);
        json.set("complexity", complexity);
        json.set("branch", branch);
        return json.toString();
    }
}
