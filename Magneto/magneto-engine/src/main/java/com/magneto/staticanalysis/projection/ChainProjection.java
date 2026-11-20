package com.magneto.staticanalysis.projection;

import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONConfig;
import cn.hutool.json.JSONObject;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

/**
 * 一条调用链的完整投影结果，序列化即 projection.json 的一个元素（SPEC 3.1）。
 */
@Getter
@Setter
public class ChainProjection {

    private static final JSONConfig JSON_CONFIG = JSONConfig.create().setIgnoreNullValue(false);

    private String chainId;

    private List<StepProjection> steps = new ArrayList<>();

    public ChainProjection() {
    }

    public ChainProjection(String chainId) {
        this.chainId = chainId;
    }

    public void addStep(StepProjection step) {
        this.steps.add(step);
    }

    /**
     * 实时派生，不缓存：始终与 steps 里的 breakpoint 一致。
     * 注意 projection.json 写盘于 fuzz 之前，故其中的断点数是**静态**判定结果，
     * 不含运行时升级；升级情况见 projection-steps.jsonl。
     */
    public int getBreakpointCount() {
        int count = 0;
        for (StepProjection step : steps) {
            if (step.isBreakpoint()) {
                count++;
            }
        }
        return count;
    }

    /**
     * 显式序列化。不走 hutool 的 bean 内省：它要求 getter/setter 成对，
     * 派生的 breakpointCount 会被静默丢弃；同时关掉 ignoreNullValue，
     * 保证 projection.json 的字段集恒定，下游脚本不必判空。
     */
    public JSONObject toJSONObject() {
        JSONObject json = new JSONObject(JSON_CONFIG);
        json.set("chainId", chainId);

        JSONArray stepArray = new JSONArray(JSON_CONFIG);
        for (StepProjection step : steps) {
            stepArray.add(new JSONObject(step, JSON_CONFIG));
        }
        json.set("steps", stepArray);

        json.set("breakpointCount", getBreakpointCount());
        return json;
    }
}
