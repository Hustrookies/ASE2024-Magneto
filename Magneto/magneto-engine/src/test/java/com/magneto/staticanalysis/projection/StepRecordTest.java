package com.magneto.staticanalysis.projection;

import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * SPEC 3.3 的步骤级埋点。字段名固定为 SPEC 写定的 snake_case——
 * S5 的 run_projection_experiment.sh 直接按这些名字汇总 CSV，改名会静默破坏实验脚本。
 */
public class StepRecordTest {

    private StepRecord record() {
        StepRecord r = new StepRecord();
        r.setChainId("chain-3");
        r.setVulName("CVE-2019-10086");
        r.setStep(4);
        r.setKind(ProjectionKind.CONDITIONAL_SELECT);
        r.setBreakpoint(true);
        r.setFuzzSkipped(false);
        r.setTrialResult(false);
        r.setUpgraded(false);
        r.setStepTimeMs(1234L);
        r.setLlmCalls(2);
        r.setComplexity(37);
        r.setBranch(1);
        return r;
    }

    @Test
    public void emitsExactlyTheFieldsSpecifiedByTheSpec() {
        JSONObject json = JSONUtil.parseObj(record().toJsonLine());

        Set<String> expected = new HashSet<>(Arrays.asList(
                "chain_id", "vul_name", "step", "kind", "breakpoint", "fuzz_skipped",
                "trial_result", "upgraded", "step_time_ms", "llm_calls", "complexity", "branch"));

        assertEquals("埋点字段集必须与 SPEC 3.3 完全一致", expected, json.keySet());
    }

    @Test
    public void carriesTheStepValues() {
        JSONObject json = JSONUtil.parseObj(record().toJsonLine());

        assertEquals("chain-3", json.getStr("chain_id"));
        assertEquals("CVE-2019-10086", json.getStr("vul_name"));
        assertEquals(4, json.getInt("step").intValue());
        assertEquals("CONDITIONAL_SELECT", json.getStr("kind"));
        assertEquals(Boolean.TRUE, json.getBool("breakpoint"));
        assertEquals(Boolean.FALSE, json.getBool("fuzz_skipped"));
        assertEquals(1234L, json.getLong("step_time_ms").longValue());
        assertEquals(2, json.getInt("llm_calls").intValue());
        assertEquals(37, json.getInt("complexity").intValue());
        assertEquals(1, json.getInt("branch").intValue());
    }

    @Test
    public void aSkippedStepIsRecordedAsSuch() {
        StepRecord r = record();
        r.setKind(ProjectionKind.PASSTHROUGH);
        r.setBreakpoint(false);
        r.setFuzzSkipped(true);
        r.setTrialResult(true);
        r.setLlmCalls(0);

        JSONObject json = JSONUtil.parseObj(r.toJsonLine());

        assertEquals(Boolean.TRUE, json.getBool("fuzz_skipped"));
        assertEquals(Boolean.TRUE, json.getBool("trial_result"));
        assertEquals(0, json.getInt("llm_calls").intValue());
    }

    @Test
    public void anUpgradedStepIsDistinguishableFromANativeBreakpoint() {
        StepRecord r = record();
        r.setKind(ProjectionKind.PASSTHROUGH);
        r.setBreakpoint(true);
        r.setUpgraded(true);
        r.setFuzzSkipped(false);
        r.setTrialResult(false);

        JSONObject json = JSONUtil.parseObj(r.toJsonLine());

        assertTrue(json.getBool("upgraded"));
        assertTrue(json.getBool("breakpoint"));
        assertEquals("kind 记录静态判定，不随运行时升级改变", "PASSTHROUGH", json.getStr("kind"));
    }

    @Test
    public void oneLinePerRecordWithNoEmbeddedNewline() {
        String line = record().toJsonLine();

        assertFalseMsg(line.contains("\n"), "埋点必须是单行 JSON，否则无法按行汇总");
        assertTrue(line.startsWith("{") && line.endsWith("}"));
    }

    @Test
    public void missingScoresSerialiseAsNullRatherThanBeingDropped() {
        StepRecord r = record();
        r.setComplexity(null);
        r.setBranch(null);

        JSONObject json = JSONUtil.parseObj(r.toJsonLine());

        assertTrue(json.containsKey("complexity"));
        assertTrue(json.containsKey("branch"));
    }

    private static void assertFalseMsg(boolean condition, String message) {
        assertEquals(message, false, condition);
    }
}
