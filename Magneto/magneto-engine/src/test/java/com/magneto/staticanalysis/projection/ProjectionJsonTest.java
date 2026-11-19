package com.magneto.staticanalysis.projection;

import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * 锁定 projection.json 的 schema（SPEC 3.1）。S1 验收「字段齐全」与 S3 的
 * docs/projection-schema.md 都以这里为准，字段改名会直接在此失败。
 */
public class ProjectionJsonTest {

    private static final String CALLER = "<org.demo.Caller: void call(java.lang.String)>";
    private static final String CALLEE = "<org.demo.Callee: void target(java.lang.String)>";

    private ParamProjection param() {
        ParamProjection param = new ParamProjection();
        param.setCalleeArgIndex(0);
        param.setSourceKind(ProjectionSource.CALLER_PARAM);
        param.setCallerParamIndex(1);
        param.setDerivationOps(Collections.singletonList("GET_FIELD(getName)"));
        return param;
    }

    private StepProjection step() {
        StepProjection step = new StepProjection();
        step.setStepIndex(1);
        step.setCallerSignature(CALLER);
        step.setCalleeSignature(CALLEE);
        step.setKind(ProjectionKind.SIMPLE_DERIVATION);
        step.setParamProjections(Collections.singletonList(param()));
        step.setProjectedConstraints(Arrays.asList("形参 1 的 getName() 须返回 \"x\""));
        step.setTaintMapping(Collections.singletonMap(0, Collections.singletonList("PARAM " + CALLER + " #1")));
        step.setEvidence("r0 := @parameter1: java.lang.String");
        step.setComplexityScore(34);
        step.setBranchScore(1);
        return step;
    }

    @Test
    public void paramProjectionCarriesEverySpecField() {
        JSONObject json = JSONUtil.parseObj(param());

        assertEquals(0, json.getInt("calleeArgIndex").intValue());
        assertEquals(1, json.getInt("callerParamIndex").intValue());
        assertEquals("CALLER_PARAM", json.getStr("sourceKind"));
        assertEquals("GET_FIELD(getName)", json.getJSONArray("derivationOps").getStr(0));
    }

    @Test
    public void stepProjectionCarriesEverySpecField() {
        JSONObject json = JSONUtil.parseObj(step());

        assertEquals(1, json.getInt("stepIndex").intValue());
        assertEquals(CALLER, json.getStr("callerSignature"));
        assertEquals(CALLEE, json.getStr("calleeSignature"));
        assertEquals("SIMPLE_DERIVATION", json.getStr("kind"));
        assertEquals(Boolean.FALSE, json.getBool("breakpoint"));
        assertEquals(Boolean.FALSE, json.getBool("upgraded"));
        assertEquals("r0 := @parameter1: java.lang.String", json.getStr("evidence"));
        assertEquals(34, json.getInt("complexityScore").intValue());
        assertEquals(1, json.getInt("branchScore").intValue());
        assertEquals(1, json.getJSONArray("paramProjections").size());
        assertEquals(1, json.getJSONArray("projectedConstraints").size());
        assertTrue(json.getJSONObject("taintMapping").containsKey("0"));
    }

    @Test
    public void chainProjectionCarriesEverySpecField() {
        ChainProjection projection = new ChainProjection("chain-0");
        projection.addStep(step());

        JSONObject json = projection.toJSONObject();

        assertEquals("chain-0", json.getStr("chainId"));
        assertEquals(1, json.getJSONArray("steps").size());
        assertEquals(0, json.getInt("breakpointCount").intValue());
    }

    @Test
    public void breakpointCountIsRecomputedAtSerialisationTime() {
        ChainProjection projection = new ChainProjection("chain-0");
        StepProjection promoted = step();
        projection.addStep(promoted);
        assertEquals(0, projection.toJSONObject().getInt("breakpointCount").intValue());

        promoted.promoteToBreakpoint();

        assertEquals("a runtime promotion must reach the serialised report",
                1, projection.toJSONObject().getInt("breakpointCount").intValue());
    }

    @Test
    public void anUnknownStepSerialisesAsABreakpoint() {
        JSONObject json = JSONUtil.parseObj(ProjectionAnalyzer.unresolvedStep(2, CALLER, CALLEE));

        assertEquals("UNKNOWN", json.getStr("kind"));
        assertEquals(Boolean.TRUE, json.getBool("breakpoint"));
    }

    /**
     * S1 骨架阶段 evidence / paramProjections / projectedConstraints 尚未填充。
     * 字段必须仍然出现在 JSON 里（值为 null 或空），否则 projection.json 的 schema
     * 会随分析阶段推进而变动，下游汇总脚本无法稳定取值。
     */
    @Test
    public void unsetFieldsStillAppearInTheSerialisedChain() {
        ChainProjection projection = new ChainProjection("chain-0");
        projection.addStep(ProjectionAnalyzer.unresolvedStep(1, CALLER, CALLEE));

        JSONObject json = projection.toJSONObject().getJSONArray("steps").getJSONObject(0);

        for (String field : Arrays.asList("stepIndex", "callerSignature", "calleeSignature", "kind",
                "breakpoint", "upgraded", "paramProjections", "projectedConstraints",
                "taintMapping", "evidence", "complexityScore", "branchScore")) {
            assertTrue("field missing from projection.json: " + field, json.containsKey(field));
        }
    }
}
