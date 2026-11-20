package com.magneto.staticanalysis.projection;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * SPEC S1: 骨架阶段所有步骤分类恒为 UNKNOWN（全断点）。
 * SPEC 3.2 R5: 无法解析时保守兜底为断点——宁可多验证，不可漏验证。
 */
public class ProjectionAnalyzerTest {

    private static final String CALLER = "<org.demo.Caller: void call()>";
    private static final String CALLEE = "<org.demo.Callee: void target(java.lang.String)>";

    @Test
    public void anUnanalysedStepIsUnknown() {
        StepProjection step = ProjectionAnalyzer.unresolvedStep(3, CALLER, CALLEE);

        assertEquals(ProjectionKind.UNKNOWN, step.getKind());
    }

    @Test
    public void anUnanalysedStepIsABreakpoint() {
        StepProjection step = ProjectionAnalyzer.unresolvedStep(3, CALLER, CALLEE);

        assertTrue("conservative fallback must block, never skip", step.isBreakpoint());
    }

    @Test
    public void anUnanalysedStepCarriesItsPositionAndSignatures() {
        StepProjection step = ProjectionAnalyzer.unresolvedStep(3, CALLER, CALLEE);

        assertEquals(3, step.getStepIndex());
        assertEquals(CALLER, step.getCallerSignature());
        assertEquals(CALLEE, step.getCalleeSignature());
    }

    @Test
    public void anUnanalysedStepHasEmptyButNonNullCollections() {
        StepProjection step = ProjectionAnalyzer.unresolvedStep(3, CALLER, CALLEE);

        assertTrue(step.getParamProjections().isEmpty());
        assertTrue(step.getProjectedConstraints().isEmpty());
        assertTrue(step.getTaintMapping().isEmpty());
    }
}
