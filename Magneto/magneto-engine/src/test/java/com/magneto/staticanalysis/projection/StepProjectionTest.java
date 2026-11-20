package com.magneto.staticanalysis.projection;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * SPEC 3.1：breakpoint 由 kind 派生。运行时升级不改本对象（见 StepRecord / projection-steps.jsonl），
 * 因为 projection.json 在 fuzz 之前就已写盘，且同一 ChainProjection 会被同链的多个 CVE 共享。
 */
public class StepProjectionTest {

    private static final String CALLER = "<org.demo.Caller: void call()>";
    private static final String CALLEE = "<org.demo.Callee: void target(java.lang.String)>";

    private StepProjection step(ProjectionKind kind) {
        StepProjection step = new StepProjection();
        step.setStepIndex(2);
        step.setCallerSignature(CALLER);
        step.setCalleeSignature(CALLEE);
        step.setKind(kind);
        return step;
    }

    @Test
    public void breakpointFollowsPassthroughKind() {
        assertFalse(step(ProjectionKind.PASSTHROUGH).isBreakpoint());
    }

    @Test
    public void breakpointFollowsSimpleDerivationKind() {
        assertFalse(step(ProjectionKind.SIMPLE_DERIVATION).isBreakpoint());
    }

    @Test
    public void breakpointFollowsComplexConstructionKind() {
        assertTrue(step(ProjectionKind.COMPLEX_CONSTRUCTION).isBreakpoint());
    }

    @Test
    public void breakpointFollowsConditionalSelectKind() {
        assertTrue(step(ProjectionKind.CONDITIONAL_SELECT).isBreakpoint());
    }

    @Test
    public void breakpointFollowsUnknownKind() {
        assertTrue(step(ProjectionKind.UNKNOWN).isBreakpoint());
    }

    /**
     * 升级语义已移出本类：projection.json 写盘于 fuzz 之前，运行时升级记在 StepRecord 里。
     * 这里只保留「breakpoint 随 kind 变化」这一静态语义。
     */
    @Test
    public void reclassifyingAStepResetsItsBreakpointFlag() {
        StepProjection step = step(ProjectionKind.UNKNOWN);
        assertTrue(step.isBreakpoint());

        step.setKind(ProjectionKind.PASSTHROUGH);

        assertFalse(step.isBreakpoint());
    }

    @Test
    public void collectionsAreNeverNull() {
        StepProjection step = step(ProjectionKind.UNKNOWN);

        assertTrue(step.getParamProjections().isEmpty());
        assertTrue(step.getProjectedConstraints().isEmpty());
        assertTrue(step.getTaintMapping().isEmpty());
    }
}
