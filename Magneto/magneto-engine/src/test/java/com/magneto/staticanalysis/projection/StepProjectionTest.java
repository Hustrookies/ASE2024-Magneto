package com.magneto.staticanalysis.projection;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * SPEC 3.1 breakpoint 由 kind 派生；SPEC 3.3 promoteToBreakpoint() 在试运行失败后升级断点而不改 kind。
 * 埋点字段 upgraded 用于区分「原生断点」与「运行时升级断点」。
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

    @Test
    public void promoteToBreakpointMakesANonBreakpointStepBlocking() {
        StepProjection step = step(ProjectionKind.PASSTHROUGH);

        step.promoteToBreakpoint();

        assertTrue(step.isBreakpoint());
    }

    @Test
    public void promoteToBreakpointKeepsTheOriginalKind() {
        StepProjection step = step(ProjectionKind.PASSTHROUGH);

        step.promoteToBreakpoint();

        assertEquals(ProjectionKind.PASSTHROUGH, step.getKind());
    }

    @Test
    public void promoteToBreakpointMarksTheStepUpgraded() {
        StepProjection step = step(ProjectionKind.PASSTHROUGH);
        assertFalse(step.isUpgraded());

        step.promoteToBreakpoint();

        assertTrue(step.isUpgraded());
    }

    @Test
    public void aNativeBreakpointStaysDistinguishableFromAnUpgradedOne() {
        StepProjection step = step(ProjectionKind.UNKNOWN);

        step.promoteToBreakpoint();

        assertTrue(step.isBreakpoint());
        assertFalse("native breakpoints must not be reported as runtime upgrades", step.isUpgraded());
    }

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
