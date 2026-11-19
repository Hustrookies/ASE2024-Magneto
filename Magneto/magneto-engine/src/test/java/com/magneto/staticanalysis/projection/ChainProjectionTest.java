package com.magneto.staticanalysis.projection;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class ChainProjectionTest {

    private StepProjection step(int index, ProjectionKind kind) {
        StepProjection step = new StepProjection();
        step.setStepIndex(index);
        step.setCallerSignature("<org.demo.C" + index + ": void call()>");
        step.setCalleeSignature("<org.demo.C" + (index - 1) + ": void target()>");
        step.setKind(kind);
        return step;
    }

    @Test
    public void breakpointCountIsZeroWhenNoStepBlocks() {
        ChainProjection projection = new ChainProjection("chain-0");
        projection.addStep(step(1, ProjectionKind.PASSTHROUGH));
        projection.addStep(step(2, ProjectionKind.SIMPLE_DERIVATION));

        assertEquals(0, projection.getBreakpointCount());
    }

    @Test
    public void breakpointCountCountsEveryBlockingStep() {
        ChainProjection projection = new ChainProjection("chain-0");
        projection.addStep(step(1, ProjectionKind.PASSTHROUGH));
        projection.addStep(step(2, ProjectionKind.COMPLEX_CONSTRUCTION));
        projection.addStep(step(3, ProjectionKind.UNKNOWN));

        assertEquals(2, projection.getBreakpointCount());
    }

    @Test
    public void breakpointCountReflectsARuntimePromotion() {
        ChainProjection projection = new ChainProjection("chain-0");
        StepProjection passthrough = step(1, ProjectionKind.PASSTHROUGH);
        projection.addStep(passthrough);
        assertEquals(0, projection.getBreakpointCount());

        passthrough.promoteToBreakpoint();

        assertEquals(1, projection.getBreakpointCount());
    }

    @Test
    public void stepsKeepInsertionOrder() {
        ChainProjection projection = new ChainProjection("chain-0");
        StepProjection first = step(1, ProjectionKind.UNKNOWN);
        StepProjection second = step(2, ProjectionKind.UNKNOWN);

        projection.addStep(first);
        projection.addStep(second);

        assertEquals(2, projection.getSteps().size());
        assertSame(first, projection.getSteps().get(0));
        assertSame(second, projection.getSteps().get(1));
    }

    @Test
    public void aChainWithNoStepHasNoBreakpoint() {
        ChainProjection projection = new ChainProjection("chain-0");

        assertTrue(projection.getSteps().isEmpty());
        assertEquals(0, projection.getBreakpointCount());
    }
}
