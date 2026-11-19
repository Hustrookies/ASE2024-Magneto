package com.magneto.staticanalysis.projection;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * SPEC 3.1 断点判定：breakpoint = kind ∈ {COMPLEX_CONSTRUCTION, CONDITIONAL_SELECT, UNKNOWN}
 */
public class ProjectionKindTest {

    @Test
    public void complexConstructionIsBreakpoint() {
        assertTrue(ProjectionKind.COMPLEX_CONSTRUCTION.isBreakpointKind());
    }

    @Test
    public void conditionalSelectIsBreakpoint() {
        assertTrue(ProjectionKind.CONDITIONAL_SELECT.isBreakpointKind());
    }

    @Test
    public void unknownIsBreakpoint() {
        assertTrue(ProjectionKind.UNKNOWN.isBreakpointKind());
    }

    @Test
    public void passthroughIsNotBreakpoint() {
        assertFalse(ProjectionKind.PASSTHROUGH.isBreakpointKind());
    }

    @Test
    public void simpleDerivationIsNotBreakpoint() {
        assertFalse(ProjectionKind.SIMPLE_DERIVATION.isBreakpointKind());
    }
}
