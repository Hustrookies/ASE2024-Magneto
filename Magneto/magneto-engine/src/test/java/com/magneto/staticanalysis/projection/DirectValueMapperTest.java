package com.magneto.staticanalysis.projection;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

/**
 * SPEC 3.3：非断点步骤免 LLM 直接合成种子。
 * 这里只验证「把 callee 实参值按投影填进 caller 形参数组」这一步——纯 Java 对象，不需要 Soot。
 *
 * 红线：任何不确定（类型不符、下标越界、原始类型拿到 null）都必须返回 false，
 * 让调用方放弃直接合成、退回完整 fuzz，而不是塞一个错值进去。
 */
public class DirectValueMapperTest {

    private ParamProjection param(int calleeArg, ProjectionSource source, int callerParam, String... ops) {
        ParamProjection p = new ParamProjection();
        p.setCalleeArgIndex(calleeArg);
        p.setSourceKind(source);
        p.setCallerParamIndex(callerParam);
        p.setDerivationOps(new ArrayList<>(Arrays.asList(ops)));
        return p;
    }

    private StepProjection step(ProjectionKind kind, ParamProjection... params) {
        StepProjection s = new StepProjection();
        s.setStepIndex(1);
        s.setKind(kind);
        s.setParamProjections(new ArrayList<>(Arrays.asList(params)));
        return s;
    }

    @Test
    public void copiesEachCalleeArgumentOntoItsCallerParameter() {
        Object bean = new Object();
        Object[] callerParams = new Object[2];
        Class<?>[] types = {Object.class, String.class};

        boolean ok = DirectValueMapper.apply(callerParams, types, new Object[]{bean, "class"},
                step(ProjectionKind.PASSTHROUGH,
                        param(0, ProjectionSource.CALLER_PARAM, 0),
                        param(1, ProjectionSource.CALLER_PARAM, 1)));

        assertTrue(ok);
        assertSame(bean, callerParams[0]);
        assertEquals("class", callerParams[1]);
    }

    @Test
    public void honoursACrossMappingBetweenArgumentAndParameterIndices() {
        // callee 实参 0 <- caller 形参 1；callee 实参 1 <- caller 形参 0
        Object calleeArg0 = new Object();
        String calleeArg1 = "class";
        Object[] callerParams = new Object[2];
        Class<?>[] types = {String.class, Object.class};   // 形参 0 是 String，形参 1 是 Object

        boolean ok = DirectValueMapper.apply(callerParams, types, new Object[]{calleeArg0, calleeArg1},
                step(ProjectionKind.PASSTHROUGH,
                        param(0, ProjectionSource.CALLER_PARAM, 1),
                        param(1, ProjectionSource.CALLER_PARAM, 0)));

        assertTrue(ok);
        assertEquals("供给了 callee 实参 1 的是 caller 形参 0", calleeArg1, callerParams[0]);
        assertSame("供给了 callee 实参 0 的是 caller 形参 1", calleeArg0, callerParams[1]);
    }

    @Test
    public void unboxesAWrapperValueIntoAPrimitiveParameter() {
        Object[] callerParams = new Object[1];
        Class<?>[] types = {int.class};

        boolean ok = DirectValueMapper.apply(callerParams, types, new Object[]{Integer.valueOf(42)},
                step(ProjectionKind.PASSTHROUGH, param(0, ProjectionSource.CALLER_PARAM, 0)));

        assertTrue(ok);
        assertEquals(42, callerParams[0]);
    }

    @Test
    public void refusesToMapNullOntoAPrimitiveParameter() {
        Object[] callerParams = new Object[1];
        Class<?>[] types = {int.class};

        boolean ok = DirectValueMapper.apply(callerParams, types, new Object[]{null},
                step(ProjectionKind.PASSTHROUGH, param(0, ProjectionSource.CALLER_PARAM, 0)));

        assertFalse("原始类型拿到 null 会在反射调用时 NPE，必须放弃直接合成", ok);
    }

    @Test
    public void acceptsNullForAReferenceParameter() {
        Object[] callerParams = new Object[1];
        Class<?>[] types = {String.class};

        boolean ok = DirectValueMapper.apply(callerParams, types, new Object[]{null},
                step(ProjectionKind.PASSTHROUGH, param(0, ProjectionSource.CALLER_PARAM, 0)));

        assertTrue(ok);
        assertNull(callerParams[0]);
    }

    @Test
    public void refusesAnAssignmentThatTheParameterTypeCannotAccept() {
        Object[] callerParams = new Object[1];
        Class<?>[] types = {String.class};

        boolean ok = DirectValueMapper.apply(callerParams, types, new Object[]{Integer.valueOf(1)},
                step(ProjectionKind.PASSTHROUGH, param(0, ProjectionSource.CALLER_PARAM, 0)));

        assertFalse("类型不符说明投影与实际不符，必须退回完整 fuzz", ok);
        assertNull("失败时不得留下半填的数组", callerParams[0]);
    }

    @Test
    public void refusesAnOutOfRangeCallerParameterIndex() {
        Object[] callerParams = new Object[1];
        Class<?>[] types = {String.class};

        assertFalse(DirectValueMapper.apply(callerParams, types, new Object[]{"v"},
                step(ProjectionKind.PASSTHROUGH, param(0, ProjectionSource.CALLER_PARAM, 5))));
    }

    @Test
    public void refusesAnOutOfRangeCalleeArgumentIndex() {
        Object[] callerParams = new Object[1];
        Class<?>[] types = {String.class};

        assertFalse(DirectValueMapper.apply(callerParams, types, new Object[]{"v"},
                step(ProjectionKind.PASSTHROUGH, param(7, ProjectionSource.CALLER_PARAM, 0))));
    }

    @Test
    public void leavesNonInvertibleDerivationsUntouchedWithoutFailing() {
        // STR_CONCAT 不可值级求逆：不映射，但也不算失败，交给 fixContext / 完整流程处理
        Object[] callerParams = new Object[1];
        Class<?>[] types = {String.class};

        boolean ok = DirectValueMapper.apply(callerParams, types, new Object[]{"v"},
                step(ProjectionKind.SIMPLE_DERIVATION,
                        param(0, ProjectionSource.CALLER_PARAM, 0, DerivationOps.STR_CONCAT)));

        assertTrue(ok);
        assertNull(callerParams[0]);
    }

    @Test
    public void leavesConstantSourcedArgumentsUntouched() {
        Object[] callerParams = new Object[1];
        Class<?>[] types = {String.class};

        boolean ok = DirectValueMapper.apply(callerParams, types, new Object[]{"v"},
                step(ProjectionKind.PASSTHROUGH, param(0, ProjectionSource.CONSTANT, -1)));

        assertTrue(ok);
        assertNull(callerParams[0]);
    }

    @Test
    public void mapsNothingForABreakpointStepEvenIfTheArgumentsLookProjectable() {
        Object[] callerParams = new Object[1];
        Class<?>[] types = {String.class};

        boolean ok = DirectValueMapper.apply(callerParams, types, new Object[]{"v"},
                step(ProjectionKind.CONDITIONAL_SELECT, param(0, ProjectionSource.CALLER_PARAM, 0)));

        assertTrue(ok);
        assertNull("守卫断点的实参形态虽是透传，也不能直接拷值——种子可能到不了 callee", callerParams[0]);
    }

    @Test
    public void aCalleeWithNoArgumentsSucceedsTrivially() {
        Object[] callerParams = new Object[0];

        assertTrue(DirectValueMapper.apply(callerParams, new Class<?>[0], new Object[0],
                step(ProjectionKind.PASSTHROUGH)));
    }

    @Test
    public void appliesACastDerivedArgumentBecauseCastingIsValueIdentity() {
        Object[] callerParams = new Object[1];
        Class<?>[] types = {int.class};

        boolean ok = DirectValueMapper.apply(callerParams, types, new Object[]{Integer.valueOf(7)},
                step(ProjectionKind.SIMPLE_DERIVATION,
                        param(0, ProjectionSource.CALLER_PARAM, 0, DerivationOps.CAST)));

        assertTrue(ok);
        assertEquals(7, callerParams[0]);
    }

    @Test
    public void aPartialFailureLeavesNoHalfFilledArray() {
        Object[] callerParams = new Object[2];
        Class<?>[] types = {String.class, String.class};

        boolean ok = DirectValueMapper.apply(callerParams, types, new Object[]{"ok", Integer.valueOf(1)},
                step(ProjectionKind.PASSTHROUGH,
                        param(0, ProjectionSource.CALLER_PARAM, 0),
                        param(1, ProjectionSource.CALLER_PARAM, 1)));

        assertFalse(ok);
        assertNull("第 0 个已填成功，但整体失败时必须回滚，否则调用方拿到一个半对的种子", callerParams[0]);
    }

    @Test
    public void reportsWhetherAnyArgumentIsDirectlyMappable() {
        assertTrue(DirectValueMapper.hasAnyDirectMapping(
                step(ProjectionKind.PASSTHROUGH, param(0, ProjectionSource.CALLER_PARAM, 0))));

        assertFalse("守卫断点即使实参形态是透传也不可拷值",
                DirectValueMapper.hasAnyDirectMapping(
                        step(ProjectionKind.CONDITIONAL_SELECT, param(0, ProjectionSource.CALLER_PARAM, 0))));

        assertFalse("常量实参对 caller 无约束，没有可映射项",
                DirectValueMapper.hasAnyDirectMapping(
                        step(ProjectionKind.PASSTHROUGH, param(0, ProjectionSource.CONSTANT, -1))));

        assertFalse("拼接不可值级求逆",
                DirectValueMapper.hasAnyDirectMapping(
                        step(ProjectionKind.SIMPLE_DERIVATION,
                                param(0, ProjectionSource.CALLER_PARAM, 0, DerivationOps.STR_CONCAT))));
    }
}
