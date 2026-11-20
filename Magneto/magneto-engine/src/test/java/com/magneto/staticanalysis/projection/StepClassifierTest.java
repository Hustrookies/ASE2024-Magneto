package com.magneto.staticanalysis.projection;

import com.magneto.staticanalysis.projection.fixture.ComplexConstructionFixture;
import com.magneto.staticanalysis.projection.fixture.ConcatFixture;
import com.magneto.staticanalysis.projection.fixture.FieldOfParamFixture;
import com.magneto.staticanalysis.projection.fixture.FieldOfThisFixture;
import com.magneto.staticanalysis.projection.fixture.ConditionalSelectFixture;
import com.magneto.staticanalysis.projection.fixture.GuardedCallFixture;
import com.magneto.staticanalysis.projection.fixture.ParamGuardFixture;
import com.magneto.staticanalysis.projection.fixture.PassthroughFixture;
import com.magneto.staticanalysis.projection.fixture.SimpleDerivationFixture;
import com.magneto.staticanalysis.projection.fixture.UnresolvableFixture;
import org.junit.Test;
import soot.Body;
import soot.Unit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * SPEC 3.2 的 R1—R5 判定，逐个 fixture 一条。
 *
 * 红线（SPEC S2 验收）：**不允许把断点判成非断点**。因此 PASSTHROUGH / SIMPLE_DERIVATION
 * 的断言是强断言，而保守方向（把可跳过的判成断点）只要求不反向出错。
 */
public class StepClassifierTest {

    private static final int MAX_DEPTH = 3;

    private StepTrace classify(Class<?> fixture) {
        Body body = SootFixtureHarness.bodyOf(fixture, "caller");
        Unit invoke = SootFixtureHarness.invokeOf(body, "callee");
        return StepClassifier.classify(body, invoke, MAX_DEPTH);
    }

    // ---------- R1 ----------

    @Test
    public void r1_argumentsCopiedStraightFromParametersArePassthrough() {
        assertEquals(ProjectionKind.PASSTHROUGH, classify(PassthroughFixture.class).getKind());
    }

    @Test
    public void r1_passthroughIsNotABreakpoint() {
        assertFalse(classify(PassthroughFixture.class).getKind().isBreakpointKind());
    }

    @Test
    public void r1_eachArgumentMapsToItsOwnCallerParameter() {
        StepTrace trace = classify(PassthroughFixture.class);

        assertEquals(2, trace.getParamProjections().size());

        ParamProjection first = trace.getParamProjections().get(0);
        assertEquals(0, first.getCalleeArgIndex());
        assertEquals(ProjectionSource.CALLER_PARAM, first.getSourceKind());
        assertEquals(0, first.getCallerParamIndex());
        assertTrue("a pure copy has no derivation ops", first.getDerivationOps().isEmpty());

        ParamProjection second = trace.getParamProjections().get(1);
        assertEquals(1, second.getCalleeArgIndex());
        assertEquals(ProjectionSource.CALLER_PARAM, second.getSourceKind());
        assertEquals(1, second.getCallerParamIndex());
    }

    // ---------- R2 ----------

    @Test
    public void r2_getterAndCastAreSimpleDerivation() {
        assertEquals(ProjectionKind.SIMPLE_DERIVATION, classify(SimpleDerivationFixture.class).getKind());
    }

    @Test
    public void r2_getterRecordsTheFieldReadOp() {
        StepTrace trace = classify(SimpleDerivationFixture.class);

        ParamProjection fromGetter = trace.getParamProjections().get(0);
        assertEquals(ProjectionSource.CALLER_FIELD, fromGetter.getSourceKind());
        assertEquals(1, fromGetter.getDerivationOps().size());
        assertTrue("expected a GET_FIELD op, got " + fromGetter.getDerivationOps(),
                fromGetter.getDerivationOps().get(0).startsWith(DerivationOps.GET_FIELD));
    }

    @Test
    public void r2_castRecordsTheCastOpAndKeepsTheParameterSource() {
        StepTrace trace = classify(SimpleDerivationFixture.class);

        ParamProjection casted = trace.getParamProjections().get(1);
        assertEquals(ProjectionSource.CALLER_PARAM, casted.getSourceKind());
        assertEquals(0, casted.getCallerParamIndex());
        assertTrue("expected a CAST op, got " + casted.getDerivationOps(),
                casted.getDerivationOps().contains(DerivationOps.CAST));
    }

    /**
     * Java 8 把 `a + "!"` 编成 new StringBuilder / append / append / toString。
     * 按朴素规则这是 NewExpr + 多次调用 = R3 断点；SPEC R2 明确要求识别为字符串拼接。
     */
    @Test
    public void r2_stringConcatIsSimpleDerivationNotComplexConstruction() {
        assertEquals(ProjectionKind.SIMPLE_DERIVATION, classify(ConcatFixture.class).getKind());
    }

    @Test
    public void r2_stringConcatRecordsTheConcatOp() {
        StepTrace trace = classify(ConcatFixture.class);

        ParamProjection concat = trace.getParamProjections().get(0);
        assertTrue("expected a STR_CONCAT op, got " + concat.getDerivationOps(),
                concat.getDerivationOps().contains(DerivationOps.STR_CONCAT));
    }

    // ---------- R3 ----------

    @Test
    public void r3_newObjectFollowedByMutationsIsComplexConstruction() {
        assertEquals(ProjectionKind.COMPLEX_CONSTRUCTION, classify(ComplexConstructionFixture.class).getKind());
    }

    @Test
    public void r3_complexConstructionIsABreakpoint() {
        assertTrue(classify(ComplexConstructionFixture.class).getKind().isBreakpointKind());
    }

    @Test
    public void r3_theConstructedArgumentIsRecordedAsNewObject() {
        StepTrace trace = classify(ComplexConstructionFixture.class);

        ParamProjection built = trace.getParamProjections().get(0);
        assertEquals(ProjectionSource.NEW_OBJECT, built.getSourceKind());
        assertEquals(-1, built.getCallerParamIndex());
    }

    // ---------- R4 ----------

    @Test
    public void r4_argumentDefinedInTwoBranchesIsConditionalSelect() {
        assertEquals(ProjectionKind.CONDITIONAL_SELECT, classify(ConditionalSelectFixture.class).getKind());
    }

    /**
     * 实参本身是纯透传（a := @parameter0），但调用点被字段守卫支配——
     * 守卫规则必须压过实参分类，否则 S4 会跳过一个其实到不了 callee 的步骤。
     */
    @Test
    public void r4_aGuardedCallSiteIsConditionalSelectEvenWithPassthroughArguments() {
        StepTrace trace = classify(GuardedCallFixture.class);

        assertEquals(ProjectionKind.CONDITIONAL_SELECT, trace.getKind());
        assertTrue("the guard must be reported", trace.isGuarded());
    }

    @Test
    public void r4_aGuardOnACallerParameterIsStillConditionalSelect() {
        // 保守取向：只要调用点被条件支配就记 CONDITIONAL_SELECT，不区分条件来源。
        // 理由见 SPEC S2 红线——形参守卫同样是必须满足的约束，漏判的代价（白跑一次试运行再升级）
        // 高于多判的代价（本来就要跑的定向 fuzz）。
        StepTrace trace = classify(ParamGuardFixture.class);

        assertEquals(ProjectionKind.CONDITIONAL_SELECT, trace.getKind());
        assertTrue(trace.isGuarded());
    }

    @Test
    public void r4_conditionalSelectIsABreakpoint() {
        assertTrue(classify(ConditionalSelectFixture.class).getKind().isBreakpointKind());
    }

    // ---------- R5 ----------

    @Test
    public void r5_unresolvableInterfaceDispatchIsUnknown() {
        assertEquals(ProjectionKind.UNKNOWN, classify(UnresolvableFixture.class).getKind());
    }

    @Test
    public void r5_unknownIsABreakpoint() {
        assertTrue("conservative fallback must block", classify(UnresolvableFixture.class).getKind().isBreakpointKind());
    }

    @Test
    public void r5_anUnresolvableArgumentIsRecordedAsUnresolved() {
        StepTrace trace = classify(UnresolvableFixture.class);

        assertEquals(ProjectionSource.UNRESOLVED, trace.getParamProjections().get(0).getSourceKind());
    }

    // ---------- 字段读的基对象 ----------

    /**
     * `this.value` 与 `h.value`（h 是形参）在 Jimple 里都是 InstanceFieldRef，
     * 但只有前者的基对象由种子构造并会被既有 fixContext 回填。
     * 不加区分地记为 CALLER_FIELD 会渲染出「callee arg N <- receiver object」这种
     * 事实错误的硬约束，反而误导断点步骤的 LLM。
     */
    @Test
    public void aFieldOfThisIsASimpleDerivationOnTheReceiver() {
        StepTrace trace = classify(FieldOfThisFixture.class);

        assertEquals(ProjectionKind.SIMPLE_DERIVATION, trace.getKind());
        ParamProjection p = trace.getParamProjections().get(0);
        assertEquals(ProjectionSource.CALLER_FIELD, p.getSourceKind());
    }

    @Test
    public void aFieldOfAParameterIsNotAttributedToTheReceiver() {
        StepTrace trace = classify(FieldOfParamFixture.class);

        assertTrue("形参对象的字段无法由 fixContext 回填，必须判为断点",
                trace.getKind().isBreakpointKind());
        assertEquals(ProjectionSource.UNRESOLVED, trace.getParamProjections().get(0).getSourceKind());
    }

    // ---------- 证据与健壮性 ----------

    @Test
    public void evidenceCarriesTheJimpleStatementsTheDecisionRestsOn() {
        StepTrace trace = classify(PassthroughFixture.class);

        assertNotNull(trace.getEvidence());
        assertFalse("evidence must not be empty", trace.getEvidence().isEmpty());
        assertTrue("evidence should quote the parameter identity, got: " + trace.getEvidence(),
                trace.getEvidence().contains("@parameter0"));
    }

    @Test
    public void aDepthLimitOfZeroFallsBackToUnknownRatherThanGuessing() {
        Body body = SootFixtureHarness.bodyOf(ConcatFixture.class, "caller");
        Unit invoke = SootFixtureHarness.invokeOf(body, "callee");

        StepTrace trace = StepClassifier.classify(body, invoke, 0);

        assertTrue("exhausted depth must never yield a non-breakpoint kind, got " + trace.getKind(),
                trace.getKind().isBreakpointKind());
    }

    @Test
    public void everyFixtureYieldsOneProjectionPerCalleeArgument() {
        Object[][] expectations = {
                {PassthroughFixture.class, 2}, {SimpleDerivationFixture.class, 2},
                {ConcatFixture.class, 1}, {ComplexConstructionFixture.class, 1},
                {ConditionalSelectFixture.class, 1}, {GuardedCallFixture.class, 1},
                {ParamGuardFixture.class, 1}, {UnresolvableFixture.class, 1}
        };

        for (Object[] expectation : expectations) {
            Class<?> fixture = (Class<?>) expectation[0];
            StepTrace trace = classify(fixture);

            assertEquals(fixture.getSimpleName(),
                    ((Integer) expectation[1]).intValue(), trace.getParamProjections().size());
        }
    }
}
