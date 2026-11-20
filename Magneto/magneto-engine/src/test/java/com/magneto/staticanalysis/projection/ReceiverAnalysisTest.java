package com.magneto.staticanalysis.projection;

import com.magneto.staticanalysis.projection.fixture.PassthroughFixture;
import com.magneto.staticanalysis.projection.fixture.ReceiverConstructedFixture;
import com.magneto.staticanalysis.projection.fixture.ReceiverFromCollectionFixture;
import com.magneto.staticanalysis.projection.fixture.ReceiverFromFieldFixture;
import com.magneto.staticanalysis.projection.fixture.ReceiverFromGetterChainFixture;
import com.magneto.staticanalysis.projection.fixture.ReceiverFromParamFixture;
import com.magneto.staticanalysis.projection.fixture.ReceiverIsThisFixture;
import com.magneto.staticanalysis.projection.fixture.SimpleDerivationFixture;
import org.junit.Test;
import soot.Body;
import soot.Unit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * 接收者（invoke base）分析。
 *
 * R1—R5 只描述**实参**的溯源，但要真正到达 callee，实例调用的接收者也必须是种子能提供的对象。
 * 只看实参会漏判：真实例子是 QLExpress 的
 * {@code OperatorAlias.executeInner}，其中 {@code list.get(0).getObjectInner(parent)} 的实参
 * {@code parent} 是纯透传的 caller 形参，而接收者 {@code list.get(0)} 是运行时派生对象。
 * 该步被判成 PASSTHROUGH 后直接合成必然失败——S5 的 QLExpress 案例中 3 轮里 3 次都触发了升级。
 *
 * 这里的修正只会**增加**断点，不会减少，因此不可能违反「不允许把断点判成非断点」的红线。
 */
public class ReceiverAnalysisTest {

    private static final int MAX_DEPTH = 3;

    private StepTrace classify(Class<?> fixture) {
        Body body = SootFixtureHarness.bodyOf(fixture, "caller");
        Unit invoke = SootFixtureHarness.invokeOf(body, "callee");
        return StepClassifier.classify(body, invoke, MAX_DEPTH);
    }

    @Test
    public void aCallOnThisNeedsNoExtraReceiverAndStaysPassthrough() {
        assertEquals(ProjectionKind.PASSTHROUGH, classify(ReceiverIsThisFixture.class).getKind());
    }

    @Test
    public void aStaticCallHasNoReceiverAndStaysPassthrough() {
        assertEquals("静态调用没有接收者，不该被这条规则影响",
                ProjectionKind.PASSTHROUGH, classify(PassthroughFixture.class).getKind());
    }

    @Test
    public void aReceiverHeldInACallerParameterIsABreakpoint() {
        assertTrue("种子还得额外提供一个已初始化的实例，不是纯透传",
                classify(ReceiverFromParamFixture.class).getKind().isBreakpointKind());
    }

    /**
     * 接收者是 this 的直接字段（如 JacksonSerializer 的 `this.objectMapper.readValue(...)`）。
     * 这类可以放行：种子构造 caller 时会跑构造函数初始化字段，且 Magneto 既有的
     * fixContext「fix seed object context」分支会从 Context 回填接收者字段。
     * 实证依据：idworker 案例修复前 10 次跳过全部成功、0 次升级。
     */
    @Test
    public void aReceiverHeldInAFieldOfThisStaysNonBreakpoint() {
        StepTrace trace = classify(ReceiverFromFieldFixture.class);

        assertFalse("this 的直接字段读可由既有 fixContext 回填，不该判成断点",
                trace.getKind().isBreakpointKind());
    }

    /** 比直接字段读多一跳 getter，回填没有保证，保守判为断点。 */
    @Test
    public void aReceiverReachedThroughAGetterChainIsABreakpoint() {
        assertTrue(classify(ReceiverFromGetterChainFixture.class).getKind().isBreakpointKind());
    }

    /** QLExpress OperatorAlias.executeInner 的复刻：实参纯透传，接收者却是 list.get(0)。 */
    @Test
    public void aReceiverReturnedByACollectionLookupIsABreakpoint() {
        StepTrace trace = classify(ReceiverFromCollectionFixture.class);

        assertTrue("实参可投影不代表这一步可跳过——接收者不可静态确定时必须判为断点",
                trace.getKind().isBreakpointKind());
    }

    @Test
    public void aReceiverConstructedAtTheCallSiteIsABreakpoint() {
        assertTrue(classify(ReceiverConstructedFixture.class).getKind().isBreakpointKind());
    }

    @Test
    public void aNonThisReceiverIsRecordedInTheEvidence() {
        StepTrace trace = classify(ReceiverFromCollectionFixture.class);

        assertTrue("接收者是判定依据，必须留在 evidence 里供人工核对。实际: " + trace.getEvidence(),
                trace.getEvidence().contains("receiver"));
    }

    @Test
    public void aThisReceiverIsNotRecordedAsAnObstacle() {
        StepTrace trace = classify(ReceiverIsThisFixture.class);

        assertFalse("this 接收者是种子本来就持有的，不该留下 receiver 障碍记录。实际: " + trace.getEvidence(),
                trace.getEvidence().contains("receiver is not"));
    }

    @Test
    public void theReceiverRuleDoesNotDisturbTheExistingDerivationClassification() {
        assertEquals("SimpleDerivationFixture 的 callee 是静态调用，分类应保持不变",
                ProjectionKind.SIMPLE_DERIVATION, classify(SimpleDerivationFixture.class).getKind());
    }

    @Test
    public void receiverAnalysisStillReportsEveryCalleeArgument() {
        StepTrace trace = classify(ReceiverFromCollectionFixture.class);

        assertEquals("callee 只有一个实参", 1, trace.getParamProjections().size());
        assertEquals(0, trace.getParamProjections().get(0).getCalleeArgIndex());
    }
}
