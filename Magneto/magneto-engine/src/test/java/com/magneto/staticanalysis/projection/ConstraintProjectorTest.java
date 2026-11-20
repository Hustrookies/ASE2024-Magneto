package com.magneto.staticanalysis.projection;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * SPEC S3：值级投影与约束生成。
 *
 * 投影方向是**沿链反向**：PoC 给出 F₀ 的实参值，步骤 i 的 ParamProjection 说明
 * callee Fᵢ₋₁ 的实参 j 由 caller Fᵢ 的形参 k 经算子链 O 得到，于是 Fᵢ 形参 k 的要求
 * = O 的逆作用于该实参的要求。这个要求再成为步骤 i+1 的 callee 实参要求。
 */
public class ConstraintProjectorTest {

    private static final String CALLER = "<org.demo.Caller: void call(java.lang.String,int)>";
    private static final String CALLEE = "<org.demo.Callee: void target(java.lang.String)>";

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
        s.setCallerSignature(CALLER);
        s.setCalleeSignature(CALLEE);
        s.setKind(kind);
        s.setParamProjections(new ArrayList<>(Arrays.asList(params)));
        return s;
    }

    private Map<Integer, String> req(String... values) {
        Map<Integer, String> map = new LinkedHashMap<>();
        for (int i = 0; i < values.length; i++) {
            map.put(i, values[i]);
        }
        return map;
    }

    // ---------- R1 值级直接映射 ----------

    @Test
    public void aPassthroughArgumentProjectsItsRequirementOntoTheMatchingCallerParameter() {
        StepProjection s = step(ProjectionKind.PASSTHROUGH,
                param(0, ProjectionSource.CALLER_PARAM, 1));

        Map<Integer, String> callerReqs = ConstraintProjector.propagateStep(s, req("MUST_BE_class"));

        assertEquals("MUST_BE_class", callerReqs.get(1));
    }

    @Test
    public void aPassthroughProjectionCopiesTheRequirementVerbatimWithoutRewriting() {
        StepProjection s = step(ProjectionKind.PASSTHROUGH,
                param(0, ProjectionSource.CALLER_PARAM, 0));

        Map<Integer, String> callerReqs = ConstraintProjector.propagateStep(s, req("<PoC value of arg0>"));

        assertEquals("值级投影是直接映射，不得改写要求文本",
                "<PoC value of arg0>", callerReqs.get(0));
    }

    @Test
    public void multipleArgumentsProjectIndependently() {
        // 交叉映射：callee arg0 <- caller param1，callee arg1 <- caller param0
        StepProjection s = step(ProjectionKind.PASSTHROUGH,
                param(0, ProjectionSource.CALLER_PARAM, 1),
                param(1, ProjectionSource.CALLER_PARAM, 0));

        // callee arg0 须为 REQ_FOR_ARG0，arg1 须为 REQ_FOR_ARG1
        Map<Integer, String> callerReqs = ConstraintProjector.propagateStep(s, req("REQ_FOR_ARG0", "REQ_FOR_ARG1"));

        assertEquals("供给了 callee arg0 的是 caller param1", "REQ_FOR_ARG0", callerReqs.get(1));
        assertEquals("供给了 callee arg1 的是 caller param0", "REQ_FOR_ARG1", callerReqs.get(0));
    }

    @Test
    public void aConstantArgumentProjectsNoRequirementOntoTheCaller() {
        StepProjection s = step(ProjectionKind.PASSTHROUGH,
                param(0, ProjectionSource.CONSTANT, -1));

        Map<Integer, String> callerReqs = ConstraintProjector.propagateStep(s, req("A"));

        assertTrue("常量实参对 caller 不施加任何约束", callerReqs.isEmpty());
    }

    // ---------- R2 约束转写 ----------

    @Test
    public void aGetterArgumentProjectsOntoTheReceiverFieldAsARewrittenConstraint() {
        StepProjection s = step(ProjectionKind.SIMPLE_DERIVATION,
                param(1, ProjectionSource.CALLER_FIELD, -1, DerivationOps.getField("getIndexedListProperty")));

        Map<Integer, String> callerReqs = ConstraintProjector.propagateStep(s, req("", "MUST_BE_propName"));

        String fieldReq = callerReqs.get(ConstraintProjector.RECEIVER_FIELD_KEY);
        assertNotNull("字段来源的要求必须落到接收者字段上", fieldReq);
        assertTrue("应指明是哪个 getter/字段，实际: " + fieldReq,
                fieldReq.contains("getIndexedListProperty"));
        assertTrue("应保留下层要求，实际: " + fieldReq, fieldReq.contains("MUST_BE_propName"));
    }

    @Test
    public void aCastArgumentKeepsTheCallerParameterAsTheProjectionTarget() {
        StepProjection s = step(ProjectionKind.SIMPLE_DERIVATION,
                param(2, ProjectionSource.CALLER_PARAM, 2, DerivationOps.CAST));

        Map<Integer, String> callerReqs = ConstraintProjector.propagateStep(s, req("", "", "V"));

        assertNotNull("拆装箱/类型转换在值级是恒等，要求应仍落在同一形参上", callerReqs.get(2));
        assertTrue(callerReqs.get(2).contains("V"));
    }

    @Test
    public void aConcatArgumentRecordsThatTheConcatenationMustYieldTheRequiredValue() {
        StepProjection s = step(ProjectionKind.SIMPLE_DERIVATION,
                param(0, ProjectionSource.CALLER_PARAM, 0, DerivationOps.STR_CONCAT));

        Map<Integer, String> callerReqs = ConstraintProjector.propagateStep(s, req("V"));

        assertTrue("拼接不可直接求逆，必须转写为约束而非直接赋值，实际: " + callerReqs.get(0),
                callerReqs.get(0).contains(DerivationOps.STR_CONCAT));
        assertTrue(callerReqs.get(0).contains("V"));
    }

    // ---------- 断点步骤：构造目标 ----------

    @Test
    public void aBreakpointStepDoesNotPropagateAValueRequirement() {
        StepProjection s = step(ProjectionKind.COMPLEX_CONSTRUCTION,
                param(0, ProjectionSource.NEW_OBJECT, -1));

        Map<Integer, String> callerReqs = ConstraintProjector.propagateStep(s, req("V"));

        assertTrue("构造类断点无法静态求逆，不得伪造值级映射", callerReqs.isEmpty());
    }

    @Test
    public void anUnresolvedArgumentDoesNotPropagateAValueRequirement() {
        StepProjection s = step(ProjectionKind.UNKNOWN,
                param(0, ProjectionSource.UNRESOLVED, -1, "UNRESOLVED(reason)"));

        assertTrue(ConstraintProjector.propagateStep(s, req("V")).isEmpty());
    }

    /**
     * 最危险的一类：实参形态上是纯透传（全部来自 caller 形参），但调用点被守卫支配。
     * 若这里产出值级映射，S4 会以为能直接拷值合成种子——而那个种子可能根本到不了 callee。
     * 真实例子：commons-validator 的 Field.validateForRule → ValidatorAction.executeValidationMethod。
     */
    @Test
    public void aGuardedStepWithPassthroughArgumentsStillProjectsNoValueMapping() {
        StepProjection s = step(ProjectionKind.CONDITIONAL_SELECT,
                param(0, ProjectionSource.CALLER_PARAM, 0));

        assertTrue("守卫断点绝不能产出值级映射",
                ConstraintProjector.propagateStep(s, req("V")).isEmpty());
        assertFalse("也不能被判定为可直接拷值",
                ConstraintProjector.isDirectValueMapping(s, s.getParamProjections().get(0)));
    }

    @Test
    public void aBreakpointStepWithMixedArgumentSourcesProjectsNoValueMapping() {
        // 一个实参可投影、另一个不可 -> 整步是断点 -> 不得只对可投影的那个产出映射
        StepProjection s = step(ProjectionKind.UNKNOWN,
                param(0, ProjectionSource.CALLER_PARAM, 0),
                param(1, ProjectionSource.UNRESOLVED, -1, "UNRESOLVED(depth exhausted)"));

        assertTrue(ConstraintProjector.propagateStep(s, req("A", "B")).isEmpty());
    }

    @Test
    public void directValueMappingIsOnlyOfferedForNonBreakpointPassthroughArguments() {
        StepProjection passthrough = step(ProjectionKind.PASSTHROUGH,
                param(0, ProjectionSource.CALLER_PARAM, 0));
        assertTrue(ConstraintProjector.isDirectValueMapping(passthrough, passthrough.getParamProjections().get(0)));

        StepProjection derived = step(ProjectionKind.SIMPLE_DERIVATION,
                param(0, ProjectionSource.CALLER_PARAM, 0, DerivationOps.STR_CONCAT));
        assertFalse("拼接不是值级恒等，不能直接拷值",
                ConstraintProjector.isDirectValueMapping(derived, derived.getParamProjections().get(0)));

        StepProjection fieldSourced = step(ProjectionKind.SIMPLE_DERIVATION,
                param(0, ProjectionSource.CALLER_FIELD, -1, DerivationOps.getField("getFoo")));
        assertFalse("字段来源需设置接收者状态，不是直接拷值",
                ConstraintProjector.isDirectValueMapping(fieldSourced, fieldSourced.getParamProjections().get(0)));
    }

    @Test
    public void aBreakpointStepStillRendersAConstructionTargetNamingTheArgument() {
        StepProjection s = step(ProjectionKind.COMPLEX_CONSTRUCTION,
                param(0, ProjectionSource.NEW_OBJECT, -1));

        List<String> text = ConstraintProjector.render(s, req("MUST_SATISFY_X"));

        assertFalse(text.isEmpty());
        String joined = String.join("\n", text);
        assertTrue("必须指明是第几个实参，实际: " + joined, joined.contains("0"));
        assertTrue("必须携带下层要求，实际: " + joined, joined.contains("MUST_SATISFY_X"));
    }

    @Test
    public void aGuardedBreakpointStepRendersTheReachabilityObligation() {
        StepProjection s = step(ProjectionKind.CONDITIONAL_SELECT,
                param(0, ProjectionSource.CALLER_PARAM, 0));
        s.setEvidence("if $stack2 == 0 goto L1");

        String joined = String.join("\n", ConstraintProjector.render(s, req("V")));

        assertTrue("条件选择类断点必须提示「调用点受守卫支配」，否则 S4 合成的种子到不了 callee。实际: " + joined,
                joined.toLowerCase().contains("guard") || joined.contains("branch"));
    }

    /**
     * 断点步骤下游传播中止后，下层没有要求可传。此时仍必须给出**结构信息**
     * （这个实参来自哪个 caller 形参/字段），否则注入 prompt 的约束等于没有信息。
     * 真实例子：commons-validator chain-3/step4，四个实参全部渲染成 "satisfies: (unconstrained)"。
     */
    @Test
    public void aBreakpointStepStillReportsWhichCallerParameterFeedsTheArgument() {
        StepProjection s = step(ProjectionKind.CONDITIONAL_SELECT,
                param(1, ProjectionSource.CALLER_PARAM, 3));

        String line = ConstraintProjector.render(s, req("", "REQ_V")).get(0);

        assertTrue("必须指明 callee 实参下标，实际: " + line, line.contains("callee arg 1"));
        assertTrue("必须指明来源是哪个 caller 形参，实际: " + line, line.contains("caller param 3"));
        assertTrue("必须携带下层要求，实际: " + line, line.contains("REQ_V"));
    }

    @Test
    public void aBreakpointStepWithNoDownstreamRequirementExplainsWhyInsteadOfABarePlaceholder() {
        StepProjection s = step(ProjectionKind.UNKNOWN,
                param(0, ProjectionSource.CALLER_PARAM, 0));

        List<String> lines = ConstraintProjector.render(s, Collections.<Integer, String>emptyMap());

        assertFalse("不得留下一个以裸占位符结尾的无信息约束",
                lines.get(0).trim().endsWith(ConstraintProjector.NO_REQUIREMENT));
        assertTrue("必须解释要求为何缺失，并给出可执行的替代目标",
                lines.contains(ConstraintProjector.NO_DOWNSTREAM_REQUIREMENT_HINT));
    }

    /**
     * 提示语整步只出现一次。逐实参重复会把 prompt 撑大——S5 要跑几百次调用，
     * 每个断点步骤省下的 token 都是实打实的成本。
     */
    @Test
    public void theNoDownstreamHintAppearsOncePerStepNotOncePerArgument() {
        StepProjection s = step(ProjectionKind.UNKNOWN,
                param(0, ProjectionSource.CALLER_PARAM, 0),
                param(1, ProjectionSource.CALLER_PARAM, 1),
                param(2, ProjectionSource.CALLER_PARAM, 2));

        List<String> lines = ConstraintProjector.render(s, Collections.<Integer, String>emptyMap());

        int hints = 0;
        for (String line : lines) {
            if (ConstraintProjector.NO_DOWNSTREAM_REQUIREMENT_HINT.equals(line)) {
                hints++;
            }
        }
        assertEquals("3 个实参 + 1 条整步提示", 4, lines.size());
        assertEquals(1, hints);
    }

    @Test
    public void aNonBreakpointStepWithNoRequirementMarksItInlineWithoutTheHint() {
        StepProjection s = step(ProjectionKind.PASSTHROUGH,
                param(0, ProjectionSource.CALLER_PARAM, 0));

        List<String> lines = ConstraintProjector.render(s, Collections.<Integer, String>emptyMap());

        assertEquals(1, lines.size());
        assertTrue(lines.get(0).contains(ConstraintProjector.NO_REQUIREMENT));
    }

    @Test
    public void aBreakpointStepReportsReceiverFieldSourcesAsWellAsParameters() {
        StepProjection s = step(ProjectionKind.CONDITIONAL_SELECT,
                param(0, ProjectionSource.CALLER_FIELD, -1, DerivationOps.getField("getKey")));

        String line = ConstraintProjector.render(s, req("REQ_V")).get(0);

        assertTrue("字段来源需告知 LLM 设置接收者状态，实际: " + line,
                line.contains("receiver") && line.contains("getKey"));
    }

    // ---------- 整链传播 ----------

    @Test
    public void requirementsFlowBackwardAlongTheWholeChain() {
        // F2 --step2--> F1 --step1--> F0，两步都是纯透传
        StepProjection step1 = step(ProjectionKind.PASSTHROUGH,
                param(0, ProjectionSource.CALLER_PARAM, 0));
        step1.setStepIndex(1);
        StepProjection step2 = step(ProjectionKind.PASSTHROUGH,
                param(0, ProjectionSource.CALLER_PARAM, 0));
        step2.setStepIndex(2);

        ChainProjection chain = new ChainProjection("chain-x");
        chain.addStep(step1);
        chain.addStep(step2);

        List<Map<Integer, String>> byDepth = ConstraintProjector.propagateChain(chain, req("POC_VALUE"));

        assertEquals("结果按 reverseChainList 下标索引，长度 = 步数 + 1", 3, byDepth.size());
        assertEquals("POC_VALUE", byDepth.get(0).get(0));
        assertEquals("POC_VALUE", byDepth.get(1).get(0));
        assertEquals("POC_VALUE", byDepth.get(2).get(0));
    }

    @Test
    public void propagationStopsAtABreakpointAndResumesNothingBeyondIt() {
        StepProjection step1 = step(ProjectionKind.PASSTHROUGH,
                param(0, ProjectionSource.CALLER_PARAM, 0));
        step1.setStepIndex(1);
        StepProjection step2 = step(ProjectionKind.UNKNOWN,
                param(0, ProjectionSource.UNRESOLVED, -1));
        step2.setStepIndex(2);

        ChainProjection chain = new ChainProjection("chain-x");
        chain.addStep(step1);
        chain.addStep(step2);

        List<Map<Integer, String>> byDepth = ConstraintProjector.propagateChain(chain, req("POC_VALUE"));

        assertEquals("POC_VALUE", byDepth.get(1).get(0));
        assertTrue("断点之后的要求无法继续上推", byDepth.get(2).isEmpty());
    }

    @Test
    public void aChainWithNoStepsYieldsOnlyThePocRequirements() {
        ChainProjection chain = new ChainProjection("chain-x");

        List<Map<Integer, String>> byDepth = ConstraintProjector.propagateChain(chain, req("POC_VALUE"));

        assertEquals(1, byDepth.size());
        assertEquals("POC_VALUE", byDepth.get(0).get(0));
    }

    // ---------- 渲染 ----------

    @Test
    public void aPassthroughStepRendersTheDirectValueMapping() {
        StepProjection s = step(ProjectionKind.PASSTHROUGH,
                param(0, ProjectionSource.CALLER_PARAM, 1));

        String joined = String.join("\n", ConstraintProjector.render(s, req("MUST_BE_class")));

        assertTrue("应指出 callee 实参 0 来自 caller 形参 1，实际: " + joined,
                joined.contains("0") && joined.contains("1"));
        assertTrue("应携带要求值，实际: " + joined, joined.contains("MUST_BE_class"));
    }

    @Test
    public void renderProducesOneLinePerCalleeArgument() {
        StepProjection s = step(ProjectionKind.PASSTHROUGH,
                param(0, ProjectionSource.CALLER_PARAM, 0),
                param(1, ProjectionSource.CONSTANT, -1));

        assertEquals(2, ConstraintProjector.render(s, req("A", "B")).size());
    }

    @Test
    public void renderIsDeterministicForTheSameInput() {
        StepProjection s = step(ProjectionKind.SIMPLE_DERIVATION,
                param(0, ProjectionSource.CALLER_PARAM, 0, DerivationOps.CAST),
                param(1, ProjectionSource.CALLER_FIELD, -1, DerivationOps.getField("getFoo")));

        assertEquals(ConstraintProjector.render(s, req("A", "B")),
                ConstraintProjector.render(s, req("A", "B")));
    }

    @Test
    public void renderCoversArgumentsThatHaveNoRequirementYet() {
        StepProjection s = step(ProjectionKind.PASSTHROUGH,
                param(0, ProjectionSource.CALLER_PARAM, 0),
                param(1, ProjectionSource.CALLER_PARAM, 1));

        List<String> lines = ConstraintProjector.render(s, req("A"));

        assertEquals("没有下层要求的实参也要渲染，否则 prompt 里会缺参数", 2, lines.size());
        assertNotNull(lines.get(1));
    }

    @Test
    public void anArgumentWithNoRequirementRendersAsUnconstrained() {
        StepProjection s = step(ProjectionKind.PASSTHROUGH,
                param(0, ProjectionSource.CALLER_PARAM, 0));

        String line = ConstraintProjector.render(s, Collections.<Integer, String>emptyMap()).get(0);

        assertTrue("实际: " + line, line.contains(ConstraintProjector.NO_REQUIREMENT));
    }

    // ---------- 运行时取值渲染 ----------

    /**
     * 静态阶段只有占位符；到 fuzz 阶段 Context 里已经有 PoC 的真实值，
     * 注入 prompt 的必须是真实值，否则"约束注入"注入的是一句描述而不是约束。
     */
    @Test
    public void describeValueRendersAStringAsAQuotedLiteralWithItsType() {
        String d = ConstraintProjector.describeValue("class");

        assertTrue("实际: " + d, d.contains("\"class\""));
        assertTrue("实际: " + d, d.contains("java.lang.String"));
    }

    @Test
    public void describeValueRendersNullExplicitly() {
        assertEquals("null", ConstraintProjector.describeValue(null));
    }

    @Test
    public void describeValueRendersANumberWithItsType() {
        String d = ConstraintProjector.describeValue(Integer.valueOf(42));

        assertTrue("实际: " + d, d.contains("42") && d.contains("java.lang.Integer"));
    }

    @Test
    public void describeValueTruncatesLongValuesSoThePromptStaysSmall() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 4000; i++) {
            sb.append('x');
        }

        String d = ConstraintProjector.describeValue(sb.toString());

        assertTrue("实际长度 " + d.length(), d.length() < 400);
        assertTrue("截断必须显式标注，否则 LLM 会把截断值当成完整约束", d.contains("truncated"));
    }

    @Test
    public void runtimeRenderingPutsTheActualValueIntoTheConstraint() {
        StepProjection s = step(ProjectionKind.PASSTHROUGH,
                param(0, ProjectionSource.CALLER_PARAM, 1));

        List<String> lines = ConstraintProjector.renderWithRuntimeValues(s, new Object[]{"class"});

        assertTrue("实际: " + lines.get(0), lines.get(0).contains("\"class\""));
        assertFalse("不得再出现静态阶段的占位符", lines.get(0).contains("captured by executing"));
    }

    @Test
    public void runtimeRenderingFallsBackWhenAValueIsMissing() {
        StepProjection s = step(ProjectionKind.PASSTHROUGH,
                param(0, ProjectionSource.CALLER_PARAM, 0),
                param(1, ProjectionSource.CALLER_PARAM, 1));

        List<String> lines = ConstraintProjector.renderWithRuntimeValues(s, new Object[]{"v"});

        assertEquals(2, lines.size());
        assertTrue(lines.get(1).contains(ConstraintProjector.NO_REQUIREMENT));
    }
}
