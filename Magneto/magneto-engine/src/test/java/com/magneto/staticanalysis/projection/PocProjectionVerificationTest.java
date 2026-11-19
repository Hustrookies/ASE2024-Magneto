package com.magneto.staticanalysis.projection;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * SPEC S3 验收第 1、2 项的机械核对：把真实链的投影形状与 groundtruth PoC 的实际参数值喂进去，
 * 断言渲染出的约束确实指向正确的实参、正确的 caller 形参，并携带 PoC 的值。
 *
 * 真实数据来源：
 * - 链：runs 目录下 classify 模式产出的 projection.json，commons-validator CVE-2019-10086 的 chain-0 / chain-3
 *   （人工核对记录见 docs/projection-annotation.md）
 * - PoC：`Magneto/groundtruth/CVE-2019-10086/src/main/java/com/magneto/CVE_2019_10086_Testcase1.java`
 *
 *   Object bean = new Object();
 *   PropertyUtils.getProperty(bean, "class");
 *
 *   即 F0 = PropertyUtils.getProperty(Object,String) 的 arg0 = 一个新建 Object，arg1 = "class"。
 */
public class PocProjectionVerificationTest {

    /** chain-0/step1，工具判定 PASSTHROUGH。 */
    private static final String GET_VALUE_AS_STRING =
            "<org.apache.commons.validator.util.ValidatorUtils: java.lang.String getValueAsString(java.lang.Object,java.lang.String)>";

    /** F0，PoC 直接调用的漏洞函数。 */
    private static final String GET_PROPERTY =
            "<org.apache.commons.beanutils.PropertyUtils: java.lang.Object getProperty(java.lang.Object,java.lang.String)>";

    /** chain-3/step4，工具判定 CONDITIONAL_SELECT（断点）。 */
    private static final String VALIDATE_FOR_RULE =
            "<org.apache.commons.validator.Field: boolean validateForRule(org.apache.commons.validator.ValidatorAction,"
                    + "org.apache.commons.validator.ValidatorResults,java.util.Map,java.util.Map,int)>";

    private static final String EXECUTE_VALIDATION_METHOD =
            "<org.apache.commons.validator.ValidatorAction: boolean executeValidationMethod("
                    + "org.apache.commons.validator.Field,java.util.Map,org.apache.commons.validator.ValidatorResults,int)>";

    private static final String POC_ARG0 = "a freshly allocated java.lang.Object (PoC: `Object bean = new Object()`)";
    private static final String POC_ARG1 = "\"class\"";

    private ParamProjection param(int calleeArg, ProjectionSource source, int callerParam, String... ops) {
        ParamProjection p = new ParamProjection();
        p.setCalleeArgIndex(calleeArg);
        p.setSourceKind(source);
        p.setCallerParamIndex(callerParam);
        p.setDerivationOps(new ArrayList<>(Arrays.asList(ops)));
        return p;
    }

    /** chain-0/step1：getValueAsString(bean, property) 内部 getProperty(bean, property)，两个实参均为纯拷贝。 */
    private StepProjection chain0Step1() {
        StepProjection s = new StepProjection();
        s.setStepIndex(1);
        s.setCallerSignature(GET_VALUE_AS_STRING);
        s.setCalleeSignature(GET_PROPERTY);
        s.setKind(ProjectionKind.PASSTHROUGH);
        s.setParamProjections(new ArrayList<>(Arrays.asList(
                param(0, ProjectionSource.CALLER_PARAM, 0),
                param(1, ProjectionSource.CALLER_PARAM, 1))));
        return s;
    }

    /** chain-3/step4：validateForRule 内 return va.executeValidationMethod(this, params, results, pos)。 */
    private StepProjection chain3Step4() {
        StepProjection s = new StepProjection();
        s.setStepIndex(4);
        s.setCallerSignature(VALIDATE_FOR_RULE);
        s.setCalleeSignature(EXECUTE_VALIDATION_METHOD);
        s.setKind(ProjectionKind.CONDITIONAL_SELECT);
        s.setParamProjections(new ArrayList<>(Arrays.asList(
                param(0, ProjectionSource.CALLER_FIELD, -1),
                param(1, ProjectionSource.CALLER_PARAM, 3),
                param(2, ProjectionSource.CALLER_PARAM, 1),
                param(3, ProjectionSource.CALLER_PARAM, 4, DerivationOps.CAST))));
        return s;
    }

    private Map<Integer, String> pocRequirements() {
        Map<Integer, String> poc = new LinkedHashMap<>();
        poc.put(0, POC_ARG0);
        poc.put(1, POC_ARG1);
        return poc;
    }

    // ---------- 验收项 1：透传链的投影约束与 PoC 参数值一致 ----------

    @Test
    public void thePassthroughChainProjectsThePocStringOntoTheCorrectCallerParameter() {
        StepProjection step = chain0Step1();

        Map<Integer, String> callerReqs = ConstraintProjector.propagateStep(step, pocRequirements());

        assertEquals("getValueAsString 的形参 1 (property) 必须就是 PoC 传的 \"class\"",
                POC_ARG1, callerReqs.get(1));
    }

    @Test
    public void thePassthroughChainProjectsThePocReceiverOntoTheCorrectCallerParameter() {
        StepProjection step = chain0Step1();

        Map<Integer, String> callerReqs = ConstraintProjector.propagateStep(step, pocRequirements());

        assertEquals("getValueAsString 的形参 0 (bean) 必须就是 PoC 新建的 Object",
                POC_ARG0, callerReqs.get(0));
    }

    @Test
    public void theRenderedConstraintNamesBothTheCalleeArgumentAndTheCallerParameter() {
        StepProjection step = chain0Step1();

        List<String> lines = ConstraintProjector.render(step, pocRequirements());

        assertEquals(2, lines.size());
        assertTrue(lines.get(0).contains("callee arg 0") && lines.get(0).contains("caller param 0"));
        assertTrue(lines.get(1).contains("callee arg 1") && lines.get(1).contains("caller param 1"));
        assertTrue("渲染文本必须带上 PoC 的实际值，实际: " + lines.get(1), lines.get(1).contains(POC_ARG1));
    }

    @Test
    public void thePassthroughStepIsOfferedAsADirectValueMappingForLlmFreeSynthesis() {
        StepProjection step = chain0Step1();

        for (ParamProjection param : step.getParamProjections()) {
            assertTrue("纯透传步骤应可免 LLM 直接拷值合成种子",
                    ConstraintProjector.isDirectValueMapping(step, param));
        }
    }

    // ---------- 验收项 2：断点链的构造目标指向正确实参与条件 ----------

    @Test
    public void theBreakpointStepNamesTheCorrectCallerParameterForEachCalleeArgument() {
        StepProjection step = chain3Step4();
        Map<Integer, String> downstream = new LinkedHashMap<>();
        downstream.put(1, "REQ_FOR_ARG1");

        List<String> lines = ConstraintProjector.render(step, downstream);

        // 实参 1 <- caller 形参 3；实参 2 <- caller 形参 1；实参 3 <- caller 形参 4
        assertTrue("arg1 应指向 caller param 3，实际: " + lines.get(1),
                lines.get(1).contains("callee arg 1") && lines.get(1).contains("caller param 3"));
        assertTrue("arg2 应指向 caller param 1，实际: " + lines.get(2),
                lines.get(2).contains("callee arg 2") && lines.get(2).contains("caller param 1"));
        assertTrue("arg3 应指向 caller param 4，实际: " + lines.get(3),
                lines.get(3).contains("callee arg 3") && lines.get(3).contains("caller param 4"));
    }

    @Test
    public void theBreakpointStepCarriesTheDownstreamRequirementWhenOneExists() {
        StepProjection step = chain3Step4();
        Map<Integer, String> downstream = new LinkedHashMap<>();
        downstream.put(1, "REQ_FOR_ARG1");

        String line = ConstraintProjector.render(step, downstream).get(1);

        assertTrue("有下层要求时必须给出构造目标，实际: " + line,
                line.contains("CONSTRUCTION TARGET") && line.contains("REQ_FOR_ARG1"));
    }

    @Test
    public void theBreakpointStepStatesTheReachabilityCondition() {
        StepProjection step = chain3Step4();

        String joined = String.join("\n", ConstraintProjector.render(step, new LinkedHashMap<Integer, String>()));

        assertTrue("validateForRule 里有两处提前返回守卫，必须提示可达性义务。实际: " + joined,
                joined.contains("REACHABILITY OBLIGATION"));
    }

    @Test
    public void theBreakpointStepNeverOffersADirectValueMapping() {
        StepProjection step = chain3Step4();

        for (ParamProjection param : step.getParamProjections()) {
            assertFalse("断点步骤即使实参形态是透传，也不能被当作可直接拷值——种子可能到不了 callee",
                    ConstraintProjector.isDirectValueMapping(step, param));
        }
    }

    @Test
    public void theBreakpointStepReportsTheReceiverSourcedArgumentAsReceiverState() {
        StepProjection step = chain3Step4();

        String line = ConstraintProjector.render(step, new LinkedHashMap<Integer, String>()).get(0);

        assertTrue("arg0 是 this（Field 自身），应表述为接收者对象，实际: " + line,
                line.contains("callee arg 0") && line.contains("receiver"));
    }
}
