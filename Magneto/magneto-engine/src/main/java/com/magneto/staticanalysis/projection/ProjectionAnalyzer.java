package com.magneto.staticanalysis.projection;

import com.magneto.staticanalysis.MethodCall;
import com.magneto.staticanalysis.MethodCallChain;
import com.magneto.staticanalysis.callgraph.BranchAnalyzer;
import com.magneto.staticanalysis.dataflow.ComplexityAnalyzer;
import com.magneto.staticanalysis.dataflow.MethodParameterMappingAnalysis;
import com.magneto.staticanalysis.taint.TaintField;
import com.magneto.staticanalysis.taint.TaintFlowAnalysis;
import com.magneto.staticanalysis.taint.TaintObject;
import com.magneto.staticanalysis.taint.TaintParam;
import lombok.extern.slf4j.Slf4j;
import soot.Body;
import soot.Unit;
import soot.toolkits.graph.ExceptionalUnitGraph;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * 约束投影分析器：对调用链每个步骤 ⟨caller Fᵢ, callee Fᵢ₋₁⟩ 做参数关联分类（SPEC 3.2）。
 *
 * 分类逻辑在 StepClassifier 里，只吃 Soot 对象；本类负责 MethodCall → Body/调用点的接线、
 * 多调用点取最劣，以及复用现有 MethodParameterMappingAnalysis / ComplexityAnalyzer /
 * BranchAnalyzer 填 taintObjectMap 摘要与分数。
 */
@Slf4j
public class ProjectionAnalyzer {

    private final int maxDepth;

    public ProjectionAnalyzer(int maxDepth) {
        this.maxDepth = maxDepth;
    }

    /**
     * 保守兜底步骤（SPEC 3.2 R5）：无法解析时一律 UNKNOWN + 断点。
     */
    public static StepProjection unresolvedStep(int stepIndex, String callerSignature, String calleeSignature) {
        StepProjection step = new StepProjection();
        step.setStepIndex(stepIndex);
        step.setCallerSignature(callerSignature);
        step.setCalleeSignature(calleeSignature);
        step.setKind(ProjectionKind.UNKNOWN);
        return step;
    }

    /**
     * 按 reverseChainList 顺序逐步骤分析：下标 i 的步骤对应 caller = get(i)、callee = get(i-1)，
     * 与 StepFuzzRunner.fuzzCallChain 的步骤循环一致，故产出 n-1 个步骤。
     */
    public List<StepProjection> analyzeChain(MethodCallChain chain) {
        List<MethodCall> reverseChain = chain.reverseChainList();
        List<StepProjection> steps = new ArrayList<>();

        for (int i = 1; i < reverseChain.size(); i++) {
            MethodCall caller = reverseChain.get(i);
            MethodCall callee = reverseChain.get(i - 1);

            StepProjection step = classifyStep(i, caller, callee);
            step.setComplexityScore(ComplexityAnalyzer.compute(caller, callee));
            step.setBranchScore(BranchAnalyzer.compute(caller, callee));
            step.setTaintMapping(summariseTaintMapping(caller, callee));
            steps.add(step);
        }
        return steps;
    }

    /**
     * R1—R5 判定。任何异常都退回 UNKNOWN 断点——分类器出错绝不能变成「跳过验证」。
     */
    protected StepProjection classifyStep(int stepIndex, MethodCall caller, MethodCall callee) {
        StepProjection step = unresolvedStep(stepIndex, caller.getMethodSignature(), callee.getMethodSignature());

        try {
            Body body = caller.getSootMethod().retrieveActiveBody();
            List<Unit> callSites = TaintFlowAnalysis.findTriggeredMethodUnit(
                    new ExceptionalUnitGraph(body), callee.getSootMethod());

            if (callSites.isEmpty()) {
                step.setEvidence("未在 caller 中定位到 callee 调用点: " + callee.getMethodSignature());
                return step;
            }

            StepTrace worst = null;
            boolean anyGuarded = false;
            List<String> evidence = new ArrayList<>();
            for (Unit callSite : callSites) {
                StepTrace trace = StepClassifier.classify(body, callSite, maxDepth);
                evidence.add("--- call site: " + callSite + " ---\n" + trace.getEvidence());
                anyGuarded |= trace.isGuarded();
                if (worst == null || StepClassifier.worse(worst.getKind(), trace.getKind()) != worst.getKind()) {
                    worst = trace;
                }
            }

            // 多调用点取最劣；证据保留全部调用点，便于人工核对
            step.setKind(worst.getKind());
            step.setGuarded(anyGuarded);
            step.getParamProjections().addAll(worst.getParamProjections());
            step.setEvidence(String.join("\n", evidence));
        } catch (Throwable t) {
            log.warn("ProjectionClassifyError: caller={} callee={} reason={}",
                    caller.getMethodSignature(), callee.getMethodSignature(), t.toString());
            step.setKind(ProjectionKind.UNKNOWN);
            step.setEvidence("分类异常，保守判为断点: " + t);
        }
        return step;
    }

    /**
     * 把 taintObjectMap（callee 实参下标 → caller 侧污点对象）压成可序列化、可 diff 的字符串摘要。
     * key 与 value 均排序，保证同一输入跨运行字节一致。
     */
    private Map<Integer, List<String>> summariseTaintMapping(MethodCall caller, MethodCall callee) {
        Map<Integer, List<String>> summary = new TreeMap<>();
        try {
            MethodParameterMappingAnalysis analysis = new MethodParameterMappingAnalysis(caller, callee);
            analysis.doAnalysis();

            for (Map.Entry<Integer, Set<TaintObject>> entry : analysis.getTaintObjectMap().entrySet()) {
                List<String> descriptions = new ArrayList<>();
                for (TaintObject taintObject : entry.getValue()) {
                    descriptions.add(describe(taintObject));
                }
                Collections.sort(descriptions);
                summary.put(entry.getKey(), descriptions);
            }
        } catch (Throwable t) {
            // 摘要失败不影响分类结果：taintMapping 留空，分类仍走 UNKNOWN 兜底
            log.warn("ProjectionTaintMappingError: caller={} callee={} reason={}",
                    caller.getMethodSignature(), callee.getMethodSignature(), t.toString());
        }
        return summary;
    }

    static String describe(TaintObject taintObject) {
        if (taintObject instanceof TaintParam) {
            TaintParam taintParam = (TaintParam) taintObject;
            return "PARAM " + taintParam.getMethodSignature() + " #" + taintParam.getIndex();
        }
        if (taintObject instanceof TaintField) {
            return "FIELD " + ((TaintField) taintObject).getFieldSignature();
        }
        return String.valueOf(taintObject);
    }
}
