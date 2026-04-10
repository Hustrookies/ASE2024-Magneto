package com.magneto.staticanalysis;
import com.magneto.staticanalysis.dataflow.ComplexityAnalyzer;
import com.magneto.staticanalysis.callgraph.BranchAnalyzer;
import java.io.Serializable;
import com.magneto.testcase.model.TestcaseUnit;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class MethodCallChain {

    private final List<MethodCall> methodCallList;
    private Map<String, List<TestcaseUnit>> testcaseMap; // vul name ---> testcase unit list

    public MethodCallChain(List<MethodCall> methodCallList) {
        if (methodCallList == null || methodCallList.isEmpty()) {
            throw new RuntimeException("method call list can not be null or empty");
        }
        this.methodCallList = methodCallList;
    }

    public List<MethodCall> forwardChainList() {
        return methodCallList;
    }

    public List<MethodCall> reverseChainList() {
        List<MethodCall> reversed = new ArrayList<>(methodCallList);
        Collections.reverse(reversed);
        return reversed;
    }

    public Iterator<MethodCall> forwardChainIterator() {
        return methodCallList.iterator();
    }

    public Iterator<MethodCall> reverseChainIterator() {
        List<MethodCall> reversed = new ArrayList<>(methodCallList);
        Collections.reverse(reversed);
        return reversed.iterator();
    }

    public Map<String, List<TestcaseUnit>> getTestcaseMap() {
        return testcaseMap;
    }

    public void setTestcaseMap(@NonNull Map<String, List<TestcaseUnit>> testcaseMap) {
        this.testcaseMap = testcaseMap;
    }

    public MethodCall getVulMethodCall() {
        return this.reverseChainIterator().next();
    }

    public int length() {
        return methodCallList.size();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        MethodCallChain that = (MethodCallChain) o;

        if (methodCallList == null && that.methodCallList == null) return true;
        if (methodCallList == null || that.methodCallList == null) return false;
        if (methodCallList.size() != that.methodCallList.size()) return false;
        for (int i = 0; i < methodCallList.size(); i++) {
            if (!methodCallList.get(i).equals(that.methodCallList.get(i))) return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        if (methodCallList == null) return 0;
        else {
            return Objects.hash(methodCallList.stream().map(MethodCall::getMethodSignature).collect(Collectors.toList()).toArray());
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < methodCallList.size(); i++) {
            for (int j = 0; j < i; j++) sb.append("  ");
            sb.append(methodCallList.get(i).toString());
            sb.append('\n');
        }
        return sb.toString();
    }

    /**
    * 调用链每一步的分数数据结构
    */
    public static class StepScore implements Serializable {
            public final MethodCall caller;
            public final MethodCall callee;
            public final int complexityScore;
            public final int branchScore;

            public StepScore(MethodCall caller, MethodCall callee, int complexityScore, int branchScore) {
                this.caller = caller;
                this.callee = callee;
                this.complexityScore = complexityScore;
                this.branchScore = branchScore;
            }
            @Override
            public String toString() {
                return String.format("caller:%s -> callee:%s | complexity: %d, branch: %d", caller, callee, complexityScore, branchScore);
            }
    }

    /**
     * 计算调用链每一步的复杂度分数和分支分数
     */
    public List<StepScore> calculateStepScores() {
        List<StepScore> scores = new ArrayList<>();
        for (int i = 1; i < methodCallList.size(); i++) {
            MethodCall fi = methodCallList.get(i);
            MethodCall fi_1 = methodCallList.get(i - 1);
            int complexityScore = ComplexityAnalyzer.compute(fi_1, fi);
            int branchScore = BranchAnalyzer.compute(fi_1, fi);
            scores.add(new StepScore(fi_1, fi, complexityScore, branchScore));
        }
        return scores;
    }

}

