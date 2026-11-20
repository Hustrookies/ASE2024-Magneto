package com.magneto.staticanalysis.projection;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * SPEC 3.3 任务 5：按复杂度分数给断点步骤分级 fuzz 时间预算。
 *
 * 默认关闭（config.projection-grade-fuzz-budget=false）。S5 的 off/full 对照必须只在
 * 「跳过与约束注入」这一个变量上有差异；预算分级会引入第二个变量，
 * 让成功率差异无法归因。单独开关便于阶段 B 做消融。
 */
public final class FuzzBudget {

    private FuzzBudget() {
    }

    /**
     * @param complexityScore null 表示分数缺失，此时给满预算——削减一个我们不了解的步骤的预算，
     *                        会让后续失败无法归因到投影误判还是时间不够
     */
    public static long grade(long maxFuzzTime, Integer complexityScore, int threshold) {
        if (complexityScore == null) {
            return maxFuzzTime;
        }
        return complexityScore >= threshold ? maxFuzzTime : maxFuzzTime / 2;
    }

    /**
     * 只统计断点步骤：非断点步骤不进变异循环，其复杂度与预算无关。
     * 取下中位数，保证结果是链上真实出现过的分数。
     */
    public static int medianComplexity(List<StepProjection> steps) {
        List<Integer> scores = new ArrayList<>();
        for (StepProjection step : steps) {
            if (step.isBreakpoint() && step.getComplexityScore() != null) {
                scores.add(step.getComplexityScore());
            }
        }
        if (scores.isEmpty()) {
            return 0;
        }
        Collections.sort(scores);
        return scores.get((scores.size() - 1) / 2);
    }
}
