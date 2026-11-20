package com.magneto.staticanalysis.projection;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 * SPEC 3.3 任务 5：按复杂度分数给断点步骤分级 fuzz 时间预算。
 *
 * 默认关闭（config.projection-grade-fuzz-budget=false）：S5 的 off/full 对照必须只在
 * 「跳过与约束注入」这一个变量上有差异，预算分级会引入第二个变量，把成功率差异的归因搞浑。
 * 单独开关便于阶段 B 做消融。
 */
public class FuzzBudgetTest {

    private StepProjection step(ProjectionKind kind, Integer complexity) {
        StepProjection s = new StepProjection();
        s.setKind(kind);
        s.setComplexityScore(complexity);
        return s;
    }

    @Test
    public void aHighComplexityBreakpointGetsTheFullBudget() {
        assertEquals(600000L, FuzzBudget.grade(600000L, 50, 30));
    }

    @Test
    public void aLowComplexityBreakpointGetsHalfTheBudget() {
        assertEquals(300000L, FuzzBudget.grade(600000L, 10, 30));
    }

    @Test
    public void aScoreExactlyAtTheThresholdGetsTheFullBudget() {
        assertEquals(600000L, FuzzBudget.grade(600000L, 30, 30));
    }

    @Test
    public void anUnknownScoreGetsTheFullBudgetRatherThanBeingStarved() {
        assertEquals("分数缺失时不得削减预算，否则失败无法归因", 600000L, FuzzBudget.grade(600000L, null, 30));
    }

    @Test
    public void theThresholdIsTheMedianOfTheBreakpointSteps() {
        List<StepProjection> steps = Arrays.asList(
                step(ProjectionKind.PASSTHROUGH, 5),          // 非断点，不计入
                step(ProjectionKind.UNKNOWN, 10),
                step(ProjectionKind.COMPLEX_CONSTRUCTION, 30),
                step(ProjectionKind.CONDITIONAL_SELECT, 50));

        assertEquals(30, FuzzBudget.medianComplexity(steps));
    }

    @Test
    public void theMedianOfAnEvenCountTakesTheLowerMiddle() {
        List<StepProjection> steps = Arrays.asList(
                step(ProjectionKind.UNKNOWN, 10),
                step(ProjectionKind.UNKNOWN, 20),
                step(ProjectionKind.UNKNOWN, 30),
                step(ProjectionKind.UNKNOWN, 40));

        assertEquals(20, FuzzBudget.medianComplexity(steps));
    }

    @Test
    public void aChainWithNoBreakpointHasNoThreshold() {
        List<StepProjection> steps = Collections.singletonList(step(ProjectionKind.PASSTHROUGH, 5));

        assertEquals("没有断点步骤时无从分级，返回 0 使所有（不存在的）断点都拿满预算",
                0, FuzzBudget.medianComplexity(steps));
    }

    @Test
    public void stepsWithNoScoreAreIgnoredWhenComputingTheThreshold() {
        List<StepProjection> steps = Arrays.asList(
                step(ProjectionKind.UNKNOWN, null),
                step(ProjectionKind.UNKNOWN, 10),
                step(ProjectionKind.UNKNOWN, 30));

        // 有效分数 [10, 30]，取下中位 -> 10
        assertEquals(10, FuzzBudget.medianComplexity(steps));
    }

    @Test
    public void anEmptyChainHasNoThreshold() {
        assertEquals(0, FuzzBudget.medianComplexity(new ArrayList<StepProjection>()));
    }
}
