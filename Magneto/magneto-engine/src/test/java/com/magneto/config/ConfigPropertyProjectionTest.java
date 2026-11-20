package com.magneto.config;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * SPEC 3.3 配置开关。默认值必须是 OFF——否则未显式配置的运行会静默偏离基线，
 * 破坏 S1/S4「off 模式与基线快照一致」的对照前提。
 */
public class ConfigPropertyProjectionTest {

    @Test
    public void projectionIsOffByDefault() {
        assertEquals(ProjectionMode.OFF, new ConfigProperty().getProjectionMode());
    }

    @Test
    public void conservativeFallbackIsOnByDefault() {
        assertTrue(new ConfigProperty().getProjectionConservative());
    }

    @Test
    public void passthroughSkipsLlmByDefault() {
        assertTrue(new ConfigProperty().getProjectionSkipLlmForPassthrough());
    }

    /**
     * 预算分级默认必须关闭：S5 的 off/full 对照只能有「跳过与约束注入」一个变量，
     * 否则成功率差异无法归因到投影本身。
     */
    @Test
    public void fuzzBudgetGradingIsOffByDefault() {
        assertFalse(new ConfigProperty().getProjectionGradeFuzzBudget());
    }

    @Test
    public void onlyFullModeAffectsFuzzing() {
        assertFalse(ProjectionMode.OFF.affectsFuzzing());
        assertFalse("classify must stay behaviourally identical to off", ProjectionMode.CLASSIFY.affectsFuzzing());
        assertTrue(ProjectionMode.FULL.affectsFuzzing());
    }

    @Test
    public void springBindsLowercaseModeNames() {
        ConfigProperty property = new ConfigProperty();

        property.setProjectionMode(ProjectionMode.valueOf("classify".toUpperCase()));

        assertEquals(ProjectionMode.CLASSIFY, property.getProjectionMode());
    }
}
