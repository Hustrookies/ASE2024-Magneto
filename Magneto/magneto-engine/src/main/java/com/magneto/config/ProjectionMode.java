package com.magneto.config;

/**
 * 约束投影的介入程度（SPEC 3.3 配置开关 config.projection-mode）。
 */
public enum ProjectionMode {

    /** 基线行为：不做投影分析，不产出 projection.json。 */
    OFF,

    /** 只计算并输出 projection.json，fuzz 行为与 OFF 完全一致（对照实验用）。 */
    CLASSIFY,

    /** 非断点步骤跳过定向 fuzz，断点步骤注入投影约束，试运行失败自动升级。 */
    FULL;

    /**
     * 只有 FULL 会改变 fuzz 行为；CLASSIFY 必须与 OFF 逐行一致，这是 S1/S4 的验收红线。
     */
    public boolean affectsFuzzing() {
        return this == FULL;
    }
}
