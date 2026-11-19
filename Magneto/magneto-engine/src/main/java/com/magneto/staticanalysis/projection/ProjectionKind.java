package com.magneto.staticanalysis.projection;

/**
 * 调用链单步 ⟨caller Fᵢ, callee Fᵢ₋₁⟩ 的参数关联分类（SPEC 3.2 R1—R5）。
 */
public enum ProjectionKind {

    /** R1：实参 def 链只经 IdentityStmt 与局部拷贝，值可直接映射。 */
    PASSTHROUGH,

    /** R2：def 链含可枚举算子（getter/字段读、字符串拼接、装箱、单层包装）。 */
    SIMPLE_DERIVATION,

    /** R3：def 链含 NewExpr + 多次字段写/setter、builder 链、循环填充。断点。 */
    COMPLEX_CONSTRUCTION,

    /** R4：调用点被条件分支支配，或实参在不同分支有多定义点。断点。 */
    CONDITIONAL_SELECT,

    /** R5：深度超限 / 无法解析 / 异常。保守兜底为断点。 */
    UNKNOWN;

    /**
     * SPEC 3.1 断点判定。宁可多验证，不可漏验证——只有能确证为可跳过的分类才返回 false。
     */
    public boolean isBreakpointKind() {
        return this == COMPLEX_CONSTRUCTION || this == CONDITIONAL_SELECT || this == UNKNOWN;
    }
}
