package com.magneto.staticanalysis.projection;

/**
 * 单个 callee 实参的溯源终点类型（SPEC 3.1 ParamProjection.sourceKind）。
 */
public enum ProjectionSource {

    /** 溯源到 caller 的形参。 */
    CALLER_PARAM,

    /** 溯源到 caller 所属对象的字段。 */
    CALLER_FIELD,

    /** 溯源到常量。 */
    CONSTANT,

    /** 溯源到调用点内新建的对象。 */
    NEW_OBJECT,

    /** 溯源失败（深度超限、接口分发不可解析等）。 */
    UNRESOLVED
}
