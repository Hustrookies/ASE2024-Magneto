package com.magneto.staticanalysis.projection;

/**
 * 派生算子名（SPEC 3.1 ParamProjection.derivationOps）。
 * S2 产出、S3 消费，共用这里一份常量，避免两边字符串漂移。
 */
public final class DerivationOps {

    /** 字段读或 getter 调用，附带字段名/方法名，如 GET_FIELD(getName)。 */
    public static final String GET_FIELD = "GET_FIELD";

    /** 字符串拼接（含 Java 8 的 StringBuilder 链）。 */
    public static final String STR_CONCAT = "STR_CONCAT";

    /** 类型转换。 */
    public static final String CAST = "CAST";

    /** 单层包装，如装箱或 Collections.singletonList。 */
    public static final String WRAP = "WRAP";

    private DerivationOps() {
    }

    public static String getField(String name) {
        return GET_FIELD + "(" + name + ")";
    }

    public static String getWrap(String signature) {
        return WRAP + "(" + signature + ")";
    }
}
