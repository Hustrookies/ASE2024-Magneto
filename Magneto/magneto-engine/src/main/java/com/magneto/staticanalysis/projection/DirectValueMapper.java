package com.magneto.staticanalysis.projection;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * SPEC 3.3：非断点步骤的直接值映射。把上一步 Context 里 callee 的实参值，
 * 按投影结果填进 caller 的形参数组，从而免掉一次 LLM 调用。
 *
 * 红线：任何不确定（类型不符、下标越界、原始类型拿到 null）一律返回 false，
 * 让调用方放弃直接合成、退回完整定向 fuzz——宁可多跑一次 fuzz，不可塞一个错值。
 * 失败时不留半填的数组。
 */
public final class DirectValueMapper {

    private static final Map<Class<?>, Class<?>> PRIMITIVE_WRAPPERS = new HashMap<>();

    static {
        PRIMITIVE_WRAPPERS.put(boolean.class, Boolean.class);
        PRIMITIVE_WRAPPERS.put(byte.class, Byte.class);
        PRIMITIVE_WRAPPERS.put(char.class, Character.class);
        PRIMITIVE_WRAPPERS.put(short.class, Short.class);
        PRIMITIVE_WRAPPERS.put(int.class, Integer.class);
        PRIMITIVE_WRAPPERS.put(long.class, Long.class);
        PRIMITIVE_WRAPPERS.put(float.class, Float.class);
        PRIMITIVE_WRAPPERS.put(double.class, Double.class);
    }

    private DirectValueMapper() {
    }

    /**
     * @param callerParams     caller 的形参数组，就地填充
     * @param callerParamTypes caller 的形参类型，取自 MethodCall.getParameterTypes()
     * @param calleeArgs       上一步 Context 中 callee 的实参值，即 Context.getParamsValue()
     * @return 全部直接映射均成功；false 表示应放弃直接合成
     */
    public static boolean apply(Object[] callerParams, Class<?>[] callerParamTypes,
                                Object[] calleeArgs, StepProjection step) {
        Object[] staged = callerParams.clone();

        for (ParamProjection param : step.getParamProjections()) {
            if (!ConstraintProjector.isDirectValueMapping(step, param)) {
                continue;
            }

            int target = param.getCallerParamIndex();
            int source = param.getCalleeArgIndex();
            if (target < 0 || target >= staged.length || target >= callerParamTypes.length) {
                return false;
            }
            if (source < 0 || source >= calleeArgs.length) {
                return false;
            }

            Object value = calleeArgs[source];
            Class<?> type = callerParamTypes[target];

            if (value == null) {
                if (type.isPrimitive()) {
                    return false;
                }
                staged[target] = null;
                continue;
            }

            Object converted = convert(type, value);
            if (converted == null) {
                return false;
            }
            staged[target] = converted;
        }

        System.arraycopy(staged, 0, callerParams, 0, callerParams.length);
        return true;
    }

    /**
     * 反射调用会自动拆箱，所以原始类型只需确认包装类型匹配即可原样返回。
     *
     * @return null 表示类型不兼容
     */
    private static Object convert(Class<?> targetType, Object value) {
        if (targetType.isPrimitive()) {
            Class<?> wrapper = PRIMITIVE_WRAPPERS.get(targetType);
            return wrapper != null && wrapper.isInstance(value) ? value : null;
        }
        return targetType.isInstance(value) ? value : null;
    }

    /**
     * 该步骤是否存在至少一个可直接拷值的实参。没有任何可映射实参时，
     * 直接合成没有意义（等于让 fixContext 去猜），应当直接走完整流程。
     */
    public static boolean hasAnyDirectMapping(StepProjection step) {
        List<ParamProjection> params = step.getParamProjections();
        for (ParamProjection param : params) {
            if (ConstraintProjector.isDirectValueMapping(step, param)) {
                return true;
            }
        }
        return false;
    }
}
