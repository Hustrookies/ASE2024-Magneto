package com.magneto.staticanalysis.projection;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * SPEC S3：值级投影与约束生成。
 *
 * 投影方向沿链反向。PoC 给出 F₀ 的实参值；步骤 i 的 ParamProjection 说明 callee Fᵢ₋₁ 的
 * 实参 j 由 caller Fᵢ 的形参 k 经算子链 O 得到，于是 Fᵢ 形参 k 的要求 = O 的逆作用于该实参
 * 的要求，而这个要求正是步骤 i+1 的 callee 实参要求。断点步骤无法求逆，传播在此中止，
 * 改为渲染「构造目标」交给 LLM。
 *
 * 纯函数，不依赖 Soot / Spring / MethodCall，因此可脱离流水线单测。
 */
public final class ConstraintProjector {

    /** 要求映射里的特殊键：约束落在 caller 的接收者对象字段上，而非任何形参。 */
    public static final int RECEIVER_FIELD_KEY = -1;

    /** 下层没有传来要求时的占位文本。 */
    public static final String NO_REQUIREMENT = "(unconstrained: no requirement propagated from the layer below)";

    /**
     * 断点步骤专用：下游传播在更靠内的断点处中止，本步拿不到要求值。
     * 不能只丢一个裸占位符给 LLM——那等于没有信息，反而干扰 prompt。
     * 整步只渲染一次（不是每个实参重复一次），避免无谓地撑大 prompt。
     */
    public static final String NO_DOWNSTREAM_REQUIREMENT_HINT =
            "NO DOWNSTREAM REQUIREMENT: for the arguments marked above, projection stopped at a breakpoint "
                    + "further down the chain, so no concrete target value is known. Choose a value that causes "
                    + "the callee to be invoked and drives execution toward the vulnerable function.";

    /**
     * classify 阶段还没有 PoC 具体值，用它占位；S4 在运行时用 Context 里的真实值重新渲染。
     * 带实参下标，否则同一层的所有约束文本会完全一样，人工核对时无从对应。
     */
    public static String pocPlaceholder(int calleeArgIndex) {
        return "the runtime value of PoC arg " + calleeArgIndex
                + " of the vulnerable function (F0), captured by executing the ground-truth testcase";
    }

    private ConstraintProjector() {
    }

    /**
     * 单步反向传播：callee 实参要求 → caller 形参/接收者字段要求。
     * 断点步骤与不可投影来源一律不产出映射，避免伪造一个其实无法直接赋值的「值级映射」。
     */
    public static Map<Integer, String> propagateStep(StepProjection step, Map<Integer, String> calleeArgRequirements) {
        Map<Integer, String> callerRequirements = new LinkedHashMap<>();
        if (step.isBreakpoint()) {
            return callerRequirements;
        }

        for (ParamProjection param : step.getParamProjections()) {
            String requirement = calleeArgRequirements.get(param.getCalleeArgIndex());
            if (requirement == null) {
                continue;
            }
            switch (param.getSourceKind()) {
                case CALLER_PARAM:
                    callerRequirements.put(param.getCallerParamIndex(), isValueIdentity(param.getDerivationOps())
                            ? requirement
                            : rewrite(param.getDerivationOps(), requirement));
                    break;
                case CALLER_FIELD:
                    callerRequirements.put(RECEIVER_FIELD_KEY,
                            rewriteField(param.getDerivationOps(), requirement));
                    break;
                case CONSTANT:
                case NEW_OBJECT:
                case UNRESOLVED:
                default:
                    // 常量对 caller 无约束；构造与不可解析无法求逆
                    break;
            }
        }
        return callerRequirements;
    }

    /**
     * 整链反向传播。返回值按 reverseChainList 下标索引，长度 = 步数 + 1：
     * 下标 0 是传入的 PoC 要求（即 F₀ 的实参要求），下标 k 是 F_k 的形参要求。
     */
    public static List<Map<Integer, String>> propagateChain(ChainProjection chain, Map<Integer, String> pocRequirements) {
        List<Map<Integer, String>> byDepth = new ArrayList<>();
        Map<Integer, String> current = pocRequirements;
        byDepth.add(current);

        for (StepProjection step : chain.getSteps()) {
            current = propagateStep(step, current);
            byDepth.add(current);
        }
        return byDepth;
    }

    /**
     * 渲染单步的 projectedConstraints：每个 callee 实参一行，顺序与实参下标一致。
     * 断点步骤额外产出一行可达性义务（S4 注入 prompt 时不能只给构造目标，
     * 否则合成的种子可能根本到不了 callee）。
     */
    public static List<String> render(StepProjection step, Map<Integer, String> calleeArgRequirements) {
        List<String> lines = new ArrayList<>();
        boolean anyRequirementMissing = false;

        for (ParamProjection param : step.getParamProjections()) {
            String requirement = calleeArgRequirements.get(param.getCalleeArgIndex());
            anyRequirementMissing |= requirement == null;
            lines.add(renderParam(step, param, requirement));
        }

        if (step.getKind() == ProjectionKind.CONDITIONAL_SELECT) {
            lines.add("REACHABILITY OBLIGATION: this call site is reached only under a condition "
                    + "(a guarding branch, or the argument has several definitions across branches). "
                    + "The seed must drive the caller into this call site, not merely supply the argument value.");
        }
        if (step.isBreakpoint() && anyRequirementMissing) {
            lines.add(NO_DOWNSTREAM_REQUIREMENT_HINT);
        }
        return lines;
    }

    /**
     * S4 用它判断某实参能否直接把下层值原样拷进 caller 形参（免 LLM 合成）。
     */
    public static boolean isDirectValueMapping(StepProjection step, ParamProjection param) {
        return !step.isBreakpoint()
                && param.getSourceKind() == ProjectionSource.CALLER_PARAM
                && isValueIdentity(param.getDerivationOps());
    }

    /**
     * 用运行时的真实值渲染约束。静态阶段只有占位符；到 fuzz 阶段
     * {@code Context.getParamsValue()} 已经有 PoC 的实际取值，注入 prompt 的
     * 必须是真实值，否则"约束注入"注入的是一句描述而非约束。
     *
     * @param calleeArgValues 上一步 Context 中 callee 各实参的运行时值
     */
    public static List<String> renderWithRuntimeValues(StepProjection step, Object[] calleeArgValues) {
        Map<Integer, String> requirements = new LinkedHashMap<>();
        if (calleeArgValues != null) {
            for (int j = 0; j < calleeArgValues.length; j++) {
                requirements.put(j, describeValue(calleeArgValues[j]));
            }
        }
        return render(step, requirements);
    }

    private static final int MAX_VALUE_TEXT = 200;

    /**
     * 把一个运行时值渲染成可注入 prompt 的短描述。长值截断并显式标注，
     * 否则 LLM 会把截断结果当成完整约束。
     */
    public static String describeValue(Object value) {
        if (value == null) {
            return "null";
        }
        String text;
        try {
            text = String.valueOf(value);
        } catch (Throwable t) {
            text = "<unprintable: " + t.getClass().getSimpleName() + ">";
        }
        if (text.length() > MAX_VALUE_TEXT) {
            text = text.substring(0, MAX_VALUE_TEXT) + "...(truncated, " + text.length() + " chars total)";
        }
        String type = value.getClass().getName();
        return value instanceof CharSequence ? "\"" + text + "\" (" + type + ")" : text + " (" + type + ")";
    }

    /**
     * @param requirement 下层传来的要求值，null 表示没有（下游在断点处中止了传播）
     */
    private static String renderParam(StepProjection step, ParamProjection param, String requirement) {
        int arg = param.getCalleeArgIndex();

        if (step.isBreakpoint()) {
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("callee arg %d comes from %s, but this step is a projection breakpoint (%s)",
                    arg, describeStructure(param), step.getKind()));
            if (requirement == null) {
                sb.append("; no downstream requirement reached it.");
            } else {
                sb.append(String.format(". CONSTRUCTION TARGET: make callee arg %d satisfy: %s", arg, requirement));
            }
            return sb.toString();
        }

        String required = requirement != null ? requirement : NO_REQUIREMENT;
        switch (param.getSourceKind()) {
            case CALLER_PARAM:
                if (isValueIdentity(param.getDerivationOps())) {
                    return String.format("callee arg %d <- caller param %d (direct value): caller param %d must be %s",
                            arg, param.getCallerParamIndex(), param.getCallerParamIndex(), required);
                }
                return String.format("callee arg %d <- caller param %d via %s: %s",
                        arg, param.getCallerParamIndex(), param.getDerivationOps(),
                        rewrite(param.getDerivationOps(), required));
            case CALLER_FIELD:
                return String.format("callee arg %d <- receiver object via %s: %s",
                        arg, param.getDerivationOps(), rewriteField(param.getDerivationOps(), required));
            case CONSTANT:
                return String.format("callee arg %d is a constant in the caller body: no constraint on the caller", arg);
            case NEW_OBJECT:
            case UNRESOLVED:
            default:
                return String.format("callee arg %d is not statically projectable (source %s): %s",
                        arg, param.getSourceKind(), required);
        }
    }

    /**
     * 断点步骤也要把已知的结构信息交出去：即使求不出值，
     * 「这个实参来自哪个形参/字段」对 LLM 构造种子仍然是有效约束。
     */
    private static String describeStructure(ParamProjection param) {
        switch (param.getSourceKind()) {
            case CALLER_PARAM:
                String base = "caller param " + param.getCallerParamIndex();
                return isValueIdentity(param.getDerivationOps())
                        ? base
                        : base + " via " + param.getDerivationOps();
            case CALLER_FIELD:
                return param.getDerivationOps().isEmpty()
                        ? "the receiver object (this)"
                        : "the receiver object via " + param.getDerivationOps();
            case CONSTANT:
                return "a constant in the caller body";
            case NEW_OBJECT:
                return "a value constructed inside the caller";
            case UNRESOLVED:
            default:
                return "an expression that cannot be resolved statically";
        }
    }

    /**
     * 只有类型转换在值级是恒等（含拆装箱产生的 (int) 之类编译器产物）。
     * 拼接、包装都会改变值，必须转写成约束而不是直接赋值。
     */
    private static boolean isValueIdentity(List<String> ops) {
        for (String op : ops) {
            if (!DerivationOps.CAST.equals(op)) {
                return false;
            }
        }
        return true;
    }

    private static String rewrite(List<String> ops, String requirement) {
        return "the value after " + ops + " must satisfy: " + requirement;
    }

    private static String rewriteField(List<String> ops, String requirement) {
        String accessor = ops.isEmpty() ? "the projected field" : describeAccessor(ops.get(0));
        return accessor + " of the receiver object must return a value that satisfies: " + requirement;
    }

    private static String describeAccessor(String op) {
        int open = op.indexOf('(');
        int close = op.lastIndexOf(')');
        if (open >= 0 && close > open) {
            return op.substring(open + 1, close) + "()";
        }
        return op;
    }
}
