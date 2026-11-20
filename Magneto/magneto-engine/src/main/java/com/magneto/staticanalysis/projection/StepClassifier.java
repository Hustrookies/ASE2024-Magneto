package com.magneto.staticanalysis.projection;

import com.magneto.util.ReflectionUtil;
import soot.Body;
import soot.Local;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.ArrayRef;
import soot.jimple.AssignStmt;
import soot.jimple.BinopExpr;
import soot.jimple.CastExpr;
import soot.jimple.Constant;
import soot.jimple.DefinitionStmt;
import soot.jimple.IdentityStmt;
import soot.jimple.IfStmt;
import soot.jimple.InstanceFieldRef;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.NewArrayExpr;
import soot.jimple.NewExpr;
import soot.jimple.NewMultiArrayExpr;
import soot.jimple.ParameterRef;
import soot.jimple.Stmt;
import soot.jimple.ThisRef;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * SPEC 3.2 的 R1—R5 判定：自调用点向后溯源每个实参的 def 链，给出分类、来源与派生算子。
 *
 * 刻意只依赖 Soot 对象（Body / Unit / Value），不碰 MethodCall、MavenDependency 或
 * ConfigProperty——因此可以在单测里用 fixture 直接验证，不需要 Spring 上下文，
 * 也不会触发 TaintFlowAnalysis 那个依赖 SpringUtil.getBean 的静态初始化。
 *
 * 红线：宁可多验证，不可漏验证。任何无法确证的情形一律落到断点类
 * （COMPLEX_CONSTRUCTION / CONDITIONAL_SELECT / UNKNOWN），绝不判成非断点。
 */
public final class StepClassifier {

    /** Java 8 把 `a + b` 编成 StringBuilder 链，需按 R2 的字符串拼接识别，否则会误判成 R3 构造。 */
    private static final Set<String> STRING_BUILDER_TYPES = new HashSet<>(
            Arrays.asList("java.lang.StringBuilder", "java.lang.StringBuffer"));

    private static final Set<String> PRIMITIVE_WRAPPERS = new HashSet<>(Arrays.asList(
            "java.lang.Boolean", "java.lang.Byte", "java.lang.Character", "java.lang.Short",
            "java.lang.Integer", "java.lang.Long", "java.lang.Float", "java.lang.Double"));

    private static final Set<String> WRAP_CLASSES = new HashSet<>(
            Arrays.asList("java.util.Collections", "java.util.Arrays", "java.util.Optional"));

    private static final Set<String> WRAP_METHODS = new HashSet<>(Arrays.asList(
            "singleton", "singletonList", "singletonMap", "asList", "of",
            "emptyList", "emptySet", "emptyMap"));

    private StepClassifier() {
    }

    public static StepTrace classify(Body callerBody, Unit invokeUnit, int maxDepth) {
        Stmt stmt = (Stmt) invokeUnit;
        if (!stmt.containsInvokeExpr()) {
            return unknown(Collections.<ParamProjection>emptyList(), "not an invoke statement: " + invokeUnit, false);
        }

        InvokeExpr invokeExpr = stmt.getInvokeExpr();
        List<Value> args = invokeExpr.getArgs();
        List<String> evidence = new ArrayList<>();
        List<ParamProjection> projections = new ArrayList<>(args.size());
        ProjectionKind worst = ProjectionKind.PASSTHROUGH;

        for (int i = 0; i < args.size(); i++) {
            ArgTrace traced = traceValue(callerBody, args.get(i), invokeUnit, maxDepth, evidence);
            projections.add(traced.toParamProjection(i));
            worst = worse(worst, traced.kind);
        }

        List<Unit> guards = reachableGuards(callerBody, invokeUnit);
        boolean guarded = !guards.isEmpty();
        for (Unit guard : guards) {
            evidence.add(guard.toString());
        }
        if (guarded) {
            // R4：调用点被条件分支支配。不区分条件来源——形参守卫同样是必须满足的约束，
            // 漏判的代价（白跑一次试运行再升级）高于多判的代价（本来就要跑的定向 fuzz）。
            worst = worse(worst, ProjectionKind.CONDITIONAL_SELECT);
        }

        // 接收者分析：实参可投影不代表这一步可跳过
        worst = worse(worst, classifyReceiver(invokeExpr, callerBody, invokeUnit, maxDepth, evidence));

        return new StepTrace(worst, projections, join(evidence), guarded);
    }

    /**
     * 实例调用的接收者也必须是种子能提供的对象，否则到不了 callee。
     * R1—R5 只约束实参，这一条是它们的必要补充。
     *
     * 放行的情形只有三种：
     * <ol>
     *   <li>静态调用（没有接收者）；</li>
     *   <li>接收者就是 caller 自身（`this`），种子构造阶段本来就持有它；</li>
     *   <li>接收者是 `this` 的**直接字段读**（如 `this.objectMapper.readValue(...)`）——
     *       种子构造 caller 时会跑构造函数初始化字段，且 Magneto 既有的 fixContext
     *       「fix seed object context」分支会从 Context 回填接收者字段。
     *       实证依据：idworker 案例中这类步骤 10 次跳过全部成功、0 次升级。</li>
     * </ol>
     *
     * 其余一律升级为断点。典型反例是 QLExpress 的 {@code list.get(0).getObjectInner(parent)}：
     * 实参 parent 是纯透传的 caller 形参，但接收者是运行时派生对象，没有任何机制能回填，
     * 直接合成必然失败。该规则只会增加断点、不会减少，因此不可能违反
     * 「不允许把断点判成非断点」的红线。
     */
    private static ProjectionKind classifyReceiver(InvokeExpr invokeExpr, Body body, Unit invokeUnit,
                                                   int depth, List<String> evidence) {
        if (!(invokeExpr instanceof InstanceInvokeExpr)) {
            return ProjectionKind.PASSTHROUGH;
        }

        Value base = ((InstanceInvokeExpr) invokeExpr).getBase();
        if (!(base instanceof Local)) {
            evidence.add("receiver is not a local: " + base);
            return ProjectionKind.UNKNOWN;
        }

        Local baseLocal = (Local) base;
        if (isThisValue(body, baseLocal, invokeUnit)) {
            return ProjectionKind.PASSTHROUGH;
        }

        ArgTrace baseTrace = traceLocal(body, baseLocal, invokeUnit, depth, evidence);
        if (isDirectFieldOfThis(baseTrace)) {
            return ProjectionKind.PASSTHROUGH;
        }

        evidence.add("receiver is not synthesizable: " + baseLocal.getName()
                + " traces to " + baseTrace.kind + " / " + baseTrace.source + " " + baseTrace.ops);
        // 接收者即使能溯源到形参，种子也得额外提供一个已正确初始化的实例，
        // 这不是值级映射能解决的，因此至少是构造类断点。
        return baseTrace.kind.isBreakpointKind() ? baseTrace.kind : ProjectionKind.COMPLEX_CONSTRUCTION;
    }

    /** 只认「this 的直接字段读」这一跳；再经 getter 或多层派生就不放行。 */
    private static boolean isDirectFieldOfThis(ArgTrace trace) {
        return trace.source == ProjectionSource.CALLER_FIELD
                && trace.ops.size() <= 1
                && !trace.kind.isBreakpointKind();
    }

    /** 该值是否就是 caller 自身的接收者（唯一定义且为 `l := @this`）。 */
    private static boolean isThisValue(Body body, Value value, Unit useSite) {
        if (!(value instanceof Local)) {
            return false;
        }
        List<Unit> defs = backwardDefs(body, (Local) value, useSite);
        if (defs.size() != 1) {
            return false;
        }
        Unit def = defs.get(0);
        return def instanceof IdentityStmt && ((IdentityStmt) def).getRightOp() instanceof ThisRef;
    }

    // ---------------------------------------------------------------- 实参溯源

    private static ArgTrace traceValue(Body body, Value value, Unit useSite, int depth, List<String> evidence) {
        if (depth <= 0) {
            return ArgTrace.unresolved("溯源深度耗尽于 " + value);
        }
        if (value instanceof Constant) {
            return ArgTrace.constant();
        }
        if (value instanceof Local) {
            return traceLocal(body, (Local) value, useSite, depth, evidence);
        }
        if (value instanceof InstanceFieldRef) {
            InstanceFieldRef fieldRef = (InstanceFieldRef) value;
            evidence.add(value.toString());
            // 只有 this 的字段才由种子构造 + 既有 fixContext 回填；
            // 形参对象的字段（h.value）没有这个保证，记为 CALLER_FIELD 会渲染出
            // "callee arg N <- receiver object" 这种事实错误的硬约束。
            if (!isThisValue(body, fieldRef.getBase(), useSite)) {
                return ArgTrace.unresolved("字段读的基对象不是 this: " + fieldRef.getBase());
            }
            return ArgTrace.field(DerivationOps.getField(fieldRef.getField().getName()),
                    ProjectionKind.SIMPLE_DERIVATION);
        }
        if (value instanceof CastExpr) {
            evidence.add(value.toString());
            ArgTrace inner = traceValue(body, ((CastExpr) value).getOp(), useSite, depth - 1, evidence);
            return inner.withOp(DerivationOps.CAST, ProjectionKind.SIMPLE_DERIVATION);
        }
        if (value instanceof BinopExpr) {
            evidence.add(value.toString());
            BinopExpr binop = (BinopExpr) value;
            ArgTrace left = traceValue(body, binop.getOp1(), useSite, depth - 1, evidence);
            ArgTrace right = traceValue(body, binop.getOp2(), useSite, depth - 1, evidence);
            ArgTrace merged = left.merge(right);
            return merged.withOp(DerivationOps.STR_CONCAT, ProjectionKind.SIMPLE_DERIVATION);
        }
        if (value instanceof NewExpr || value instanceof NewArrayExpr || value instanceof NewMultiArrayExpr) {
            evidence.add(value.toString());
            return ArgTrace.newObject(ProjectionKind.COMPLEX_CONSTRUCTION);
        }
        if (value instanceof ArrayRef) {
            // 数组元素读意味着别处有数组填充（R3），保守判为构造
            evidence.add(value.toString());
            return ArgTrace.newObject(ProjectionKind.COMPLEX_CONSTRUCTION);
        }
        if (value instanceof InvokeExpr) {
            return traceInvoke(body, (InvokeExpr) value, useSite, depth, evidence);
        }

        evidence.add(String.valueOf(value));
        return ArgTrace.unresolved("无法溯源的实参形态: " + value.getClass().getSimpleName());
    }

    private static ArgTrace traceLocal(Body body, Local local, Unit useSite, int depth, List<String> evidence) {
        List<Unit> defs = backwardDefs(body, local, useSite);

        if (defs.isEmpty()) {
            evidence.add("no def for " + local.getName());
            return ArgTrace.unresolved("找不到 " + local.getName() + " 的定义点");
        }
        if (defs.size() > 1) {
            // R4：实参在不同分支有多定义点
            for (Unit def : defs) {
                evidence.add(def.toString());
            }
            return ArgTrace.multiDef(ProjectionKind.CONDITIONAL_SELECT, defs.size());
        }

        Unit def = defs.get(0);
        evidence.add(def.toString());
        return classifyDef(body, def, depth, evidence);
    }

    private static ArgTrace classifyDef(Body body, Unit def, int depth, List<String> evidence) {
        if (def instanceof IdentityStmt) {
            Value right = ((IdentityStmt) def).getRightOp();
            if (right instanceof ParameterRef) {
                return ArgTrace.callerParam(((ParameterRef) right).getIndex());
            }
            if (right instanceof ThisRef) {
                // 接收者对象本身：种子构造阶段已经持有它，无需额外约束
                return ArgTrace.thisRef();
            }
            return ArgTrace.unresolved("无法溯源的 identity 右值: " + right);
        }

        if (def instanceof AssignStmt) {
            Value right = ((AssignStmt) def).getRightOp();
            return traceValue(body, right, def, depth - 1, evidence);
        }

        return ArgTrace.unresolved("无法溯源的定义语句: " + def.getClass().getSimpleName());
    }

    private static ArgTrace traceInvoke(Body body, InvokeExpr invokeExpr, Unit defSite, int depth, List<String> evidence) {
        SootMethod method = invokeExpr.getMethod();

        if (isStringBuilderToString(invokeExpr)) {
            return traceStringBuilderChain(body, invokeExpr, defSite, depth, evidence);
        }

        if ("<init>".equals(method.getName())) {
            return ArgTrace.newObject(ProjectionKind.COMPLEX_CONSTRUCTION);
        }

        if (invokeExpr instanceof InstanceInvokeExpr
                && method.getParameterCount() == 0
                && ReflectionUtil.isGetMethod(method.getName())) {
            // R2：污点基对象的 getter
            Value base = ((InstanceInvokeExpr) invokeExpr).getBase();
            ArgTrace baseTrace = base instanceof Local
                    ? traceLocal(body, (Local) base, defSite, depth - 1, evidence)
                    : ArgTrace.unresolved("getter 基对象不是 local: " + base);
            return baseTrace.withOp(DerivationOps.getField(method.getName()), ProjectionKind.SIMPLE_DERIVATION);
        }

        if (isSimpleWrapper(method)) {
            ArgTrace inner = invokeExpr.getArgCount() == 1
                    ? traceValue(body, invokeExpr.getArg(0), defSite, depth - 1, evidence)
                    : ArgTrace.unresolved("包装方法实参个数异常: " + invokeExpr.getArgCount());
            return inner.withOp(DerivationOps.getWrap(method.getSignature()), ProjectionKind.SIMPLE_DERIVATION);
        }

        // 任意其它方法调用：返回值不可静态确定，R5 保守兜底
        return ArgTrace.unresolved("无法解析的方法调用: " + method.getSignature());
    }

    /**
     * 识别 `new StringBuilder().append(x).append(y).toString()`，按 R2 归为字符串拼接。
     * 链上任一环不可解析即整体退回 UNKNOWN。
     */
    private static ArgTrace traceStringBuilderChain(Body body, InvokeExpr toStringCall, Unit defSite,
                                                    int depth, List<String> evidence) {
        if (!(toStringCall instanceof InstanceInvokeExpr)) {
            return ArgTrace.unresolved("StringBuilder.toString 无基对象");
        }

        Value baseValue = ((InstanceInvokeExpr) toStringCall).getBase();
        if (!(baseValue instanceof Local)) {
            return ArgTrace.unresolved("StringBuilder 基对象不是 local: " + baseValue);
        }

        Local current = (Local) baseValue;
        Unit site = defSite;
        List<ArgTrace> operands = new ArrayList<>();
        boolean sawAllocation = false;
        int budget = Math.max(depth, 1) * 8;

        while (budget-- > 0) {
            List<Unit> defs = backwardDefs(body, current, site);
            if (defs.size() != 1) {
                return ArgTrace.unresolved("StringBuilder 链定义点不唯一: " + defs.size());
            }

            Unit def = defs.get(0);
            evidence.add(def.toString());

            if (!(def instanceof AssignStmt)) {
                return ArgTrace.unresolved("StringBuilder 链定义不是赋值语句");
            }
            Value right = ((AssignStmt) def).getRightOp();

            if (right instanceof NewExpr) {
                if (!STRING_BUILDER_TYPES.contains(((NewExpr) right).getBaseType().getClassName())) {
                    return ArgTrace.unresolved("toString 的基对象不是 StringBuilder: " + right);
                }
                sawAllocation = true;
                break;
            }

            if (!(right instanceof InstanceInvokeExpr)) {
                return ArgTrace.unresolved("StringBuilder 链中断于: " + right);
            }
            InstanceInvokeExpr appendCall = (InstanceInvokeExpr) right;
            if (!"append".equals(appendCall.getMethod().getName())) {
                return ArgTrace.unresolved("StringBuilder 链含非 append 调用: " + appendCall.getMethod().getName());
            }
            if (appendCall.getArgCount() == 1) {
                operands.add(traceValue(body, appendCall.getArg(0), def, depth - 1, evidence));
            }

            Value next = appendCall.getBase();
            if (!(next instanceof Local)) {
                return ArgTrace.unresolved("append 基对象不是 local: " + next);
            }
            current = (Local) next;
            site = def;
        }

        if (!sawAllocation) {
            return ArgTrace.unresolved("StringBuilder 链未在深度内到达分配点");
        }

        ArgTrace merged = ArgTrace.constant();
        for (ArgTrace operand : operands) {
            merged = merged.merge(operand);
        }
        return merged.withOp(DerivationOps.STR_CONCAT, ProjectionKind.SIMPLE_DERIVATION);
    }

    private static boolean isStringBuilderToString(InvokeExpr invokeExpr) {
        SootMethod method = invokeExpr.getMethod();
        return "toString".equals(method.getName())
                && method.getParameterCount() == 0
                && STRING_BUILDER_TYPES.contains(method.getDeclaringClass().getName());
    }

    private static boolean isSimpleWrapper(SootMethod method) {
        String declaringClass = method.getDeclaringClass().getName();
        String name = method.getName();

        if ("valueOf".equals(name)
                && (PRIMITIVE_WRAPPERS.contains(declaringClass) || "java.lang.String".equals(declaringClass))) {
            return true;
        }
        return WRAP_CLASSES.contains(declaringClass) && WRAP_METHODS.contains(name);
    }

    // ---------------------------------------------------------------- 控制流

    /**
     * R4：自调用点向后遍历，收集所有能到达它的条件分支。按 body 顺序返回，保证证据可复现。
     */
    private static List<Unit> reachableGuards(Body body, Unit invokeUnit) {
        UnitGraph graph = new BriefUnitGraph(body);
        Set<Unit> visited = new HashSet<>();
        Set<Unit> guards = new HashSet<>();
        Deque<Unit> stack = new ArrayDeque<>(graph.getPredsOf(invokeUnit));

        while (!stack.isEmpty()) {
            Unit unit = stack.pop();
            if (!visited.add(unit)) {
                continue;
            }
            if (unit instanceof IfStmt) {
                guards.add(unit);
            }
            stack.addAll(graph.getPredsOf(unit));
        }
        return inBodyOrder(body, guards);
    }

    /**
     * 收集能向后到达 useSite 的、对 local 的定义点。按 body 顺序返回。
     */
    private static List<Unit> backwardDefs(Body body, Local local, Unit useSite) {
        UnitGraph graph = new BriefUnitGraph(body);
        Set<Unit> visited = new HashSet<>();
        Set<Unit> defs = new LinkedHashSet<>();
        Deque<Unit> stack = new ArrayDeque<>(graph.getPredsOf(useSite));

        while (!stack.isEmpty()) {
            Unit unit = stack.pop();
            if (!visited.add(unit)) {
                continue;
            }
            if (unit instanceof DefinitionStmt && local.equals(((DefinitionStmt) unit).getLeftOp())) {
                defs.add(unit);
            }
            stack.addAll(graph.getPredsOf(unit));
        }
        return inBodyOrder(body, defs);
    }

    private static List<Unit> inBodyOrder(Body body, Set<Unit> units) {
        List<Unit> ordered = new ArrayList<>(units.size());
        for (Unit unit : body.getUnits()) {
            if (units.contains(unit)) {
                ordered.add(unit);
            }
        }
        return ordered;
    }

    // ---------------------------------------------------------------- 汇总

    static ProjectionKind worse(ProjectionKind left, ProjectionKind right) {
        return severity(right) > severity(left) ? right : left;
    }

    private static int severity(ProjectionKind kind) {
        switch (kind) {
            case PASSTHROUGH:
                return 0;
            case SIMPLE_DERIVATION:
                return 1;
            case CONDITIONAL_SELECT:
                return 2;
            case COMPLEX_CONSTRUCTION:
                return 3;
            case UNKNOWN:
            default:
                return 4;
        }
    }

    private static StepTrace unknown(List<ParamProjection> projections, String reason, boolean guarded) {
        return new StepTrace(ProjectionKind.UNKNOWN, projections, reason, guarded);
    }

    private static String join(List<String> evidence) {
        return String.join("\n", evidence);
    }

    /**
     * 单个实参的溯源结果。kind 是该实参自身的分类，步骤级 kind 由 worse() 汇总。
     */
    private static final class ArgTrace {

        private final ProjectionSource source;
        private final int callerParamIndex;
        private final List<String> ops;
        private final ProjectionKind kind;

        private ArgTrace(ProjectionSource source, int callerParamIndex, List<String> ops, ProjectionKind kind) {
            this.source = source;
            this.callerParamIndex = callerParamIndex;
            this.ops = ops;
            this.kind = kind;
        }

        static ArgTrace callerParam(int index) {
            return new ArgTrace(ProjectionSource.CALLER_PARAM, index, new ArrayList<String>(), ProjectionKind.PASSTHROUGH);
        }

        static ArgTrace thisRef() {
            return new ArgTrace(ProjectionSource.CALLER_FIELD, -1, new ArrayList<String>(), ProjectionKind.PASSTHROUGH);
        }

        static ArgTrace constant() {
            return new ArgTrace(ProjectionSource.CONSTANT, -1, new ArrayList<String>(), ProjectionKind.PASSTHROUGH);
        }

        static ArgTrace field(String op, ProjectionKind kind) {
            List<String> ops = new ArrayList<>();
            ops.add(op);
            return new ArgTrace(ProjectionSource.CALLER_FIELD, -1, ops, kind);
        }

        static ArgTrace newObject(ProjectionKind kind) {
            return new ArgTrace(ProjectionSource.NEW_OBJECT, -1, new ArrayList<String>(), kind);
        }

        static ArgTrace multiDef(ProjectionKind kind, int defCount) {
            List<String> ops = new ArrayList<>();
            ops.add("MULTI_DEF(" + defCount + ")");
            return new ArgTrace(ProjectionSource.UNRESOLVED, -1, ops, kind);
        }

        static ArgTrace unresolved(String reason) {
            List<String> ops = new ArrayList<>();
            ops.add("UNRESOLVED(" + reason + ")");
            return new ArgTrace(ProjectionSource.UNRESOLVED, -1, ops, ProjectionKind.UNKNOWN);
        }

        ArgTrace withOp(String op, ProjectionKind atLeast) {
            List<String> extended = new ArrayList<>(ops);
            extended.add(op);
            return new ArgTrace(source, callerParamIndex, extended, worse(kind, atLeast));
        }

        /**
         * 合并两个来源：分类取最劣，来源取第一个非 CONSTANT 的，
         * 以便 S3 生成约束时知道该派生值最终依赖哪个 caller 形参。
         */
        ArgTrace merge(ArgTrace other) {
            ProjectionSource mergedSource = this.source;
            int mergedIndex = this.callerParamIndex;
            if (mergedSource == ProjectionSource.CONSTANT && other.source != ProjectionSource.CONSTANT) {
                mergedSource = other.source;
                mergedIndex = other.callerParamIndex;
            }
            List<String> mergedOps = new ArrayList<>(ops);
            mergedOps.addAll(other.ops);
            return new ArgTrace(mergedSource, mergedIndex, mergedOps, worse(kind, other.kind));
        }

        ParamProjection toParamProjection(int calleeArgIndex) {
            ParamProjection projection = new ParamProjection();
            projection.setCalleeArgIndex(calleeArgIndex);
            projection.setSourceKind(source);
            projection.setCallerParamIndex(callerParamIndex);
            projection.setDerivationOps(new ArrayList<>(ops));
            return projection;
        }
    }
}
