package com.magneto.staticanalysis.projection;

import soot.Body;
import soot.G;
import soot.Scene;
import soot.SootClass;
import soot.Unit;
import soot.jimple.Stmt;
import soot.options.Options;

import java.io.File;

/**
 * 在单测里启动一个最小 Soot 环境，用于分析 src/test/java 下的 fixture 类。
 *
 * 刻意不经过 Spring：分类逻辑（StepClassifier）只吃 Soot 对象，不碰 MethodCall /
 * MavenDependency / ConfigProperty，因此也不需要 TaintFlowAnalysis 那个
 * 依赖 SpringUtil.getBean 的静态初始化。classpath 配置对齐 ProjectCallGraph.preProcess()。
 */
public final class SootFixtureHarness {

    private static final String TEST_CLASSES_DIR = "target/test-classes";

    private static final String RT_JAR = "target/classes/rt.jar";

    private static boolean booted = false;

    private SootFixtureHarness() {
    }

    public static synchronized void boot() {
        if (booted) {
            return;
        }

        File rtJar = new File(RT_JAR);
        if (!rtJar.exists()) {
            throw new IllegalStateException("bundled rt.jar not found at " + rtJar.getAbsolutePath()
                    + " — run `mvn -pl magneto-engine process-resources` first");
        }

        G.reset();
        Options.v().parse(new String[]{
                "-allow-phantom-refs",
                "-keep-line-number", "enabled",
                "-cp", rtJar.getAbsolutePath(),
                "-process-dir", new File(TEST_CLASSES_DIR).getAbsolutePath(),
                "-p", "jb", "use-original-names:true"
        });
        Options.v().set_src_prec(Options.src_prec_only_class);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_app(false);
        Scene.v().loadNecessaryClasses();

        booted = true;
    }

    public static Body bodyOf(Class<?> fixtureClass, String methodName) {
        boot();
        SootClass sootClass = Scene.v().forceResolve(fixtureClass.getName(), SootClass.BODIES);
        sootClass.setApplicationClass();
        return sootClass.getMethodByName(methodName).retrieveActiveBody();
    }

    /** 定位 body 中对 calleeMethodName 的调用点；多个时返回第一个。 */
    public static Unit invokeOf(Body body, String calleeMethodName) {
        for (Unit unit : body.getUnits()) {
            Stmt stmt = (Stmt) unit;
            if (stmt.containsInvokeExpr()
                    && stmt.getInvokeExpr().getMethod().getName().equals(calleeMethodName)) {
                return unit;
            }
        }
        throw new AssertionError("no invocation of " + calleeMethodName
                + " in " + body.getMethod().getSignature());
    }

    public static String jimpleOf(Body body) {
        StringBuilder sb = new StringBuilder();
        for (Unit unit : body.getUnits()) {
            sb.append(unit.toString()).append('\n');
        }
        return sb.toString();
    }
}
