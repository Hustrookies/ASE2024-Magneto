package com.magneto.staticanalysis.projection.fixture;

/** R4：调用点被条件分支支配，条件依赖 caller 形参。 */
public class ParamGuardFixture {

    public static String caller(String a, boolean flag) {
        if (flag) {
            return callee(a);
        }
        return "skipped";
    }

    public static String callee(String s) {
        return s;
    }
}
