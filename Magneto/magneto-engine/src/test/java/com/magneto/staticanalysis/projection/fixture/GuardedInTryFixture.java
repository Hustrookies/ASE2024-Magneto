package com.magneto.staticanalysis.projection.fixture;

/**
 * 守卫位于 try 块内。用来钉住 BriefUnitGraph 的选择：
 * 正常控制流边足以发现守卫，异常边只会引入并非真正支配调用点的 if。
 */
public class GuardedInTryFixture {

    public static String caller(String a, boolean flag) {
        try {
            if (flag) {
                return callee(a);
            }
        } catch (RuntimeException e) {
            return "err";
        }
        return "none";
    }

    public static String callee(String s) {
        return s;
    }
}
