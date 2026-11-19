package com.magneto.staticanalysis.projection.fixture;

/** R4：调用点被条件分支支配，条件依赖字段。实参本身是纯透传——用来验证守卫规则优先于实参分类。 */
public class GuardedCallFixture {

    private boolean enabled;

    public String caller(String a) {
        if (enabled) {
            return callee(a);
        }
        return "skipped";
    }

    public static String callee(String s) {
        return s;
    }
}
