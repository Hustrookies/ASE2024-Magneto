package com.magneto.staticanalysis.projection.fixture;

/** R4：实参在不同分支有多定义点。 */
public class ConditionalSelectFixture {

    public static String caller(String a, boolean flag) {
        String chosen;
        if (flag) {
            chosen = a;
        } else {
            chosen = "literal";
        }
        return callee(chosen);
    }

    public static String callee(String s) {
        return s;
    }
}
