package com.magneto.staticanalysis.projection.fixture;

/** R1：实参 def 链只经 IdentityStmt 与局部拷贝。 */
public class PassthroughFixture {

    public static String caller(String value, int count) {
        return callee(value, count);
    }

    public static String callee(String s, int n) {
        return s + n;
    }
}
