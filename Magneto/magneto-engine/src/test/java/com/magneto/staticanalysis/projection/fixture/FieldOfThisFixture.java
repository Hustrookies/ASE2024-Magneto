package com.magneto.staticanalysis.projection.fixture;

/** 实参是 this 的字段——正例，应由既有 fixContext 回填，判为简单派生。 */
public class FieldOfThisFixture {

    private String value;

    public String caller() {
        return callee(this.value);
    }

    public static String callee(String s) {
        return s;
    }
}
