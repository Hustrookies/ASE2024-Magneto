package com.magneto.staticanalysis.projection.fixture;

/** 实参是「某个形参对象的字段」，不是 this 的字段——回填机制对它没有保证。 */
public class FieldOfParamFixture {

    public static class Holder {
        public String value;
    }

    public static String caller(Holder h) {
        return callee(h.value);
    }

    public static String callee(String s) {
        return s;
    }
}
