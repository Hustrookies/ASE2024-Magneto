package com.magneto.staticanalysis.projection.fixture;

/** R2：字符串拼接。Java 8 字节码里是 StringBuilder 链，必须识别为 STR_CONCAT 而非 COMPLEX_CONSTRUCTION。 */
public class ConcatFixture {

    public static String caller(String a) {
        return callee(a + "!");
    }

    public static String callee(String s) {
        return s;
    }
}
