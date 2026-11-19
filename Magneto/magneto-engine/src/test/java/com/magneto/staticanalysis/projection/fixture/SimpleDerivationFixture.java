package com.magneto.staticanalysis.projection.fixture;

/** R2：def 链含可枚举算子——污点基对象的 getter 与类型转换。 */
public class SimpleDerivationFixture {

    private String name;

    public String getName() {
        return name;
    }

    public String caller(Object raw) {
        return callee(getName(), (String) raw);
    }

    public static String callee(String a, String b) {
        return a + b;
    }
}
