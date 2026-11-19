package com.magneto.staticanalysis.projection.fixture;

/** R5：接口分发无法解析，保守兜底为 UNKNOWN。 */
public class UnresolvableFixture {

    public interface Provider {
        String provide();
    }

    public static String caller(Provider p) {
        return callee(p.provide());
    }

    public static String callee(String s) {
        return s;
    }
}
