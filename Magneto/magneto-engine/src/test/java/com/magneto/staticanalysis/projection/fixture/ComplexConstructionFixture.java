package com.magneto.staticanalysis.projection.fixture;

import java.util.HashMap;
import java.util.Map;

/** R3：def 链含 NewExpr + 多次写入。 */
public class ComplexConstructionFixture {

    public static String caller(String a) {
        Map<String, String> map = new HashMap<String, String>();
        map.put("k1", a);
        map.put("k2", "v2");
        return callee(map);
    }

    public static String callee(Map<String, String> m) {
        return m.toString();
    }
}
