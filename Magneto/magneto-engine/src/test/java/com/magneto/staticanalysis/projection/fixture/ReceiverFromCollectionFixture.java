package com.magneto.staticanalysis.projection.fixture;

import java.util.List;

/**
 * 复刻 QLExpress OperatorAlias.executeInner 的真实形态：
 * 接收者是 list.get(0) 的返回值，实参却是纯透传的 caller 形参。
 * 只看实参会误判为 PASSTHROUGH。
 */
public class ReceiverFromCollectionFixture {

    public interface Element {
        String callee(String s);
    }

    public static String caller(List<Element> list, String a) {
        return list.get(0).callee(a);
    }
}
