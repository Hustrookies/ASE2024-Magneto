package com.magneto.staticanalysis.projection.fixture;

/** 接收者是 caller 的形参：种子必须额外提供一个已正确初始化的实例。 */
public class ReceiverFromParamFixture {

    public interface Target {
        String callee(String s);
    }

    public static String caller(Target target, String a) {
        return target.callee(a);
    }
}
