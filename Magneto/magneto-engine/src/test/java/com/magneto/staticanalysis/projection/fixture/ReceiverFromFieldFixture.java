package com.magneto.staticanalysis.projection.fixture;

/** 接收者来自字段读：需要先把该字段设置成可用实例。 */
public class ReceiverFromFieldFixture {

    private Helper helper;

    public static class Helper {
        public String callee(String s) {
            return s;
        }
    }

    public String caller(String a) {
        return this.helper.callee(a);
    }
}
