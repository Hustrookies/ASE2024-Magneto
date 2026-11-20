package com.magneto.staticanalysis.projection.fixture;

/** 接收者在调用点内新建：属于 R3 构造问题。 */
public class ReceiverConstructedFixture {

    public static class Helper {
        private String state;

        public String callee(String s) {
            return state + s;
        }
    }

    public static String caller(String a) {
        return new Helper().callee(a);
    }
}
