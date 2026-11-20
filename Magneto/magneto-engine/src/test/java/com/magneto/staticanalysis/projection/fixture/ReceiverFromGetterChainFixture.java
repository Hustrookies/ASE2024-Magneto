package com.magneto.staticanalysis.projection.fixture;

/** 接收者是 this 的字段再经一层 getter：比直接字段读多一跳，不确定能否被回填。 */
public class ReceiverFromGetterChainFixture {

    private Holder holder;

    public static class Holder {
        private Target target;

        public Target getTarget() {
            return target;
        }
    }

    public static class Target {
        public String callee(String s) {
            return s;
        }
    }

    public String caller(String a) {
        return this.holder.getTarget().callee(a);
    }
}
