package com.magneto.staticanalysis.projection.fixture;

/** 接收者就是 caller 自身：种子本来就构造它，不构成额外障碍。 */
public class ReceiverIsThisFixture {

    public String caller(String a) {
        return this.callee(a);
    }

    public String callee(String s) {
        return s;
    }
}
