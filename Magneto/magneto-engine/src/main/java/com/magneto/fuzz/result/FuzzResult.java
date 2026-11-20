package com.magneto.fuzz.result;

import com.magneto.fuzz.seed.Seed;

public class FuzzResult {
    private long consumeTime;

    private Seed seed;

    private boolean success;

    private Throwable validateThrow;

    private Object fuzzTargetObj;

    private Object[] fuzzArgs;

    private InvokeMethodResult invokeResult;

    public FuzzResult() {

    }

    public Throwable getValidateThrow() {
        return validateThrow;
    }

    public void setValidateThrow(Throwable validateThrow) {
        this.validateThrow = validateThrow;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public long getConsumeTime() {
        return consumeTime;
    }

    public void setConsumeTime(long consumeTime) {
        this.consumeTime = consumeTime;
    }

    public Object getFuzzTargetObj() {
        return fuzzTargetObj;
    }

    public void setFuzzArgs(Object[] fuzzArgs) {
        this.fuzzArgs = fuzzArgs;
    }

    public Object[] getFuzzArgs() {
        return fuzzArgs;
    }

    public void setFuzzTargetObj(Object fuzzTargetObj) {
        this.fuzzTargetObj = fuzzTargetObj;
    }

    public InvokeMethodResult getInvokeResult() {
        return invokeResult;
    }

    public void setInvokeResult(InvokeMethodResult invokeResult) {
        this.invokeResult = invokeResult;
    }

    public Seed getSeed() {
        return seed;
    }

    public void setSeed(Seed seed) {
        this.seed = seed;
    }

    // ---- 约束投影埋点（SPEC 3.3 报告扩展）。projection-mode=off 时全部为 null ----

    private String projectionKind;

    private Boolean projectionBreakpoint;

    private Boolean projectionFuzzSkipped;

    private Boolean projectionUpgraded;

    private Integer projectionLlmCalls;

    public String getProjectionKind() {
        return projectionKind;
    }

    public void setProjectionKind(String projectionKind) {
        this.projectionKind = projectionKind;
    }

    public Boolean getProjectionBreakpoint() {
        return projectionBreakpoint;
    }

    public void setProjectionBreakpoint(Boolean projectionBreakpoint) {
        this.projectionBreakpoint = projectionBreakpoint;
    }

    public Boolean getProjectionFuzzSkipped() {
        return projectionFuzzSkipped;
    }

    public void setProjectionFuzzSkipped(Boolean projectionFuzzSkipped) {
        this.projectionFuzzSkipped = projectionFuzzSkipped;
    }

    public Boolean getProjectionUpgraded() {
        return projectionUpgraded;
    }

    public void setProjectionUpgraded(Boolean projectionUpgraded) {
        this.projectionUpgraded = projectionUpgraded;
    }

    public Integer getProjectionLlmCalls() {
        return projectionLlmCalls;
    }

    public void setProjectionLlmCalls(Integer projectionLlmCalls) {
        this.projectionLlmCalls = projectionLlmCalls;
    }
}
