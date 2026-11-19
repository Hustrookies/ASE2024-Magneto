package com.magneto.staticanalysis.projection;

import lombok.Data;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 调用链单步的投影结果（SPEC 3.1）。
 *
 * breakpoint 是权威字段：初始由 kind 派生，试运行失败后可被 promoteToBreakpoint() 单独抬升，
 * 此时 kind 保持不变，upgraded 用于在埋点里区分「原生断点」与「运行时升级断点」。
 */
@Data
public class StepProjection {

    /** 对应 reverseChainList 的下标 i，即 caller = get(i)、callee = get(i-1)。 */
    private int stepIndex;

    private String callerSignature;

    private String calleeSignature;

    private ProjectionKind kind = ProjectionKind.UNKNOWN;

    private boolean breakpoint = true;

    private boolean upgraded = false;

    private List<ParamProjection> paramProjections = new ArrayList<>();

    private List<String> projectedConstraints = new ArrayList<>();

    /** taintObjectMap 摘要：callee 实参下标 → caller 侧污点来源描述。 */
    private Map<Integer, List<String>> taintMapping = new LinkedHashMap<>();

    /** 关键 Jimple 语句摘录，S2 分类与 S3 约束的人工核对依据。 */
    private String evidence;

    private Integer complexityScore;

    private Integer branchScore;

    public void setKind(ProjectionKind kind) {
        this.kind = kind;
        this.breakpoint = kind.isBreakpointKind();
    }

    public void promoteToBreakpoint() {
        if (!this.breakpoint) {
            this.breakpoint = true;
            this.upgraded = true;
        }
    }
}
