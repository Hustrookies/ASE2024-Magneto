package com.magneto.staticanalysis.projection;

import lombok.Data;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 调用链单步的投影结果（SPEC 3.1）。
 *
 * breakpoint 是权威字段，由 kind 派生。本对象是**静态阶段**产物：projection.json 在 fuzz 之前
 * 就已写盘，因此运行时的升级不写回这里，而记在 StepRecord / projection-steps.jsonl 中。
 * 这样也避免了多个 CVE 共享同一条链的缓存对象时相互污染。
 */
@Data
public class StepProjection {

    /** 对应 reverseChainList 的下标 i，即 caller = get(i)、callee = get(i-1)。 */
    private int stepIndex;

    private String callerSignature;

    private String calleeSignature;

    private ProjectionKind kind = ProjectionKind.UNKNOWN;

    private boolean breakpoint = true;

    /**
     * 调用点是否被条件分支支配（R4）。独立于 kind 保存：接收者规则可能把该步升级成
     * 严重度更高的 COMPLEX_CONSTRUCTION / UNKNOWN，若只靠 kind 判断，可达性义务就会丢失。
     */
    private boolean guarded = false;

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
}
