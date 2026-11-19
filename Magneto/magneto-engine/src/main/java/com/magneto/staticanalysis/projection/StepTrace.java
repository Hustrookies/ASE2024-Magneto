package com.magneto.staticanalysis.projection;

import lombok.Getter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 单个调用点的分类结果（SPEC 3.2）。StepClassifier 的产物，
 * 由 ProjectionAnalyzer 在多调用点间取最劣后写入 StepProjection。
 */
@Getter
public class StepTrace {

    private final ProjectionKind kind;

    private final List<ParamProjection> paramProjections;

    private final String evidence;

    /** 调用点是否被条件分支支配（R4）。 */
    private final boolean guarded;

    public StepTrace(ProjectionKind kind, List<ParamProjection> paramProjections, String evidence, boolean guarded) {
        this.kind = kind;
        this.paramProjections = Collections.unmodifiableList(new ArrayList<>(paramProjections));
        this.evidence = evidence;
        this.guarded = guarded;
    }
}
