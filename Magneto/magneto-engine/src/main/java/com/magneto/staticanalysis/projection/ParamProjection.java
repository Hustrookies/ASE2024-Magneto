package com.magneto.staticanalysis.projection;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * 单个 callee 实参的溯源结果（SPEC 3.1）。
 */
@Data
public class ParamProjection {

    private int calleeArgIndex;

    private ProjectionSource sourceKind = ProjectionSource.UNRESOLVED;

    /** 仅当 sourceKind = CALLER_PARAM 时有效，否则为 -1。 */
    private int callerParamIndex = -1;

    /** 派生算子链，如 GET_FIELD(getX) / STR_CONCAT / CAST / WRAP。 */
    private List<String> derivationOps = new ArrayList<>();
}
