package com.magneto.report.json;

import com.alibaba.fastjson2.annotation.JSONField;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Getter
@Setter
public class JSONFuzzStepResult {
    @JSONField(name = "consumeTime")
    private Long consumeTime;

    @JSONField(name = "consumeTimeStr")
    private String consumeTimeStr;

    @JSONField(name = "argsMapList")
    private List<Map<String, String>> argsMapList;

    @JSONField(name = "fieldMap")
    private Map<String, String> fieldMap;

    @JSONField(name = "invokeResultMap")
    private Map<String, String> invokeResultMap;

    // ---- 约束投影埋点（SPEC 3.3）。projection-mode=off 时全部为 null，报告与基线一致 ----

    @JSONField(name = "projectionKind")
    private String projectionKind;

    @JSONField(name = "projectionBreakpoint")
    private Boolean projectionBreakpoint;

    @JSONField(name = "projectionFuzzSkipped")
    private Boolean projectionFuzzSkipped;

    @JSONField(name = "projectionUpgraded")
    private Boolean projectionUpgraded;

    @JSONField(name = "projectionLlmCalls")
    private Integer projectionLlmCalls;
}
