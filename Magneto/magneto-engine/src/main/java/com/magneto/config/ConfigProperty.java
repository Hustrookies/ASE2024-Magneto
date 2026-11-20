package com.magneto.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.io.File;

@Component
@ConfigurationProperties(prefix = "config")
public class ConfigProperty {

    private String groundTruthPath = System.getProperty("user.dir") + File.separator + "groundtruth";

    private Integer maxCallChainLength = 10;

    private Integer maxGptRequestLimit = 5;

    private String outputDir = "output";

    private Integer maxPromptScope = 2;

    private Integer maxInterAnalysisScope = 2;

    private Integer maxFuzzChainNumber = 15;

    private String gptModelName = "gpt-4";

    private Long maxFuzzTime = 600000L;

    private Integer maxRetryCount = 3;

    private Boolean enableGpt = true;

    /** SPEC 3.3：off = 基线行为；classify = 只产出 projection.json；full = 跳过 + 注入 + 升级。 */
    private ProjectionMode projectionMode = ProjectionMode.OFF;

    /** SPEC 3.3：R1 透传步骤是否完全免 LLM；false 则仍走一次性 LLM 合成。 */
    private Boolean projectionSkipLlmForPassthrough = true;

    /**
     * SPEC 3.3 任务 5：按复杂度给断点步骤分级 fuzz 预算。默认关闭——
     * S5 的 off/full 对照必须只在「跳过与约束注入」一个变量上有差异，
     * 预算分级会引入第二个变量，让成功率差异无法归因。留给阶段 B 做消融。
     */
    private Boolean projectionGradeFuzzBudget = false;

    /**
     * 是否把投影约束文本注入 LLM prompt。默认开启。
     * 关掉即得到「只跳过、不注入」的消融组，用于把「跳过带来的收益」与
     * 「注入对断点步骤的影响」这两个变量分开——SPEC 5 把「约束注入干扰」
     * 列为需要能回退的风险项，回退手段就是这个开关。
     */
    private Boolean projectionInjectConstraints = true;

    public Boolean getProjectionInjectConstraints() {
        return projectionInjectConstraints;
    }

    public void setProjectionInjectConstraints(Boolean projectionInjectConstraints) {
        this.projectionInjectConstraints = projectionInjectConstraints;
    }

    public Boolean getProjectionGradeFuzzBudget() {
        return projectionGradeFuzzBudget;
    }

    public void setProjectionGradeFuzzBudget(Boolean projectionGradeFuzzBudget) {
        this.projectionGradeFuzzBudget = projectionGradeFuzzBudget;
    }

    public ProjectionMode getProjectionMode() {
        return projectionMode;
    }

    public void setProjectionMode(ProjectionMode projectionMode) {
        this.projectionMode = projectionMode;
    }

    public Boolean getProjectionSkipLlmForPassthrough() {
        return projectionSkipLlmForPassthrough;
    }

    public void setProjectionSkipLlmForPassthrough(Boolean projectionSkipLlmForPassthrough) {
        this.projectionSkipLlmForPassthrough = projectionSkipLlmForPassthrough;
    }

    public String getOutputDir() {
        return outputDir;
    }

    public void setOutputDir(String outputDir) {
        this.outputDir = outputDir;
    }

    public Integer getMaxInterAnalysisScope() {
        return maxInterAnalysisScope;
    }

    public void setMaxInterAnalysisScope(Integer maxInterAnalysisScope) {
        this.maxInterAnalysisScope = maxInterAnalysisScope;
    }

    public Integer getMaxPromptScope() {
        return maxPromptScope;
    }

    public void setMaxPromptScope(Integer maxPromptScope) {
        this.maxPromptScope = maxPromptScope;
    }

    public Integer getMaxFuzzChainNumber() {
        return maxFuzzChainNumber;
    }

    public void setMaxFuzzChainNumber(Integer maxFuzzChainNumber) {
        this.maxFuzzChainNumber = maxFuzzChainNumber;
    }

    public Long getMaxFuzzTime() {
        return maxFuzzTime;
    }

    public void setMaxFuzzTime(Long maxFuzzTime) {
        this.maxFuzzTime = maxFuzzTime;
    }

    public String getGroundTruthPath() {
        return groundTruthPath;
    }

    public void setGroundTruthPath(String groundTruthPath) {
        this.groundTruthPath = groundTruthPath;
    }

    public Integer getMaxCallChainLength() {
        return maxCallChainLength;
    }

    public void setMaxCallChainLength(Integer maxCallChainLength) {
        this.maxCallChainLength = maxCallChainLength;
    }

    public void setGptModelName(String gptModelName) {
        this.gptModelName = gptModelName;
    }

    public String getGptModelName() {
        return gptModelName;
    }

    public Integer getMaxGptRequestLimit() {
        return maxGptRequestLimit;
    }

    public void setMaxGptRequestLimit(Integer maxGptRequestLimit) {
        this.maxGptRequestLimit = maxGptRequestLimit;
    }

    public Integer getMaxRetryCount() {
        return maxRetryCount;
    }

    public void setMaxRetryCount(Integer maxRetryCount) {
        this.maxRetryCount = maxRetryCount;
    }

    public void setEnableGpt(Boolean enableGpt) {
        this.enableGpt = enableGpt;
    }

    public Boolean getEnableGpt() {
        return enableGpt;
    }
}
