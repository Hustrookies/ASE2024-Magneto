package com.magneto.staticanalysis.projection;

import cn.hutool.core.io.FileUtil;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.nio.charset.StandardCharsets;

/**
 * 步骤级埋点落盘：每个 fuzz 步骤一行 JSON，写入 output 目录的 projection-steps.jsonl。
 * S5 的 run_projection_experiment.sh 直接按行汇总。
 */
@Slf4j
public class ProjectionStepLog {

    public static final String FILE_NAME = "projection-steps.jsonl";

    private final File file;

    private final boolean enabled;

    public ProjectionStepLog(File outputDir, boolean enabled) {
        this.enabled = enabled;
        this.file = enabled ? FileUtil.file(outputDir, FILE_NAME) : null;
    }

    public synchronized void append(StepRecord record) {
        if (!enabled) {
            return;
        }
        try {
            FileUtil.appendString(record.toJsonLine() + System.lineSeparator(), file, StandardCharsets.UTF_8);
        } catch (Throwable t) {
            // 埋点失败绝不能影响 fuzz 主流程
            log.warn("ProjectionStepLogWriteError: {}", t.toString());
        }
    }

    public File getFile() {
        return file;
    }
}
