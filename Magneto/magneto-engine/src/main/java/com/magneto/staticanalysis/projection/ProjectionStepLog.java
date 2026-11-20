package com.magneto.staticanalysis.projection;

import cn.hutool.core.io.FileUtil;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 步骤级埋点落盘：每个 fuzz 步骤一行 JSON，写入 output 目录的 projection-steps.jsonl。
 * S5 的 run_projection_experiment.sh 直接按行汇总。
 */
@Slf4j
public class ProjectionStepLog {

    public static final String FILE_NAME = "projection-steps.jsonl";

    /**
     * 本次 JVM 运行中已经清空过的文件。StepFuzzRunner 在 CVE 循环内为每条链构造一次本类，
     * 若「构造即截断」，后一条链就会擦掉前一条链的全部埋点（实测曾使 jsonl 只剩最后一条链）。
     * 因此每个文件在一次运行里只清空一次：既避免同目录重跑导致行翻倍，又不丢本轮已写记录。
     */
    private static final Set<File> TRUNCATED_THIS_RUN =
            Collections.newSetFromMap(new ConcurrentHashMap<File, Boolean>());

    private final File file;

    private final boolean enabled;

    public ProjectionStepLog(File outputDir, boolean enabled) {
        this.enabled = enabled;
        this.file = enabled ? FileUtil.file(outputDir, FILE_NAME) : null;
        if (this.file != null && TRUNCATED_THIS_RUN.add(this.file.getAbsoluteFile())) {
            FileUtil.del(this.file);
        }
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
