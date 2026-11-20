package com.magneto.staticanalysis.projection;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * 埋点落盘。S5 的实验脚本按行读 projection-steps.jsonl 汇总 CSV，
 * 所以「一条记录恰好一行」是硬约束。
 */
public class ProjectionStepLogTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    private StepRecord record(int step) {
        StepRecord r = new StepRecord();
        r.setChainId("chain-0");
        r.setVulName("CVE-2019-10086");
        r.setStep(step);
        r.setKind(ProjectionKind.PASSTHROUGH);
        r.setFuzzSkipped(true);
        r.setTrialResult(true);
        r.setStepTimeMs(100L);
        r.setLlmCalls(0);
        r.setComplexity(34);
        r.setBranch(1);
        return r;
    }

    @Test
    public void appendsExactlyOneLinePerRecord() throws Exception {
        File out = folder.newFolder("output");
        ProjectionStepLog log = new ProjectionStepLog(out, true);

        log.append(record(1));
        log.append(record(2));
        log.append(record(3));

        List<String> lines = Files.readAllLines(new File(out, ProjectionStepLog.FILE_NAME).toPath(),
                StandardCharsets.UTF_8);
        assertEquals(3, lines.size());
        for (String line : lines) {
            assertTrue("每行必须是完整 JSON: " + line, line.startsWith("{") && line.endsWith("}"));
        }
    }

    @Test
    public void writesIntoTheGivenOutputDirectoryUnderTheFixedName() {
        File out = folder.getRoot();

        ProjectionStepLog log = new ProjectionStepLog(out, true);
        log.append(record(1));

        assertEquals(new File(out, "projection-steps.jsonl"), log.getFile());
        assertTrue(log.getFile().exists());
    }

    @Test
    public void aDisabledLogWritesNothingAtAll() {
        File out = folder.getRoot();

        ProjectionStepLog log = new ProjectionStepLog(out, false);
        log.append(record(1));

        assertFalse("off/classify 模式不得产生埋点文件，否则会污染与基线的目录对比",
                new File(out, ProjectionStepLog.FILE_NAME).exists());
    }

    /**
     * 回归测试：StepFuzzRunner 会为每条链构造一次 ProjectionStepLog（它在 CVE 循环内），
     * 若"构造即截断"，后一条链就会擦掉前一条链的全部埋点。实测曾导致 jsonl 只剩最后一条链。
     * 截断必须每个 JVM 运行只发生一次。
     */
    @Test
    public void aSecondLogOnTheSameRunDoesNotWipeTheFirst() throws Exception {
        File out = folder.newFolder("output");

        ProjectionStepLog first = new ProjectionStepLog(out, true);
        first.append(record(1));
        ProjectionStepLog second = new ProjectionStepLog(out, true);
        second.append(record(2));

        List<String> lines = Files.readAllLines(new File(out, ProjectionStepLog.FILE_NAME).toPath(),
                StandardCharsets.UTF_8);
        assertEquals("同一运行内多次构造不得清空已写入的记录", 2, lines.size());
    }

    @Test
    public void laterAppendsDoNotOverwriteEarlierRecords() throws Exception {
        File out = folder.newFolder("output");
        ProjectionStepLog log = new ProjectionStepLog(out, true);

        log.append(record(1));
        log.append(record(7));

        String content = new String(Files.readAllBytes(new File(out, ProjectionStepLog.FILE_NAME).toPath()),
                StandardCharsets.UTF_8);
        assertTrue(content.contains("\"step\":1"));
        assertTrue(content.contains("\"step\":7"));
    }
}
