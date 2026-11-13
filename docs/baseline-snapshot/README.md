# S0 基线快照

对应 [SPEC.md](../../SPEC.md) S0「基线确认与开发准备」。本目录是 S1/S4 `off` 模式一致性验收的对照物。

## 环境

| 项 | 值 |
|---|---|
| 基线 commit | `8f024c0d` (add: add complexity and branch analyzer) |
| 开发分支 | `projection` |
| JDK | OpenJDK 1.8.0_512 (`/usr/lib/jvm/java-8-openjdk-amd64`) |
| Maven | 3.9.12 |
| 构建命令 | `mvn -B clean package -DskipTests`（于 `Magneto/`）→ BUILD SUCCESS，8m28s |
| 构建警告 | 18 条，全部为既有警告，见 `build-warnings.txt`（S1 验收「零新增警告」的对照） |

JDK/Maven 为本次执行新装（原环境无 Java 工具链）。

## 复现命令

```bash
cd /root/workspace/bishe/ASE2024-Magneto
mkdir -p runs/<name>
cat > runs/<name>/application.properties <<'EOF'
config.ground-truth-path=/root/workspace/bishe/ASE2024-Magneto/Magneto/groundtruth
config.output-dir=output
EOF
cd runs/<name>
java -jar ../../Magneto/magneto-engine/target/magneto-engine-1.0.jar \
  -p ../../Magneto/test-tool-demo -skipFuzz -output "$PWD/output" > run.log 2>&1
```

外置 `application.properties` 覆盖 jar 内 classpath 配置（Spring Boot `file:./` 优先级高于
`classpath:/`），因此**无需改动受版本控制的
`Magneto/magneto-engine/src/main/resources/application.properties`**，也不要把真实 GPT token 写进仓库。

## 运行结果

- 目标项目：`test-tool-demo`（commons-validator 1.6），漏洞 `CVE-2019-10086`
- 退出码 0，`[entire-work]` 38.9s
- `method-call-chain.json`：21 条候选链
- `puring-method-call-chain.json`：6 条精化链，**含 `stepScores` 字段**（用户已有改造）
- `dependency-chain.json`：1 条依赖链

样例（6 条链中第 1 条）：

```json
{
  "chain": [
    "<org.apache.commons.validator.util.ValidatorUtils: java.lang.String getValueAsString(java.lang.Object,java.lang.String)>",
    "<org.apache.commons.beanutils.PropertyUtils: java.lang.Object getProperty(java.lang.Object,java.lang.String)>"
  ],
  "vuls": ["CVE-2019-10086"],
  "stepScores": [
    "caller:<...ValidatorUtils: ...getValueAsString(...)> -> callee:<...PropertyUtils: ...getProperty(...)> | complexity: 34, branch: 1"
  ]
}
```

## 可复现性实测（重要）

同一命令连跑两次（`runs/s0-baseline`、`runs/s0-verify`）后逐文件 diff：

| 文件 | 结果 |
|---|---|
| `dependency-chain.json` | 字节一致 |
| `puring-method-call-chain.json` | 字节一致（含顺序） |
| `method-call-chain.json` | **顺序不同，链集合相同**（两次均 21 条，排序后逐条相等） |

`method-call-chain.json` 的顺序不确定性来自上游链集合的无序遍历，属基线既有行为，与本 SPEC 改造无关。
因此本快照对该文件存的是**排序归一化版本** `output/method-call-chain.normalized.json`。

**S1/S4「`off` 模式与基线一致」的判定标准（据此机械化，不做肉眼 diff）：**

1. `puring-method-call-chain.json` 与快照字节一致；
2. `method-call-chain.json` 排序归一化后与 `method-call-chain.normalized.json` 一致；
3. `dependency-chain.json` 字节一致；
4. 关键日志（`TimeUtil` 阶段行、`has been written` 行、`input args` 行，剥离时间戳与 PID 后）与 `run.key.log` 一致。

用 `python3 docs/baseline-snapshot/compare.py <run-output-dir> <run.log>` 一键核对。

## 完整 fuzz 案例：复用已有结果

S0 要求「1 个真实 CVE 案例完整流程可运行（或已有可复现的运行记录）」。

**未跑实时 fuzz，原因是环境无 GPT access token**（`env` 无相关变量，仓库内亦无 `gpt-cache.json`）。
`GPTSolver.getGPTAnswer()` 在 `enableGpt=false` 时返回 `answer=null`，`validateAnswer(null)` 失败后
`FuzzParser.parseSeed(null, ...)` 得不到种子，fuzz 必然在第一步失败——离线跑不出有意义的完整流程。

按 SPEC 给出的替代路径，复用同 client + 同 CVE 的既有结果作为可复现运行记录：

- `Evaluation_Data/ours-evaluate/commons-validator/CVE-2019-10086/result.json`（2 条成功链）
- `Evaluation_Data/ours-evaluate/commons-validator/CVE-2019-10086/private-result.json`（2 条）
- `Evaluation_Data/gpt-scope-4/commons-validator/CVE-2019-10086/result.json`（2 条）

这些文件记录的链均落在本次 `-skipFuzz` 产出的 21 条候选链内，说明静态分析侧环境与原始实验一致。

**影响面：** S1—S3 为纯静态分析（`classify` 模式），不需要 token，可正常推进。
S4 的「`full` 模式 ≥1 条链端到端」与 S5 的「`off` vs `full` 对照」需要可用 token，进入 S4 前必须解决。
