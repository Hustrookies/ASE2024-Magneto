# SPEC：约束投影分析器与流水线集成（11 月阶段 A）

> 对应计划：[11月任务清单与实现方案.md](../11月任务清单与实现方案.md) T1（约束投影分析器）+ T2（Magneto 流水线集成）
>
> 工程：`ASE2024-Magneto/Magneto`（Java 8 + Soot + Spring Boot，基线 commit `8f024c0d`）
>
> 状态：**阶段 A 完成**（S0—S5 全部验收通过，含 1 项附加消融未达显著、1 项默认关闭，均如实记录于 S5）。
> 验收证据：[docs/baseline-snapshot/](docs/baseline-snapshot/)（S0）、[docs/projection-annotation.md](docs/projection-annotation.md)（S2）、
> [docs/projection-schema.md](docs/projection-schema.md)（S3）、[docs/s4-evidence/](docs/s4-evidence/)（S4）、
> [docs/s5-evidence/RESULTS.md](docs/s5-evidence/RESULTS.md)（S5 实验结果与效度威胁）、
> [docs/stage-A-summary.md](docs/stage-A-summary.md)（阶段总结）

---

## 1. 目标与非目标

**目标（阶段 A，11/14—11/19）：**
1. 实现 `ProjectionAnalyzer`：对调用链每个步骤 ⟨caller Fᵢ, callee Fᵢ₋₁⟩ 做参数关联四分类（透传 / 简单派生 / 复杂构造 / 条件选择），输出断点集合 K 与投影约束 `projection.json`；
2. 集成进 `StepFuzzRunner` 分步循环：非断点步骤跳过定向 fuzz（直接合成种子 + 单次试运行），失败自动升级为断点；断点步骤将投影约束注入 LLM 提示；
3. 全程受配置开关控制，`off` 模式行为与基线完全一致（可对照实验）。

**非目标（明确顺延，阶段 A 不做）：**
- 回退到前一断点重调（12 月 Supervisor 阶段）；
- Experience Store / 历史脆弱分数 / 自净化（12 月）；
- 符号级约束求解（阶段 A 做**值级投影**：直接映射 PoC/上下文的具体值，符号约束表达顺延）；
- 三层漏斗第二层（12 月）；
- 阈值 τ 的系统标定实验（阶段 B）。

---

## 2. 代码地图（已勘察）

| 组件 | 位置 | 与本 SPEC 的关系 |
|---|---|---|
| 主流程编排 | `Magneto.java` `work()` L280–333；`fuzzVulCallChain()` L237–264 | 静态分析产物在此输出；投影分析可挂在 `outputStaticAnalysisResult` 之后 |
| **分步 fuzz 循环（核心改造点）** | `fuzz/runner/StepFuzzRunner.fuzzCallChain()` L69–175，步骤循环 L110–166 | `reverseChainList()` 后 index 0 = 漏洞函数 F₀；每步 `targetMethodCall=get(i)`（caller Fᵢ）、`triggeredMethodCall=get(i-1)`（callee Fᵢ₋₁）；L136–144 为重试循环（`maxRetryCount=3`） |
| 单步 fuzz 实现 | `StepFuzzRunner.fuzzing()` L183–265 | LLM 生成种子 → `fixAndConnectContext` → `SeedQueue` 变异循环（`maxFuzzTime=600s`）→ `invokeMethod` → `validateInvokeResult` → 成功则上下文向上传播 |
| 单步污点分析（**投影底座**） | `StepFuzzRunner.analysisMethodCallStep()` L800–837 | 产出 `FuzzAnalysis`：`taintObjectMap`（callee 实参 idx → caller 侧 TaintParam/TaintField 集合）即现成的参数映射 |
| 参数映射分析 | `staticanalysis/dataflow/MethodParameterMappingAnalysis.java`（349 行） | 从调用点对实参做后向 BFS 污点回溯（`intraTaintAnalysis`，深度 `maxInterAnalysisScope=2`） |
| 控制流污点分析 | `staticanalysis/dataflow/ControlFlowVariableAnalysis.java`（283 行） | 分支条件涉及的污点变量 → "条件选择"分类的依据 |
| 污点分析基类 | `staticanalysis/taint/TaintFlowAnalysis.java` L68–94 | `findTriggeredMethodUnit()` 调用点定位（支持多调用点），直接复用 |
| LLM 提示生成（**约束注入点**） | `gpt/PromptGenerator.java` `generate()` L49–83；模板 `resources/analysis_code_template.txt` | 提示 = 裁剪后反编译源码 + 模板；投影约束以附加段落注入 |
| LLM 调用与缓存 | `gpt/GPTSolver.getGPTAnswer()` L38 | 有 prompt→answer 缓存（`gpt-cache.json`），对照实验需清缓存或区分 key |
| 上下文（PoC 值来源） | `fuzz/context/FuzzContext.java` L38（由 `TestcaseUnit` 构造）、`getLatestContext()` L111 | 初始 Context 携带 PoC 参数值；`Context.getParamsValue()` 供值级投影 |
| 种子修复回填 | `StepFuzzRunner.fixContext()` L272 起 | 已按 `locateParamPos` 映射用上一步上下文回填 NULL 参数——直接合成种子可复用同一机制 |
| 已有用户改造 | `MethodCallChain.StepScore/calculateStepScores()` L99–130；`ComplexityAnalyzer`（45 行）；`BranchAnalyzer`（50 行）；报告接线 `JSONReportGenerator` L74、`JsonOutputHandler` L79 | 评分作为断点兜底与 fuzz 预算分级；报告管线可沿用扩展 |
| 配置 | `config/ConfigProperty.java` + `application.properties` | 新增 `projection-mode` 等配置项 |
| PoC 与实验数据 | `Magneto/groundtruth/`（CVE 测试用例）、`Evaluation_Data/gpt-scope-4/<client>/<CVE>/` | S2/S5 验收用真实链与回归样本 |

---

## 3. 总体设计

### 3.1 数据模型（新增 `staticanalysis/projection/` 包）

```java
enum ProjectionKind { PASSTHROUGH, SIMPLE_DERIVATION, COMPLEX_CONSTRUCTION, CONDITIONAL_SELECT, UNKNOWN }

class ParamProjection {          // 单个 callee 实参的溯源结果
    int calleeArgIndex;
    String sourceKind;           // CALLER_PARAM / CALLER_FIELD / CONSTANT / NEW_OBJECT / UNRESOLVED
    int callerParamIndex;        // sourceKind=CALLER_PARAM 时有效
    List<String> derivationOps;  // 派生算子链: GET_FIELD(getX) / STR_CONCAT / CAST / WRAP ...
}

class StepProjection {
    int stepIndex;                        // 对应 reverseChainList 的 i
    String callerSignature, calleeSignature;
    ProjectionKind kind;
    boolean breakpoint;                   // kind ∈ {COMPLEX_CONSTRUCTION, CONDITIONAL_SELECT, UNKNOWN}
    List<ParamProjection> paramProjections;
    List<String> projectedConstraints;    // 注入提示/合成种子用的约束描述
    String evidence;                      // 关键 Jimple 语句摘录
    Integer complexityScore, branchScore; // 融合已有分析器
}

class ChainProjection {          // 一条链的完整投影结果，序列化即 projection.json
    String chainId; List<StepProjection> steps; int breakpointCount;
}
```

**断点判定：** `breakpoint = kind ∈ {COMPLEX_CONSTRUCTION, CONDITIONAL_SELECT, UNKNOWN}`；保守规则——溯源深度超限（`maxInterAnalysisScope`）、接口分发无法解析、多调用点中任一为断点 → 整步记 UNKNOWN/断点。**宁可多验证，不可漏验证。**

### 3.2 四分类规则（Jimple 级，自调用点向后溯源实参 def 链）

| 规则 | 判定特征 | 分类 | 投影动作 |
|---|---|---|---|
| R1 | 实参 local 的 def 链只经 `IdentityStmt`（`r@parameterN`）与局部拷贝 | PASSTHROUGH | caller 形参 N 的值 = callee 实参的上下文值（值级直接映射，**无需 LLM**） |
| R2 | def 链含可枚举算子：污点基对象的字段读/getter、字符串拼接、基本类型转换/装箱、单层集合包装 | SIMPLE_DERIVATION | 记录算子链，约束转写（"caller 形参 N 的 getX() 须返回 …"），LLM 一次性合成 |
| R3 | def 链含 `NewExpr` + 多次字段写/setter、builder 链、循环/数组填充 | COMPLEX_CONSTRUCTION | **断点**；投影约束作为"构造目标"注入提示 |
| R4 | 调用点被条件分支支配且条件依赖非形参污点值，或实参在不同分支有多定义点 | CONDITIONAL_SELECT | **断点**；记录分支条件 |
| R5 | 深度超限 / 无法解析 / 异常 | UNKNOWN | **断点**（保守兜底） |

### 3.3 集成方式（`StepFuzzRunner.fuzzCallChain` 步骤循环内）

```
链级预分析：ChainProjectionService.analyze(chain) → List<StepProjection>（每链一次，缓存）

for 每个步骤 i（现有循环 L110）:
    p = projections[i]
    if (projectionMode == FULL && !p.breakpoint):
        seed = 直接合成(p, latestContext)      // R1: 值映射回填（复用 fixContext 机制）
                                                 // R2: GPTSolver 单次调用（约束注入提示，不进重试循环）
        result = invokeMethod(seed) + validateInvokeResult   // 单次试运行
        if 成功: 上下文传播（addNewContext），记 fuzz_skipped=true，continue
        else:    promotedSteps.add(i)（按 CVE 独立，不改写共享缓存对象），记 upgraded=true，落入下方完整流程
    // 断点步骤（= 原流程 + 约束注入）:
    PromptGenerator 附加约束段落——用 Context 的真实值经 renderWithRuntimeValues 重新渲染，
    而非 projection.json 里那份静态占位文本
    analysisMethodCallStep → preCheck → fuzzing(...)   // 原逻辑不动
    复杂度分数分级 fuzz 时间预算（高分断点给满 maxFuzzTime，低分给 1/2）
```

**配置开关（`ConfigProperty` 新增）：**

| 配置项 | 取值 | 语义 |
|---|---|---|
| `config.projection-mode` | `off` / `classify` / `full` | off=基线行为；classify=只计算并输出 projection.json，不改 fuzz 行为；full=跳过+注入+升级 |
| ~~`config.projection-conservative`~~ | ~~true/false~~ | **实现时移除**。原意是控制「UNKNOWN 是否一律断点」，但 UNKNOWN→断点正是本方法的保守性红线（§3.2 R5），一个只能让工具变得不安全的开关不是有效的消融项；保留一个绑定后无人读取的死配置更糟。 |
| `config.projection-skip-llm-for-passthrough` | true/false（默认 true） | R1 步骤是否完全免 LLM（false 则仍走一次性 LLM 合成） |
| `config.projection-inject-constraints` | true/false（默认 true） | **新增**（超出原 SPEC）。关掉即「只跳过、不注入」，用于把跳过收益与注入影响这两个变量分开；也是 §5「约束注入干扰」的实际回退手段——原 SPEC 写的回退项 `projection-skip-llm-for-passthrough` 管的是 R1 免 LLM，管不到注入。 |
| `config.projection-grade-fuzz-budget` | true/false（默认 **false**） | §3.3 任务 5 的复杂度分级预算。已实现但默认关闭：开启会给 off/full 对照引入第二个变量，使成功率差异无法归因到投影本身（§5 也已把它列为可砍项）。留给阶段 B 做消融。 |
| `-Dmagneto.llm.calls.metric=true` | JVM 系统属性 | **新增**。把真实 LLM API 请求数写入 `output/llm-calls.txt`。默认不写，保证 off 模式产物与基线一致。 |

**日志埋点（每步骤一行 JSON，供阶段 B 实验直接汇总）：**
`{chain_id, vul_name, step, kind, breakpoint, fuzz_skipped, trial_result, upgraded, step_time_ms, llm_calls, complexity, branch}`

**报告扩展：** `JSONFuzzStepResult` 增加上述字段；`projection.json` 经 `JsonOutputHandler` 输出到 output 目录（沿用 StepScore 的接线方式）。

---

## 4. 阶段划分与验收标准（阶段门禁）

> 门禁规则：每阶段完成后产出**验收证据**（产物 + 勾选清单），由朱一丁确认通过后才能开始下一阶段；S2、S4 建议同步导师抽查。任何阶段验收失败，修复后重新验收，不得带病推进。

### S0 基线确认与开发准备（11/14 上午，~0.5 天）

**任务：**
1. 从 `8f024c0d` 拉 `projection` 分支；
2. `mvn clean package` 构建通过；配置 `application.properties`（gpt token、ground-truth-path）；
3. 跑通基线：`test-tool-demo` 上 `-skipFuzz` 输出调用链 JSON（含已有 stepScores 字段）；再选 1 个 `Evaluation_Data` 中的 CVE 案例跑完整 fuzz（或复用已有结果），确认环境可用；
4. 记录基线行为快照（输出文件清单 + 关键日志），作为 S4 `off` 模式一致性对照。

**验收标准：**
- [x] `projection` 分支创建，构建零错误；
- [x] demo 项目 `-skipFuzz` 产出 `puring-method-call-chain.json` 且含 stepScores；
- [x] 1 个真实 CVE 案例完整流程可运行（或已有可复现的运行记录）；*按「复用已有结果」路径达成，见 [docs/baseline-snapshot/README.md](docs/baseline-snapshot/README.md)——环境无 GPT token，实时 fuzz 顺延至 S4 前解决*
- [x] 基线快照存档至 `docs/baseline-snapshot/`。

### S1 数据模型与分析器骨架（11/14 下午—11/15，~1 天）

**任务：**
1. 新建 `staticanalysis/projection/` 包：`ProjectionKind`、`ParamProjection`、`StepProjection`、`ChainProjection`、`ProjectionAnalyzer`（骨架）、`ChainProjectionService`；
2. `ProjectionAnalyzer` 复用 `TaintFlowAnalysis.findTriggeredMethodUnit` 定位调用点，内部调用现有 `MethodParameterMappingAnalysis` 与 `ControlFlowVariableAnalysis` 取 `taintObjectMap` / 控制流污点；
3. 骨架阶段所有步骤分类恒为 `UNKNOWN`（全断点），但完整走通"链 → 逐步骤 → StepProjection 列表 → JSON 序列化"；
4. `JsonOutputHandler` 增加 `projection.json` 输出；`ConfigProperty` 增加三个配置项。

**验收标准：**
- [x] `classify` 模式下 demo 项目运行产出 `projection.json`，步骤数 = 链长-1，字段齐全；*6 条链全部满足（1/4/4/5/7/7 步 = 链长-1），12 个字段恒定输出*
- [x] 每步骤含 `taintObjectMap` 摘要（callee 实参 → caller 形参映射，可为空集）与 complexity/branch 分数；*28 步中空集 0 步，77 个实参中 68 个有映射（88%）——SPEC §5「映射空集比例过高」风险未触发*
- [x] `off` 模式行为与 S0 基线快照一致（diff 日志无差异）；*`compare.py` exit=0，四项全 PASS*
- [x] 编译零警告新增，单测骨架（JUnit）可运行。*警告 18=18 与基线逐行一致；45 个单测全绿*

### S2 四分类判定实现（11/16—11/17，~1.5 天）

**任务：**
1. 实现实参 def 链后向溯源（BFS，深度上限 `maxInterAnalysisScope`），按 R1—R5 规则分类；多调用点取最劣；
2. 编写 4 个手工 fixture（`src/test/java` 下的小型 Java 类，各覆盖 R1—R4 一类）+ 对应 JUnit 断言；
3. 在 `Evaluation_Data` 真实链上标注 ≥3 条链的人工期望分类（至少含：1 条纯透传链、1 条含复杂构造链、1 条含分支调用链），与工具输出比对。

**验收标准：**
- [x] fixture 单测全绿（R1—R4 各至少 1 个用例，含负例：UNKNOWN 兜底）；*8 个 fixture + 21 个断言全绿；4 次变异测试（强制 PASSTHROUGH / 去掉 StringBuilder 特例 / 去掉守卫升级 / 深度耗尽改 PASSTHROUGH）均被捕获，证明非空过*
- [x] ≥3 条真实链分类与人工标注一致率 100%（保守规则允许把 SIMPLE_DERIVATION 判成 UNKNOWN，不允许反向错判——即**不允许把断点判成非断点**）；*标注 chain-0（纯透传）/ chain-2（含分支）/ chain-3（含复杂构造）共 10 步，断点判定 10/10 一致，红线违规 0 例，详见 [docs/projection-annotation.md](docs/projection-annotation.md)*
- [x] 分类结果写入 `projection.json` 且 evidence 字段含关键 Jimple 语句。

**实测补充：** 全量 28 步断点率 71%（PASSTHROUGH 1 / SIMPLE_DERIVATION 7 / CONDITIONAL_SELECT 7 / COMPLEX_CONSTRUCTION 3 / UNKNOWN 10），低于 §5 的 80% 降级阈值，无需退回二分类。UNKNOWN 的 10 例去重后 4 种原因，全部为合法 R5（接口分发 `Map.get`、任意方法返回值、深度耗尽）。

### S3 值级投影与约束生成（11/17—11/18，~1 天）

**任务：**
1. R1 值级投影：由 `taintObjectMap` 生成 caller 形参 ← 上下文/PoC 值的直接映射描述；
2. R2 约束转写：算子链 → 自然语言约束（"形参 N 经 getX() 后须等于 V"）；
3. 断点步骤：生成"构造目标"约束段落（该实参须满足什么，来自下层投影上来的要求）；
4. `projectedConstraints` 填充并序列化；在 demo + 1 条真实链上人工核对约束语义正确性。

**验收标准：**
- [x] ≥1 条透传链的投影约束与 PoC（groundtruth testcase）参数值人工核对一致；*chain-0（`ValidatorUtils.getValueAsString` → `PropertyUtils.getProperty`）喂入 CVE-2019-10086 PoC 的实际值后，形参 1 精确解析为 `"class"`、形参 0 解析为新建 Object，机械核对见 `PocProjectionVerificationTest`*
- [x] ≥1 条含断点链的"构造目标"约束明确指向正确实参与条件；*chain-3/step4（CONDITIONAL_SELECT）四个实参分别指向 caller param 3/1/4 与接收者对象，并附 REACHABILITY OBLIGATION 行*
- [x] `projection.json` schema 文档化（字段说明写入 `docs/projection-schema.md`）。

### S4 流水线集成（11/18—11/19，~1 天）

**任务：**
1. `ChainProjectionService` 接入 `StepFuzzRunner.fuzzCallChain`（链级预分析 + 缓存）；
2. `full` 模式步骤循环改造（§3.3 伪代码）：非断点直接合成（R1 复用 `fixContext` 回填机制免 LLM；R2 走 `GPTSolver` 单次调用，约束经 `PromptGenerator` 注入）+ 单次试运行 + 失败升级；
3. 断点步骤约束注入：`PromptGenerator.generate` 增加约束附加段（注意 `GPTSolver` 缓存 key 会随 prompt 变化，符合预期）；
4. 埋点日志 + `JSONFuzzStepResult` 字段扩展；
5. 复杂度分数分级 fuzz 预算（低分断点 `maxFuzzTime/2`）。

**验收标准：**
- [x] `classify` 模式：fuzz 行为与 `off` 完全一致（日志 diff），仅多 projection.json；*比日志 diff 更硬的证据：两次运行发给 LLM 的 4 个 prompt **逐字节相同**（gpt-cache.json 的 prompt 集合相等）；结构性 fuzz 日志逐行一致，classify 仅多 9 行静态阶段投影日志；report.json 的 successStep / 字段集完全一致*
- [x] `full` 模式：≥1 条链端到端完成，日志可见 `fuzz_skipped=true` 的步骤且该步未进入变异循环；*chain-0 端到端完成：`fuzz_skipped=true, llm_calls=0, step_time_ms=19`，`[ context propagation fuzzing start... ]` 出现 **0 次**；对照 off 模式同链 2065ms，**约 90× 提速且零 LLM 调用**，successStep 相同*
- [x] 构造一个必然试运行失败的场景（fixture），验证 `upgraded=true` 后走完整 fuzz 流程；*用故障注入（临时令 `trySingleShotSynthesis` 恒返回 null，验证后已还原并复跑确认）：埋点输出 `kind=PASSTHROUGH, breakpoint=true, upgraded=true, fuzz_skipped=false, llm_calls=1`，变异循环启动 1 次——即静态判定被保留、断点被抬升、完整流程确实接管*
- [x] `off` 模式回归：S0 基线快照复跑一致。*`compare.py` exit=0 四项全 PASS；且 off 模式不产生 projection.json / projection-steps.jsonl，report.json 步骤字段集与改动前完全一致（无新增 null 字段）*

### S5 冒烟回归与实验就绪（11/19，~0.5 天）

**任务：**
1. 选 2—3 个 `Evaluation_Data` 中有基线结果的 CVE 案例，`off` vs `full` 各跑一轮；
2. 编写 `scripts/run_projection_experiment.sh`（参数：项目路径、CVE、模式、输出目录；自动清 gpt-cache、收集埋点日志、汇总步骤级 CSV）；
3. 汇总冒烟数据：断点率、跳过步骤数、LLM 调用数、每步耗时、成功/失败与基线对照。

**验收标准（= 阶段 A 总验收，进入阶段 B 的入口条件）：**
- [x] 2—3 个案例 `full` 模式成功率不低于 `off`（若有下降，逐条归因：误判透传 → 修 S2 规则；约束注入干扰 → 回退 `projection-skip-llm-for-passthrough` 配置）；*3 案例 4 组配对对照全部 PASS（validator 3好/6平/1差、validator-noinject 1/8/1、idworker 0/6/0、qlexpress 1/5/0）。两处"更差"均已归因：1 例为单次合成失败后完整 fuzz 亦失败（安全网未产生错误判定），1 例源于 QLExpress 静态分析不确定导致两臂链不同。另：S5 过程中确实发现并修正了一处"误判透传"（接收者未投影），见 `docs/projection-annotation.md` 补记*
- [x] 冒烟数据表显示非断点步骤 LLM 调用与 fuzz 时间显著减少（记录具体数字，作为 11 月汇报初步证据）；*非断点步骤 26 次尝试 25 次成功（PASSTHROUGH 16/16、SIMPLE_DERIVATION 9/10），升级率 3.8%；断点侧 50 次零误跳过。真实 LLM 请求数 idworker −50%、validator −19%；单步量级 2000ms→20ms、1 次 LLM→0 次、不进变异循环。整轮耗时未同比例下降的原因（短预算伪影）见 `docs/s5-evidence/RESULTS.md` §6.2*
- [x] 实验脚本可一键重跑，埋点 CSV 字段完整；*`run_projection_experiment.sh` + `aggregate_projection_results.py` + `compare_modes.py`；steps.csv 含 SPEC 3.3 全部 12 个埋点字段*
- [x] `projection` 分支代码提交（分阶段 commit，message 规范），阶段 A 总结写入周报。*S0—S5 各自独立 commit；总结见 `docs/stage-A-summary.md` 与 `开题/2026年周报-朱一丁.md` 的 2026.11.14-2026.11.21 条目*

**未达成的附加项（如实记录）：**
- 约束注入的消融方向为正但**不显著**（chain-1 上 4/5 对 1/5 对 1/5，n=5，Fisher p≈0.55）。只能主张"有正向迹象、证据不足"，需 ≥20 轮／臂重测。
- 复杂度分级 fuzz 预算（任务 5）已实现但默认关闭，未按 SPEC 原文默认启用——开启会给 off/full 对照引入第二个变量。留作阶段 B 消融。
- QLExpress 的跨臂数值不可比（两臂实际模糊测试的是不同链），根因是上游并发建图导致的静态分析不确定性，非本方法引入。

---

## 5. 风险与降级路径

| 风险 | 触发信号 | 降级 |
|---|---|---|
| Soot def 链溯源在真实代码上大量 UNKNOWN | S2 真实链断点率 >80% | 收紧为二分类"透传 vs 其他"（只实现 R1+R5），仍可支撑实验（断点率上升但成功率安全） |
| `taintObjectMap` 精度不足（深度 2 限制） | S1 映射空集比例过高 | 临时调 `maxInterAnalysisScope=3` 评估耗时；或仅对映射非空的实参做投影 |
| 直接合成种子成功率低 | S4 试运行大量失败升级 | 保留升级机制兜底（正确性不受损，效率收益减少）；R2 改为全部走 LLM 单次合成 |
| 约束注入干扰断点步骤 | full 的断点步骤成功率低于 off | 关 `config.projection-inject-constraints` 得到「只跳过、不注入」臂，用三臂对照分离两个变量（原写的回退项 `projection-skip-llm-for-passthrough` 管不到注入） |
| GPT 缓存污染对照实验 | off/full 结果异常一致 | 实验脚本强制清 `gpt-cache.json` 并分目录隔离输出 |
| 时间不够（17 天总盘子） | S3 结束仍晚于 11/18 | S4 砍掉"复杂度分级预算"（纯装饰项），保跳过+升级主链路 |

## 6. 交付物清单（阶段 A 汇总）

1. `projection` 分支代码（新增 `staticanalysis/projection/` 包 ≈600—900 行 + `StepFuzzRunner`/`PromptGenerator`/报告类改造）；
2. `projection.json` schema 文档（`docs/projection-schema.md`）；
3. fixture 单测 + 真实链标注记录（S2 验收件）；
4. `scripts/run_projection_experiment.sh` + 冒烟数据 CSV；
5. 阶段 A 总结（进周报，作为 11/30 汇报 T1/T2 达成证据）。
