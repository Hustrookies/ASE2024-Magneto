# 阶段 A 总结（11 月）：约束投影分析器与流水线集成

对应 [SPEC.md](../SPEC.md) 与 [11月任务清单与实现方案.md](../../nov26/11月任务清单与实现方案.md) 的 T1（约束投影分析器）+ T2（Magneto 流水线集成）。
分支 `projection`，基线 `8f024c0d`。S0—S5 六个阶段全部按门禁顺序完成并验收。

---

## 1. 做成了什么

在 Magneto（ASE'24，分步 LLM 增强定向模糊测试）之上加了一层**约束投影分析**：
对可达调用链的每个步骤 ⟨caller Fᵢ, callee Fᵢ₋₁⟩，在 Jimple 层溯源 callee 各实参的来源与派生算子，
连同**调用点的接收者**与**可达守卫**一起，把该步归入五类之一；无法确证可跳过的一律判为**投影断点**（关键节点）。
PoC 的触发值随后沿链反向传播，得到每一步的约束。验证阶段据此分派：
非断点步骤只做一次合成 + 一次试运行（透传步骤**完全不调用 LLM**），断点步骤走原有完整定向 fuzz 并注入约束。
试运行失败即升级为断点、回落完整流程。

**核心不变量**：分类只决定"是否搜索"，不决定"是否算成功"——两条路径共用同一个校验谓词。
因此分类误判的最坏后果是多花一次试运行，绝不会产生错误的可利用性结论。

## 2. 交付物

| 类别 | 内容 |
|---|---|
| 代码 | `com.magneto.staticanalysis.projection` 新包 12 个类；`StepFuzzRunner` / `PromptGenerator` / `GPTSolver` / `ConfigProperty` / 报告类改造；4 个配置开关 |
| 测试 | **158 个 JUnit 测试**，16 个 Soot fixture；`mvn -pl magneto-engine test` 全绿 |
| 文档 | [projection-schema.md](projection-schema.md)（输出格式）、[projection-annotation.md](projection-annotation.md)（真实链人工标注）、[baseline-snapshot/](baseline-snapshot/)（基线与复现）、[s4-evidence/](s4-evidence/)、[s5-evidence/RESULTS.md](s5-evidence/RESULTS.md) |
| 脚本 | `run_projection_experiment.sh`（一键实验）、`aggregate_projection_results.py`、`compare_modes.py`、`check_svg_layout.py` |
| 图 | [figures/projection-workflow.svg](figures/projection-workflow.svg)（含 PDF/PNG） |
| 论文 | [../docs/论文章节草稿-约束投影.md](../../docs/论文章节草稿-约束投影.md) §1—§6 |

## 3. 关键结果

**分类准确性**（[projection-annotation.md](projection-annotation.md)）：3 条真实链 10 步人工标注，
断点判定 **10/10 一致**，红线违规 **0 例**；2 处标签偏差均为保守方向。

**运行时可靠性**（3 案例 × 2—3 臂 × 3—5 轮，共 76 个埋点步骤）：

| kind | 尝试跳过 | 成功 | 升级 |
|---|---|---|---|
| PASSTHROUGH | 16 | **16（100%）** | 0 |
| SIMPLE_DERIVATION | 10 | **9（90%）** | 1 |
| 断点（CONDITIONAL_SELECT / UNKNOWN / COMPLEX_CONSTRUCTION） | 0 | – | – |

非断点步骤 **26 次尝试、25 次成功、升级率 3.8%**；断点步骤 50 次无一被误跳过。
唯一一次升级由安全网吸收，未产生错误结论。

**成本与效率**（真实 API 请求数口径，全臂一致）：

| 案例 | LLM 请求 | fuzz 耗时 | 成功步数（配对） |
|---|---|---|---|
| idworker | 2.00 → **1.00**（−50%） | 34985±538 → **32761±83**（σ 降 6.5×） | 6 对全持平 |
| validator | 4.20 → **3.40**（−19%） | 基本持平（见下） | 3 更好 / 6 持平 / 1 更差 |
| qlexpress | 不可比（两臂链不同） | 不可比 | 1 更好 / 5 持平 / 0 更差（非严格配对） |

单步量级上收益极大：validator 的透传步骤 **2000 ms → 20 ms、1 次 LLM → 0 次、不进变异循环**。
整轮耗时之所以看不出同等幅度，是因为个别断点步骤烧满时间预算、独占总时长 80%——
这是短预算实验的伪影，**不能据此声称整体提速比例**（详见 [s5-evidence/RESULTS.md](s5-evidence/RESULTS.md) §6.2）。

**SPEC S5 验收 1**：3 案例 4 组对照全部 PASS。§5 的降级路径未触发（断点率 71%/64%/84–92%）。

**约束注入消融**：注入臂在 chain-1 上 4/5 轮多走通一步（另两臂各 1/5），方向一致但 n=5 下
p≈0.55，**不显著**。如实记为"有正向迹象、证据不足"，已列入阶段 B 首要任务。

## 4. 过程中修掉的实质问题

这些不是风格问题，每一个都会导致错误结论或错误行为：

1. **surefire 静默跑 0 个测试**。`spring-boot-starter-test` 引入 jupiter，surefire 自动选 JUnit Platform
   provider，而测试是 JUnit 4 且无 vintage engine → 报 `Tests run: 0` 后 BUILD SUCCESS。
   仓库原本零测试，所以从未暴露。**若未发现，后续所有 fixture 单测都会全程假绿。**
2. **hutool bean 内省静默丢字段**。`getBreakpointCount()` 无配对 setter，`JSONUtil.parseObj` 直接省略该字段且不报错。
3. **只投影实参、不投影接收者**。QLExpress 的 `list.get(0).getObjectInner(parent)` 实参纯透传，
   接收者却是运行时派生对象 → 判为 PASSTHROUGH → 3 轮里 3 次直接合成全部失败。
4. **接收者修复过宽**。第一版"非 this 即断点"把 idworker 的断点率从 64% 推到 **100%**，
   而该工程 10 次跳过本来全部成功——**把真实收益修没了**。收窄为"静态调用 / this / this 的直接字段读"后恢复。
5. **可达性义务提示从未生效**。`kind` 是多来源取最劣的聚合值，接收者规则的严重度（3/4）
   覆盖了 CONDITIONAL_SELECT（2），而渲染恰按 `kind == CONDITIONAL_SELECT` 判断——
   validator 28 步中 17 步受守卫支配、0 步 kind 为 CONDITIONAL_SELECT，
   **该提示在真实运行中一次都没输出过**，之前那次注入消融因此测的是残缺的 prompt。
6. **实验脚本会伪造 PASS**。凭证检查放过了 `off` 臂；缺 token 时每步 401 失败但 JVM 仍 exit 0，
   `compare_modes.py` 会打出"full 不低于 off"。
7. **LLM 计数两臂口径不同**。`off` 数日志行（含缓存命中与重试），`full` 数真实请求 →
   跨臂比较无意义。改为统一从 `llm-calls.txt` 取真实请求数。
8. **埋点文件被逐链截断**，jsonl 只剩最后一条链（已从 run.log 完整恢复数据并修复）。

## 5. 方法上的收获（对论文写作直接有用）

- **变异测试比"测试全绿"更能说明问题**。共做 9 次故意变异，其中 **2 次首轮未被捕获**，
  各暴露一个真实缺口（"守卫断点+透传实参不得产出值级映射"、"字段基对象未校验"）。
- **单次运行不具判别力**。同一步骤在同一配置下跨轮次可成功可失败；同一 `off` 配置在 20 s 预算下成功、
  60 s 预算下反而失败。所有结论必须基于多轮重复 + 配对 + 报方差。
- **fixture 太干净会掩盖缺陷**。字符串拼接的 StringBuilder 形态、接收者不可合成、守卫覆盖 kind——
  三个真问题全部是在真实链上暴露的，fixture 一个都没碰到。
- **聚合值不能驱动分支逻辑**。凡是"多信号取最劣"的字段，任何依赖其某个具体取值的下游判断都会被更高严重度的信号静默覆盖。

## 6. 已知边界与顺延项

| 项 | 状态 |
|---|---|
| 符号级约束求解 | 顺延至阶段 B（当前为值级投影） |
| 回退到前一断点重调 | 顺延至 12 月 Supervisor 阶段 |
| 三层漏斗第二层（数据流可满足性） | 顺延至 12 月 |
| 阈值 τ 的系统标定 | 阶段 B |
| 复杂度分级 fuzz 预算 | 已实现，默认关闭（会给对照引入第二个变量），留作阶段 B 消融 |
| `projection-conservative` 配置 | **移除**——绑定后无人读取，且其唯一作用是关掉保守红线 |
| 大型工程静态分析不确定性 | 上游固有（并发建图），阶段 B 需先解决才能做跨运行统计 |
| 逐步耗时跨模式对照 | 不做——两臂没有可对齐的逐步计时口径，一律用链级 `fuzzChainTime` |

## 7. 对 11/30 汇报的建议口径

可以主张的：**关键节点识别方法成立**（标注 10/10、运行时 26 次尝试 25 次成功、断点侧零误判），
**成本下降可测**（LLM 请求 −19%～−50%，单步 100× 量级），**成功率不劣于基线**（4 组配对全 PASS），
**可复现性提升**（idworker 耗时标准差降 6.5 倍）。

不要主张的：整体提速百分比（受短预算伪影支配）、约束注入的有效性（n=5 不显著）、
QLExpress 的任何跨臂数值比较（两臂链不同）。
