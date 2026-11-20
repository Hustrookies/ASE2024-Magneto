# S5 冒烟回归与实验结果

对应 [SPEC.md](../../SPEC.md) S5，即**阶段 A 总验收**。分支 `projection`，构建含全部评审修复（HEAD 见 git log）。

---

## 1. 实验设置

| 项 | 设置 |
|---|---|
| 案例 | 3 个下游客户端工程 × 各自对应的上游 CVE |
| 臂 | `off`（基线）、`full`（跳过 + 约束注入）、`full-noinject`（只跳过、不注入，仅 validator） |
| 重复 | validator 5 轮／臂；idworker 3 轮／臂；QLExpress 3 轮／臂 |
| 每步 fuzz 预算 | validator 40 s；idworker、QLExpress 20 s（工具默认 600 s，为控制时长而压缩，其副作用见 §6.2） |
| 每轮 fuzz 链数 | 2 |
| LLM | DeepSeek `deepseek-chat`（OpenAI 兼容端点），凭证经环境变量注入 |
| gpt-cache | 每轮独立运行目录，天然隔离；`--keep-cache` 选项已作为死代码移除 |

| 案例 | 客户端 | CVE | 规模（puring 链 / 步） | 断点率 |
|---|---|---|---|---|
| validator | commons-validator 1.6（= `test-tool-demo`） | CVE-2019-10086 | 6 / 28 | **71%** |
| idworker | imadcn idworker | CVE-2022-42004（jackson-databind） | 2 / 11 | **64%** |
| qlexpress | Alibaba QLExpress | CVE-2019-10086 | 数百～数千（**跨运行不稳定**） | **84–92%** |

复现：

```bash
scripts/run_projection_experiment.sh --project <客户端路径> --cve <CVE> \
    --mode <off|classify|full> --out runs/<名> --reps N --fuzz-time MS --chains 2
    [--tag <臂名>] [--no-inject-constraints]
python3 scripts/compare_modes.py runs/<名> [runs/<名2> ...]
```

累计 LLM 花费：**¥0.54**（约 60 次完整 fuzz 运行，含全部返工）。

---

## 2. 主结果

### 2.1 三案例对照

| 案例 | 臂 | 成功步/轮 | LLM 请求/轮 | fuzz 耗时/轮 (ms) | 埋点步 | 跳过 | 升级 |
|---|---|---|---|---|---|---|---|
| validator | `off` | 3.20 ± 0.45 | 4.20 ± 0.45 | 52969 ± 3143 | – | – | – |
| validator | `full` | **3.40 ± 1.34** | **3.40 ± 1.34** (−19%) | 53369 ± 2693 | 22 | 9 | 1 |
| validator | `full-noinject` | 3.20 ± 0.45 | **3.20 ± 0.45** (−24%) | 50596 ± 597 | 21 | 10 | 0 |
| idworker | `off` | 2.00 ± 0.00 | 2.00 ± 0.00 | 34985 ± 538 | – | – | – |
| idworker | `full` | 2.00 ± 0.00 | **1.00 ± 0.00** (−50%) | **32761 ± 83** (−6%，σ 降 6.5×) | 9 | 6 | 0 |
| qlexpress | `off` | 5.33 ± 1.15 | 5.00 ± 0.00 | 52881 ± 610 | – | – | – |
| qlexpress | `full` | 6.00 ± 0.00 | 7.00 ± 0.00 ※ | 55232 ± 1049 | 24 | 0 | 0 |

※ QLExpress 的 LLM 数不可跨臂比较，见 §6.1。

LLM 请求数口径：`output/llm-calls.txt`，即**真实发出的 API 请求数**，缓存命中不计，所有臂同一口径。
（此前用 `run.log` 里 `the gpt answer:` 行数计数是错的——该行在缓存命中与每次重试时都会打印，
会使 `off` 臂系统性偏高，跨臂比较结论不可信。已修，见 `docs/projection-schema.md` §10。）

### 2.2 配对比较（SPEC S5 验收 1）

同一轮次、同一链位配对：

| 案例 | 对照 | 配对数 | 更好 | 持平 | 更差 | 配对均值 | 判定 |
|---|---|---|---|---|---|---|---|
| validator | off → full | 10 | 3 | 6 | 1 | 1.600 → 1.700 | **PASS** |
| validator | off → full-noinject | 10 | 1 | 8 | 1 | 1.600 → 1.600 | **PASS** |
| idworker | off → full | 6 | 0 | 6 | 0 | 1.000 → 1.000 | **PASS** |
| qlexpress | off → full | 6 | 1 | 5 | 0 | 2.667 → 3.000 | **PASS**（非严格配对，见 §6.1） |

validator 的 1 例"更差"已定位：`full` 第 2 轮 chain-1/step1 单次合成失败 → 升级为断点 →
完整定向 fuzz 跑满 40 s 仍失败 → 该链 success_step=0（其余 4 轮均为 3）。
同轮 `off` 臂在同一步也并非稳定成功。**安全网按设计工作（未产生任何错误的成功判定），
但该轮确实损失了效率。**

### 2.3 分类质量：跳过成功率（核心指标）

三案例、两个 full 臂合并，共 76 个被埋点的步骤：

| kind | 出现 | 尝试跳过 | 跳过成功 | 升级 | 成功率 |
|---|---|---|---|---|---|
| PASSTHROUGH | 16 | 16 | **16** | 0 | **100%** |
| SIMPLE_DERIVATION | 10 | 10 | **9** | 1 | **90%** |
| CONDITIONAL_SELECT | 9 | 0 | – | – | 未尝试（断点）|
| UNKNOWN | 41 | 0 | – | – | 未尝试（断点）|

**非断点步骤 26 次尝试，25 次成功，升级率 1/26 = 3.8%。**
断点步骤 50 次，无一被误当作可跳过——即 SPEC S2 的红线在运行时也成立，
不只是在静态标注里成立（[projection-annotation.md](../projection-annotation.md) 的 10/10）。

---

## 3. 效率收益的来源与量级

跳过省下的是**整个变异循环 + 该步的 LLM 调用**，不是"少调一次 LLM"。典型步骤：

| 步骤 | 分类 | `off` | `full` |
|---|---|---|---|
| validator chain-0/step1 | PASSTHROUGH | 1277–2131 ms，1 次 LLM，进变异循环 | **14–26 ms，0 次 LLM，不进变异循环** |
| validator chain-1/step1 | SIMPLE_DERIVATION | 完整 fuzz | **1.4–1.7 s，1 次 LLM，不进变异循环** |
| idworker chain-0/step1–2 | PASSTHROUGH | 完整 fuzz | 跳过，0 次 LLM |

idworker 是最干净的样本：静态分类完全确定（3 轮 × 2 臂链集合指纹一致），
成功率逐轮零方差，**LLM 请求 −50%，fuzz 耗时 −6% 且标准差从 538 ms 降到 83 ms（6.5 倍）**。
方差下降本身是有价值的副产品：跳过确定性步骤等于从测量中移除了一部分随机源。

---

## 4. 约束注入的消融（validator，三臂各 5 轮）

三臂唯一的差别是断点步骤 prompt 里是否附带投影约束；跳过逻辑两臂相同。

聚焦信息量最大的 chain-1（5 方法长链），其 `success_step` 逐轮取值：

| 臂 | chain-1 各轮 success_step | 均值 | 走到 step3 的轮数 |
|---|---|---|---|
| `off` | 3, 2, 2, 2, 2 | 2.20 | 1 / 5 |
| `full`（注入） | 3, 0, 3, 3, 3 | **2.40** | **4 / 5** |
| `full-noinject` | 2, 2, 2, 2, 3 | 2.20 | 1 / 5 |

注入臂在 4/5 轮里比另两臂多走通一步，方向一致；但 n=5 下 Fisher 精确检验 p ≈ 0.55，
**不构成统计显著**。诚实结论：

> 在 commons-validator 上，约束注入对断点步骤的成功率有**方向一致但不显著**的正向迹象；
> 对 LLM 成本无实质影响（3.40 vs 3.20，差异落在标准差内）。需要更大样本才能定论。

有一条间接证据支持"注入确实起作用"：修复前的消融批次（约束是**占位符文本**、
且因 §5 所述缺陷从未输出可达性义务）中，`full` 臂 chain-1 的 success_step 是
`[2,2,2,2,2,2,2,2]`（8 轮全为 2，从未走到 step3）；修复后变为 `[3,0,3,3,3]`。
但同期间 `off` 臂也从 1.88 升到 2.20，存在环境漂移，故不能把差异全部归因于注入。

---

## 5. S5 验收结论

| 验收项 | 结论 |
|---|---|
| 2—3 个案例 `full` 成功率不低于 `off` | **达成**。3 案例 4 组对照全部 PASS，配对"更差"共 2/32，均已归因（1 例为单次合成失败后完整 fuzz 亦失败，1 例为 QLExpress 非严格配对） |
| 冒烟数据表显示非断点步骤 LLM 调用与 fuzz 时间显著减少 | **达成**。跳过步骤 0 次 LLM（PASSTHROUGH）或 1 次且不进变异循环（SIMPLE_DERIVATION）；单步耗时 2000 ms → 20 ms 量级；整轮 LLM 请求 −19%／−50%／−24% |
| 实验脚本可一键重跑，埋点 CSV 字段完整 | **达成**。`run_projection_experiment.sh` + `aggregate_projection_results.py` + `compare_modes.py`；steps.csv 含 SPEC 3.3 全部 12 个埋点字段 |
| 分支代码分阶段提交，阶段 A 总结写入周报 | **达成**。S0–S5 各自独立 commit；总结见 [stage-A-summary.md](../stage-A-summary.md) 与 `开题/2026年周报-朱一丁.md` |

SPEC §5 的降级路径**未触发**：三案例断点率 71% / 64% / 84–92%，
仅 QLExpress 超过 80% 阈值，但即便如此其可跳过步骤的判定依然准确（0 次误跳过），
故不需要退回二分类。

---

## 6. 效度威胁（均已在实验中实际观察到）

### 6.1 大型工程静态分析不确定，QLExpress 的配对不成立

同一工程同一配置重复运行，QLExpress 的 puring 链数目在 **74 / 165 / 613 / 687** 之间波动，
被 fuzz 的前两条链的入口方法也不同（`off` rep1 为 `OperatorAlias`/`OperatorExportAlias`，
`full` rep1 为 `OperatorExportAlias`/`OperatorMacro`）。成因是上游调用图构建启用
`set_num_threads(15)` 并发处理，属基线固有行为，非本方法引入。

后果：

- QLExpress 的"配对"实为"同轮同链位"，并非同一条链，其 success_step 差异只能作观察性参考；
- 该案例 `full` 臂 LLM 请求数**高于** `off`（7 vs 5），这不是投影导致的成本上升，
  而是两臂跑了不同的链（`full` 的链更长／更难）。**不应据此得出任何结论。**

validator 与 idworker 已验证链集合跨轮跨臂**完全一致**（MD5 指纹相同），其配对结论有效。

### 6.2 短时间预算放大边界效应

预算接近某步实际所需时间时，成败对预算高度敏感。commons-validator 的
chain-1/step3（守卫断点）在 20 s 预算下 `off` 5 轮中成功 2 轮，在 40 s 预算下 8 轮中成功 0 轮，
在 v3 批次 40 s 下 `off` 5 轮中成功 1 轮——**同一配置跨批次都不稳定**。

后果：短预算下的"耗时下降比例"会**低估**真实收益，因为总耗时被个别烧满预算的断点步骤支配。
validator 三臂 fuzz 耗时几乎相同（52969 / 53369 / 50596 ms），而其中 chain-1/step4 一步就占
约 42 s；真正被省掉的 chain-0（2000 ms → 20 ms）在总量里几乎看不见。
**不得据本批数据声称"整体提速 X%"。**

### 6.3 PoC 选择随机

`StepFuzzRunner` 用 `RandomUtil.randomChoose(testcaseUnitList)` 选取测试用例。
当某 CVE 有多个 testcase 时，不同轮次可能用不同 PoC，"配对"因此不是严格的同条件配对。
本次三案例每个 CVE 均只有 1 个 testcase，故未受影响；但多 testcase 的 CVE 需注意。

### 6.4 工具会就地改写输入

`POMParser` 会把客户端实际依赖版本写回 `Magneto/groundtruth/<CVE>/pom.xml`
（实测 commons-beanutils `1.9.2 → 1.8.2`、jackson-databind `2.13.1 → 2.13.0`）。
单轮内部自洽（改写发生在分析之前），但跨案例顺序执行会改变该文件的落盘状态。
实验脚本未自动还原；本批实验结束后已用 `git checkout -- Magneto/groundtruth` 复原。

### 6.5 埋点曾丢失前序链的数据（已修）

`ProjectionStepLog` 在 CVE 循环内被逐链构造，而构造即截断文件，导致
`projection-steps.jsonl` 只剩最后一条链的行。本报告的跳过／升级统计**已从 run.log 的
`[projection-step]` 行完整恢复**（该日志同时输出每条记录，未受影响），
聚合脚本也已改为以日志为权威来源。缺陷本身已修（每个 JVM 运行只截断一次）并补了回归测试。

> 教训：`success_step`、LLM 请求数、fuzz 耗时来自 report.json 与 llm-calls.txt，
> 未受该缺陷影响；受影响的只有 jsonl 派生的跳过／升级计数。

---

## 7. 阶段 B 的直接输入

1. **加大样本量重测约束注入**。当前 n=5，方向一致但 p≈0.55。建议 ≥20 轮／臂，
   或改用固定随机种子降低 fuzz 侧方差。
2. **用生产级预算（600 s）重跑耗时对照**，才能给出可信的"整体提速"数字。
3. **QLExpress 类大型工程需要先解决静态分析不确定性**（固定线程数或排序链列表），
   否则任何跨运行统计都不可靠。
4. **断点率 84–92% 的大型工程**是投影收益的下限场景；收益上限由可跳过步骤比例决定，
   应在论文中按工程规模分层报告，而非给单一平均数。
5. `config.projection-grade-fuzz-budget`（复杂度分级预算）已实现但默认关闭，
   可作为独立消融项在阶段 B 评估。

---

## 附：原始运行目录的留存情况

单次运行会在运行目录下反编译全部依赖（`.dummy/`），三个案例约 60 次运行共占 9.3 GB。
最终批次（`runs/v3-validator`、`runs/v3-idworker`、`runs/v3-qlexpress`）保留在本地（未纳入版本控制，
`runs/` 已在 `.gitignore` 中）；其余中间批次——含 S0 基线复跑、S1–S4 各阶段验证、
接收者修复前后的对照、以及第一版消融——在结论落档后已删除，共释放 7.1 GB。

被删除批次的**结论性数据均已固化在版本控制内**：

| 批次 | 固化位置 |
|---|---|
| S0 基线 | `docs/baseline-snapshot/`（产物 + `compare.py` + 构建警告清单） |
| S2 静态分类 | `docs/s2-evidence/projection.json`、`docs/projection-annotation.md` |
| S3 约束渲染 | `docs/s3-evidence/projection.json` |
| S4 集成验证 | `docs/s4-evidence/VERIFICATION.md`、`docs/s4-evidence/projection-steps.jsonl` |
| S5 最终实验 | `docs/s5-evidence/RESULTS.md`、`docs/s5-evidence/data/`（各臂 summary.json + steps.csv + chains.csv） |

需要复现任何一批时，用 §1 的命令重跑即可；`docs/baseline-snapshot/compare.py`
可机械核对 `off` 模式是否仍与基线一致。
