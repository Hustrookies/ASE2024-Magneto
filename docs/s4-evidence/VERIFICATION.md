# S4 流水线集成验收证据

对应 [SPEC.md](../../SPEC.md) S4。分支 `projection`，工程 `Magneto`。

## 运行配置

所有 fuzz 运行都做了限界，以便快速、低成本地反复验证：

```properties
config.max-fuzz-chain-number=2     # 只 fuzz 前 2 条链
config.max-fuzz-time=20000         # 每步变异循环 20s（生产默认 600000）
config.max-retry-count=1
config.gpt-model-name=deepseek-chat
```

LLM 凭证经环境变量注入（`MAGNETO_GPT_TOKEN` / `MAGNETO_GPT_ENDPOINT`），不写入仓库。
复现方式见 [docs/baseline-snapshot/README.md](../baseline-snapshot/README.md) 的运行命令，去掉 `-skipFuzz` 即可。

---

## 验收 1：`classify` 模式 fuzz 行为与 `off` 完全一致

比「日志 diff」更硬的证据是**比对发给 LLM 的 prompt 本身**。`classify` 模式下
`projectionActive` 为 false，传给 `fuzzing()` 的约束是 `null`，因此 prompt 不应有任何变化。

从两次运行的 `output/gpt-cache.json` 取出全部 prompt，排序后求 SHA256：

| 模式 | prompt 数 | 各 prompt 长度 | prompt 集合 SHA256（前 32 位） |
|---|---|---|---|
| `off` | 4 | 3494, 3733, 4046, 5327 | `0843aa3ce0298bc95b4660f8e5a6869f` |
| `classify` | 4 | 3494, 3733, 4046, 5327 | `0843aa3ce0298bc95b4660f8e5a6869f` |

**逐字节相同。**

辅助证据：

- 结构性 fuzz 日志（`fuzzing ]` / `context propagation fuzzing start|end` / `success trigger` /
  `fuzzing stop on` / `begin to fuzzing`，剥离时间戳与 PID）逐行一致；`classify` 只多 9 行，
  全部来自静态分析阶段的 `generate-constraint-projection`，fuzz 循环内零差异。
- `report.json` 的 `successStep` 与 `fuzzChainTime` 量级一致；步骤字段集两者均为原有 5 个字段，
  `classify` 未引入任何新字段。
- 产物差异仅为 `classify` 多出 `projection.json`。

## 验收 2：`full` 模式端到端 + `fuzz_skipped=true` 的步骤未进入变异循环

`runs/s4c-full` 的 `projection-steps.jsonl`（已存档为本目录同名文件）：

| chain/step | kind | breakpoint | fuzz_skipped | llm_calls | step_time_ms |
|---|---|---|---|---|---|
| chain-0/step1 | PASSTHROUGH | false | **true** | **0** | **19** |
| chain-1/step1 | SIMPLE_DERIVATION | false | **true** | 1 | 1329 |
| chain-1/step2 | UNKNOWN | true | false | 1 | 1211 |
| chain-1/step3 | CONDITIONAL_SELECT | true | false | 1 | 21660 |

未进入变异循环的证据：

- chain-0 段落内 `[ context propagation fuzzing start... ]` 出现 **0 次**（off 模式同链为 1 次）；
- `llm_calls=0`，即整条 chain-0 一次 LLM 都没调；
- 日志出现 `*** [projection] single-shot synthesis triggered the vulnerability: ... ***`
  与 `[projection] step 1 skipped directed fuzzing, kind=PASSTHROUGH`。

两条链的成功步数与 `off` 完全一致（chain-0 = 1，chain-1 = 2），chain-0 耗时对照：

| 模式 | chain-0 耗时 | chain-0 LLM 调用 |
|---|---|---|
| `off` | 2065 ms | 1 |
| `full` | **23 ms** | **0** |

约 **90× 提速**。chain-1 因为 3 步里有 2 步是断点，整体耗时与 `off` 相当（24207 vs 25289 ms），
符合预期——投影的收益只体现在非断点步骤上。

## 验收 3：试运行失败后 `upgraded=true` 并回落完整 fuzz

真实链上没有自然出现试运行失败，因此用**故障注入**验证该控制流：临时令
`StepFuzzRunner.trySingleShotSynthesis` 恒返回 `null`，重新打包后跑 `full` 模式（chain-0）。

埋点输出：

```json
{"chain_id":"chain-0","vul_name":"CVE-2019-10086","step":1,"kind":"PASSTHROUGH","breakpoint":true,
 "fuzz_skipped":false,"trial_result":false,"upgraded":true,"step_time_ms":2167,"llm_calls":1,
 "complexity":34,"branch":1}
```

- `upgraded=true`、`breakpoint=true` → 断点已抬升；
- `kind` 仍为 `PASSTHROUGH` → **静态判定未被运行时结果改写**，两者差异正是阶段 B 要统计的误判样本；
- `llm_calls=1` 且该次运行 `[ context propagation fuzzing start... ]` 出现 **1 次** → 完整定向 fuzz 确实接管；
- 日志出现 `[projection] step 1 single-shot synthesis failed, promoted to breakpoint`。

注入代码在验证后已还原（`grep -c "TEMP FAULT INJECTION"` = 0），并重新打包复跑确认
`fuzz_skipped=true / llm_calls=0 / step_time_ms=11 / 变异循环 0 次` 恢复正常，全量单测 140/140 绿。

## 验收 4：`off` 模式回归

```
$ python3 docs/baseline-snapshot/compare.py runs/s4-offreg/output runs/s4-offreg/run.log
[PASS] dependency-chain.json
[PASS] puring-method-call-chain.json
[PASS] method-call-chain.json (set) — 21 chains
[PASS] key log — 22 lines

IDENTICAL TO BASELINE
```

`off` 模式产物目录仅含 `dependency-chain.json` / `method-call-chain.json` /
`puring-method-call-chain.json`，**不产生** `projection.json` 与 `projection-steps.jsonl`。
fuzz 运行的 `report.json` 步骤字段集与改动前完全一致（fastjson2 默认省略 null 字段，
5 个新增的 `projection*` 字段在 `off` 模式下不出现）。

---

## 归因记录：20s 预算下曾观察到的 chain-1 "回退"

首轮 20s 预算运行中，`off` 的 chain-1 到 `successStep=3`、`full` 只到 2，看似投影导致成功率下降。
按 SPEC S5「若有下降，逐条归因」追查后确认**与投影无关**：

- 把预算提到 60s 重跑，`off` 模式自己也只有 `successStep=2`（step3 耗时 61446 ms 后失败）；
- 即同一个 `off` 配置，20s 那次 step3 成功、60s 那次 step3 失败——**step3 本身是不稳定的**；
- chain-1/step3 是 `Form.validate → Field.validate`，`CONDITIONAL_SELECT` 断点，两种模式都走完整
  定向 fuzz，差别只在 prompt 是否附带约束；该步依赖 `Map.get` 的运行时内容与迭代器顺序，
  在 20s 量级的预算下成败接近抛硬币。

**方法论结论（对 S5 直接有效）**：单次运行不足以判定成功率差异，S5 的 off/full 对照必须做多次重复
并报告方差，否则会把 fuzz 与 LLM 的随机波动误读成投影的效果或副作用。
