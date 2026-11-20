# projection.json schema

约束投影分析器的输出格式。对应 [SPEC.md](../SPEC.md) S3 验收第 3 项。

产出条件：`config.projection-mode` 为 `classify` 或 `full`（`off` 不产出任何文件，行为与基线逐字节一致）。
写入位置：`<output-dir>/projection.json`，由 `JsonOutputHandler.outputProjection` 落盘。
生成时机：静态分析阶段结束后、fuzz 之前（`Magneto.generateProjection`），因此 `-skipFuzz` 也能产出。

顶层是一个数组，每个元素对应一条 puring 调用链，顺序与 `puring-method-call-chain.json` 一致。

---

## 1. ChainProjection（顶层元素）

| 字段 | 类型 | 说明 |
|---|---|---|
| `chainId` | string | 链标识，正常为 `chain-<i>`（i 为在 puring 链列表中的下标）。若 fuzz 阶段遇到未被静态阶段分析过的链，退化为 `chain-unlisted-<hashCode 十六进制>` 并打 WARN |
| `steps` | StepProjection[] | 逐步骤投影，**长度 = 链长 − 1**，顺序与 `reverseChainList` 一致 |
| `breakpointCount` | int | `steps` 中 `breakpoint=true` 的个数 |

`breakpointCount` 是**序列化时实时计算**的派生值，不是存储字段，始终与 `steps` 里的 `breakpoint` 一致。

> 注意：`projection.json` 写盘于 fuzz **之前**，因此其中的断点数是纯静态判定结果，
> **不含运行时升级**。升级情况见 `projection-steps.jsonl` 的 `upgraded` 字段。

## 2. StepProjection

步骤 i 对应 `reverseChainList` 的下标 i：**caller = get(i) = Fᵢ**，**callee = get(i−1) = Fᵢ₋₁**。
与 `StepFuzzRunner.fuzzCallChain` 的步骤循环（`targetMethodCall=get(i)`、`triggeredMethodCall=get(i-1)`）
严格一致，因此 `stepIndex` 可以直接对上 fuzz 循环的 `i`。

| 字段 | 类型 | 说明 |
|---|---|---|
| `stepIndex` | int | 步骤下标，取值 1 … 链长−1 |
| `callerSignature` | string | Fᵢ 的 Soot 方法签名 |
| `calleeSignature` | string | Fᵢ₋₁ 的 Soot 方法签名 |
| `kind` | ProjectionKind | R1—R5 分类结果，见 §4 |
| `breakpoint` | boolean | **权威字段**。是否需要走完整定向 fuzz。见下方语义说明 |
| `paramProjections` | ParamProjection[] | 逐实参溯源结果，按 `calleeArgIndex` 升序 |
| `projectedConstraints` | string[] | 渲染后的约束文本，供 S4 注入 LLM prompt，见 §6 |
| `taintMapping` | object(int → string[]) | 现有 `MethodParameterMappingAnalysis.taintObjectMap` 的摘要，见 §7 |
| `evidence` | string \| null | 判定所依据的关键 Jimple 语句，见 §8 |
| `complexityScore` | int \| null | 复用 `ComplexityAnalyzer.compute(caller, callee)` |
| `branchScore` | int \| null | 复用 `BranchAnalyzer.compute(caller, callee)` |

### `kind` 与 `breakpoint` 的关系

- `setKind(k)` 会同时把 `breakpoint` 置为 `k.isBreakpointKind()`，二者在静态阶段恒一致；
- `StepProjection` 是**静态阶段产物**，不承载运行时状态。试运行失败导致的升级记录在
  `projection-steps.jsonl` 的 `upgraded` 字段里，不回写本对象；
- 这是刻意的：同一条链可能对应多个 CVE，`ChainProjectionService` 的缓存对象会被它们共享。
  若就地 mutate，第二个 CVE 会看到一个「天生就是断点」的步骤，既不再试运行，
  也无法在埋点里与静态断点区分。升级状态因此按 CVE 独立保存在
  `StepFuzzRunner` 的局部集合中。

> 误判样本的查法：在 `projection-steps.jsonl` 中筛 `upgraded=true`，
> 其 `kind` 仍是被误判的那个非断点类别（如 `PASSTHROUGH`），
> 而 `breakpoint=true`。升级率 = `upgraded` 数 / 尝试跳过数，是分类质量的直接度量。

### 字段集恒定

序列化走 `ChainProjection.toJSONObject()`，显式构造并关闭了 hutool 的 `ignoreNullValue`。
所以即使 `evidence` 为 null、`complexityScore` 为 null，字段也**一定出现在 JSON 里**（当前共 11 个）。
下游脚本可以直接取值，不必判 key 是否存在。

> 这条是被 bug 逼出来的：hutool 的 bean 内省要求 getter/setter 成对，派生的
> `getBreakpointCount()` 没有 setter，用 `JSONUtil.parseObj` 会让该字段静默消失且不报错。

## 3. ParamProjection

单个 callee 实参的溯源结果。

| 字段 | 类型 | 说明 |
|---|---|---|
| `calleeArgIndex` | int | callee 的实参下标 |
| `sourceKind` | ProjectionSource | 溯源终点类型，见 §5 |
| `callerParamIndex` | int | 仅 `sourceKind=CALLER_PARAM` 时有意义，否则为 `-1` |
| `derivationOps` | string[] | 派生算子链，见 §5.2。诊断信息（`MULTI_DEF(n)` / `UNRESOLVED(原因)`）也记在这里 |

## 4. ProjectionKind（R1—R5）

| 值 | 规则 | 是否断点 | 含义 |
|---|---|---|---|
| `PASSTHROUGH` | R1 | 否 | 实参 def 链只经 IdentityStmt 与局部拷贝，值可原样映射 |
| `SIMPLE_DERIVATION` | R2 | 否 | def 链含可枚举算子（getter/字段读、字符串拼接、类型转换、单层包装） |
| `CONDITIONAL_SELECT` | R4 | **是** | 调用点被条件分支支配，或实参在不同分支有多定义点 |
| `COMPLEX_CONSTRUCTION` | R3 | **是** | def 链含 NewExpr + 多次写入、builder 链、数组填充/数组元素读 |
| `UNKNOWN` | R5 | **是** | 深度超限、接口分发不可解析、任意方法返回值、异常。保守兜底 |

严重度排序（多实参、多调用点时**取最劣**）：
`PASSTHROUGH(0) < SIMPLE_DERIVATION(1) < CONDITIONAL_SELECT(2) < COMPLEX_CONSTRUCTION(3) < UNKNOWN(4)`

## 5. ProjectionSource 与 derivationOps

### 5.1 ProjectionSource

| 值 | 含义 |
|---|---|
| `CALLER_PARAM` | 溯源到 caller 的形参，`callerParamIndex` 给出下标 |
| `CALLER_FIELD` | 溯源到 caller 接收者对象的字段（含 `this` 本身） |
| `CONSTANT` | 溯源到常量，对 caller 不施加约束 |
| `NEW_OBJECT` | 调用点内新建的对象，或运行时下标的数组元素读 |
| `UNRESOLVED` | 溯源失败，具体原因写在 `derivationOps` 的 `UNRESOLVED(...)` 里 |

### 5.2 derivationOps

算子名常量定义在 `DerivationOps`，S2 产出、S3 消费，共用一份避免字符串漂移。

| 算子 | 形态 | 含义 |
|---|---|---|
| `GET_FIELD` | `GET_FIELD(getName)` / `GET_FIELD(<字段签名>)` | getter 调用或字段读 |
| `STR_CONCAT` | `STR_CONCAT` | 字符串拼接。**含 Java 8 的 `new StringBuilder().append().toString()` 链** |
| `CAST` | `CAST` | 类型转换。值级视为恒等（含泛型/装箱产生的 `(int)` 等编译器产物） |
| `WRAP` | `WRAP(<方法签名>)` | 单层包装：装箱 `valueOf`、`Collections.singletonList` 等白名单 |
| `MULTI_DEF` | `MULTI_DEF(n)` | 诊断：该实参有 n 个可到达的定义点（R4） |
| `UNRESOLVED` | `UNRESOLVED(<原因>)` | 诊断：溯源中止的原因（R5） |

> **Java 8 字符串拼接的坑**：`a + "!"` 编译成 `new StringBuilder` → `append(a)` → `append("!")` →
> `toString()`。按朴素规则这是「NewExpr + 多次调用」= R3 复杂构造 = 断点。但 SPEC R2 明确要求
> 识别为字符串拼接。`StepClassifier.traceStringBuilderChain` 专门处理，否则真实代码里凡拼字符串
> 的步骤全会误判成断点。由 `ConcatFixture` 锁定。

## 6. projectedConstraints 的行格式

每个 callee 实参一行，顺序与实参下标一致；末尾按需追加整步级提示行。文本为英文，
因为要注入 `analysis_code_template.txt` 那个英文 prompt。

**非断点步骤：**

| 情形 | 格式 |
|---|---|
| 直接值映射 | `callee arg J <- caller param K (direct value): caller param K must be <要求>` |
| 经算子派生 | `callee arg J <- caller param K via [OPS]: the value after [OPS] must satisfy: <要求>` |
| 来自接收者字段 | `callee arg J <- receiver object via [OPS]: <accessor> of the receiver object must return a value that satisfies: <要求>` |
| 常量 | `callee arg J is a constant in the caller body: no constraint on the caller` |

**断点步骤：**

```
callee arg J comes from <结构描述>, but this step is a projection breakpoint (KIND). CONSTRUCTION TARGET: make callee arg J satisfy: <要求>
```

`<结构描述>` 即使在断点步骤也会给出（`caller param K` / `the receiver object via [...]` /
`a value constructed inside the caller` / `an expression that cannot be resolved statically`）——
求不出值不等于求不出结构，这个信息对 LLM 构造种子仍然有效。

**整步级追加行（按需，各最多一行）：**

- `REACHABILITY OBLIGATION: ...` —— 当 `kind = CONDITIONAL_SELECT`。**这一行不能省**：
  实参全部可投影但调用点被守卫支配时，只给构造目标会让 S4 合成一个根本到不了 callee 的种子。
- `NO DOWNSTREAM REQUIREMENT: ...` —— 当断点步骤存在拿不到下层要求的实参。
  整步只出现一次而非逐实参重复，避免无谓撑大 prompt。

**要求值的来源**：`ConstraintProjector.propagateChain` 沿链反向传播。
下标 0 是 F₀ 的实参要求（PoC 值），步骤 i 消费 Fᵢ₋₁ 的要求、产出 Fᵢ 的要求。
断点处传播中止——无法静态求逆就不伪造映射。

`projection.json` 里的 `projectedConstraints` 是**静态阶段**渲染的，此时 PoC 尚未执行，
要求值用带实参下标的占位文本：
`the runtime value of PoC arg J of the vulnerable function (F0), captured by executing the ground-truth testcase`
（带下标是必要的，否则同层所有约束文本完全一样，人工核对时无从对应）。

**注入 prompt 的不是这份占位文本。** `full` 模式下 `StepFuzzRunner` 在每一步调用
`ConstraintProjector.renderWithRuntimeValues(step, latestContext.getParamsValue())`
用 Context 里的**真实运行时值**重新渲染，值经 `describeValue` 格式化：
字符串加引号并附类型（`"class" (java.lang.String)`）、null 显式写作 `null`、
超过 200 字符截断并标注 `...(truncated, N chars total)`——截断必须显式标注，
否则 LLM 会把截断值当成完整约束。

## 7. taintMapping

现有 `MethodParameterMappingAnalysis` 产出的 `taintObjectMap`（callee 实参下标 → caller 侧污点对象集合）
的可读摘要。**key 与 value 都排过序**，保证同一输入跨运行字节一致（可 diff）。

值格式：

| 形态 | 含义 |
|---|---|
| `PARAM <方法签名> #<下标>` | `TaintParam`：caller 的某个形参 |
| `FIELD <字段签名>` | `TaintField`：caller 所属类的某个字段 |

摘要失败（异常）时为空对象 `{}`，不影响分类结果——分类仍走 UNKNOWN 兜底。

## 8. evidence

判定所依据的 Jimple 语句摘录，用于人工核对。格式：

```
--- call site: <调用点语句> ---
<实参 0 的 def 链，逐行>
<实参 1 的 def 链，逐行>
<可到达该调用点的所有 if 语句，按 body 顺序>
```

多调用点时每个调用点一段。所有顺序都做了确定性处理（实参按下标、def 与 if 按 body 顺序），
因此同一工程重复运行 evidence 完全一致。

## 9. 已知的标签不精确处

断点判定不受影响，仅标签语义偏保守，人工核对时需结合 `evidence`：

1. **运行时下标的数组元素读**（如 `paramValues[beanIndex]`，其中 `beanIndex` 由 `indexOf` 求出）
   归入 `COMPLEX_CONSTRUCTION` 而非单独一类——SPEC 3.1 的 `ProjectionKind` 只有 5 个值，
   且它与「构造新对象」同为断点，S4 行为完全相同。
2. **`(int)` 之类的编译器拆箱产物**记为 `CAST`，使步骤从 `PASSTHROUGH` 降为 `SIMPLE_DERIVATION`。
   语义上是恒等，但按 R2 记算子属保守方向。
3. **守卫规则不区分条件来源**。SPEC R4 原文是「条件依赖非形参污点值」，实现上只要调用点被条件
   支配就判 `CONDITIONAL_SELECT`。理由：形参守卫同样是必须满足的约束，漏判代价（白跑一次试运行
   再升级）高于多判代价（本来就要跑的定向 fuzz）。
4. **字段读只在基对象为 `this` 时才记 `CALLER_FIELD`**。`h.value`（h 为形参）在 Jimple 里
   同样是 `InstanceFieldRef`，但种子的接收者回填机制覆盖不到它，故记为 `UNRESOLVED`（断点）。
   接收者分析同理：仅静态调用、`this`、`this` 的直接字段读（算子链长度 ≤ 1）三种情形放行。
   这三条是 S5 在 QLExpress 上发现系统性误判后补的，详见
   [projection-annotation.md](projection-annotation.md) 与 §10 的实证依据。

## 10. 附产物：llm-calls.txt

以 `-Dmagneto.llm.calls.metric=true` 启动时，输出目录额外生成 `llm-calls.txt`，
内容为本次运行**真实发出的 LLM API 请求数**（缓存命中不计）。默认不生成，
因此不影响 `off` 模式与基线的产物一致性。

之所以需要它：`run.log` 里的 `the gpt answer:` 行在**缓存命中和每次重试时都会打印**，
用它计数会系统性偏高，且与埋点里的 `llm_calls`（真实请求数）口径不一致，
跨模式比较会得出错误结论。`scripts/run_projection_experiment.sh` 默认开启该度量。

## 11. 复现与当前规模

```bash
cd <repo>/runs/<name>
cat > application.properties <<EOF
config.ground-truth-path=<repo>/Magneto/groundtruth
config.output-dir=output
config.projection-mode=classify
EOF
java -jar <repo>/Magneto/magneto-engine/target/magneto-engine-1.0.jar \
  -p <repo>/Magneto/test-tool-demo -skipFuzz -output "$PWD/output"
```

在 `test-tool-demo`（commons-validator 1.6，CVE-2019-10086）上的实测规模：

| 指标 | 值 |
|---|---|
| 链数 / 步骤数 | 6 / 28 |
| 分类分布 | PASSTHROUGH 1、SIMPLE_DERIVATION 7、CONDITIONAL_SELECT 7、COMPLEX_CONSTRUCTION 3、UNKNOWN 10 |
| 断点率 | 20/28 = **71%**（低于 SPEC §5 的 80% 降级阈值） |
| `projectedConstraints` | 99 行 / 18105 字符 |
| `taintMapping` 覆盖率 | 28 步中空集 0 步；77 个实参中 68 个有映射（88%） |

样例产物：[s3-evidence/projection.json](s3-evidence/projection.json)（含已填充的 `projectedConstraints`）；
[s2-evidence/projection.json](s2-evidence/projection.json) 为 S2 版本，`projectedConstraints` 尚为空。
人工核对记录：[projection-annotation.md](projection-annotation.md)。
