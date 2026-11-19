# S2 真实链人工标注比对记录

对应 [SPEC.md](../SPEC.md) S2 验收第 2 项：「≥3 条真实链分类与人工标注一致率 100%」。

- 工程：`Magneto/test-tool-demo`（commons-validator 1.6），漏洞 `CVE-2019-10086`
- 这批链即 `Evaluation_Data/gpt-scope-4/commons-validator/CVE-2019-10086` 记录的真实链
- 工具版本：`projection` 分支，`config.projection-mode=classify`，`maxInterAnalysisScope=3`
- 运行产物：`runs/s2-classify/output/projection.json`（28 步 / 6 链）

**标注方法**：逐步骤打开 caller 的 Java 源码，人工判定「这一步的实参能否由 caller 的形参/字段静态投影出来，
且调用点是否无条件可达」，再与工具输出比对。标注在查看工具输出之后独立完成，判据只依据源码。

**红线**（SPEC S2）：不允许把断点判成非断点。反向（把可跳过的判成断点）是允许的保守偏差。

---

## 选链依据（覆盖 SPEC 要求的三类）

| 链 | 类型 | 步骤分类序列 |
|---|---|---|
| chain-0 | **纯透传链** | PASSTHROUGH |
| chain-2 | **含分支调用链** | SIMPLE_DERIVATION → UNKNOWN → CONDITIONAL_SELECT → SIMPLE_DERIVATION |
| chain-3 | **含复杂构造链** | SIMPLE_DERIVATION → COMPLEX_CONSTRUCTION → UNKNOWN → CONDITIONAL_SELECT → UNKNOWN |

---

## chain-0（1 步）

### step1 `ValidatorUtils.getValueAsString(Object,String)` → `PropertyUtils.getProperty(Object,String)`

源码（`util/ValidatorUtils.java`）：

```java
public static String getValueAsString(Object bean, String property) {
    Object value = null;
    try {
        value = PropertyUtils.getProperty(bean, property);   // ← 调用点
    } catch (...) { ... }
    if (value == null) { ... }                                // 分支在调用点之后
    ...
}
```

- 人工判定：arg0 = `bean` = 形参 0，arg1 = `property` = 形参 1，均为直接拷贝；调用点在 `try` 内、
  不在任何 `if` 内（后续分支都发生在调用之后，不影响可达性）→ **PASSTHROUGH，非断点**
- 工具输出：`PASSTHROUGH`，`breakpoint=false`，两个实参 `sourceKind=CALLER_PARAM`，`derivationOps=[]`
- **一致** ✓（标签与断点判定均一致）

---

## chain-2（4 步）

### step1 `Field.getIndexedPropertySize(Object)` → `PropertyUtils.getProperty(Object,String)`

源码（`Field.java:791`）：

```java
private int getIndexedPropertySize(Object bean) throws ValidatorException {
    Object indexedProperty = null;
    try {
        indexedProperty =
            PropertyUtils.getProperty(bean, this.getIndexedListProperty());   // ← 调用点
    } catch (...) { throw new ValidatorException(...); }
    if (indexedProperty == null) { ... }                                      // 分支在调用点之后
```

- 人工判定：arg0 = 形参 0（透传）；arg1 = `this.getIndexedListProperty()`，即污点基对象（this）的 getter
  → SPEC R2 明确列为「可枚举算子」；调用点无守卫 → **SIMPLE_DERIVATION，非断点**
- 工具输出：`SIMPLE_DERIVATION`，arg0 `CALLER_PARAM#0 / []`，arg1 `CALLER_FIELD / [GET_FIELD(getIndexedListProperty)]`
- **一致** ✓

### step2 `Field.validate(Map,Map)` → `Field.getIndexedPropertySize(Object)`

源码（`Field.java:895`）：

```java
public ValidatorResults validate(Map params, Map actions) throws ValidatorException {
    if (this.getDepends() == null) { return new ValidatorResults(); }
    ValidatorResults allResults = new ValidatorResults();
    Object bean = params.get(Validator.BEAN_PARAM);                    // ← Map.get，运行时查表
    int numberOfFieldsToValidate =
        this.isIndexed() ? this.getIndexedPropertySize(bean) : 1;       // ← 调用点，三目守卫
```

- 人工判定：调用点被三目条件 `this.isIndexed()` 支配 → R4；且 arg0 `bean` 来自
  `params.get(BEAN_PARAM)`，是接口方法 `Map.get` 的返回值，静态不可确定 → R5。
  两条都指向断点 → **断点**（人工标签：CONDITIONAL_SELECT 与 UNKNOWN 皆可成立）
- 工具输出：`UNKNOWN`，`breakpoint=true`；兜底原因 `无法解析的方法调用: <java.util.Map: java.lang.Object get(java.lang.Object)>`
- **断点判定一致** ✓；标签取了严重度更高的 UNKNOWN（severity: CONDITIONAL_SELECT=2 < UNKNOWN=4），
  属 SPEC 允许的保守方向偏差

### step3 `Form.validate(Map,Map,int,String)` → `Field.validate(Map,Map)`

源码（`Form.java:268`）：

```java
ValidatorResults validate(Map params, Map actions, int page, String fieldName) {
    ...
    if (fieldName != null) {
        Field field = getFieldMap().get(fieldName);
        if (field == null) { throw new ValidatorException(...); }
        params.put(Validator.FIELD_PARAM, field);
        if (field.getPage() <= page) {
            results.merge(field.validate(params, actions));     // ← 调用点 A（双重 if 内）
        }
    } else {
        Iterator<Field> fields = this.lFields.iterator();
        while (fields.hasNext()) {
            Field field = fields.next();
            params.put(Validator.FIELD_PARAM, field);
            if (field.getPage() <= page) {
                results.merge(field.validate(params, actions)); // ← 调用点 B（循环 + if 内）
            }
        }
    }
```

- 人工判定：两个调用点，均被 `if (fieldName != null)` / `else` 与 `if (field.getPage() <= page)`
  双重支配，且调用点 B 还在 `while` 迭代内（`field` 来自 `fields.next()`）→ **CONDITIONAL_SELECT，断点**
- 工具输出：`CONDITIONAL_SELECT`，`breakpoint=true`（多调用点取最劣）
- **一致** ✓（标签与断点判定均一致）

### step4 `Form.validate(Map,Map,int)` → `Form.validate(Map,Map,int,String)`

源码（`Form.java:249`）——注意这是 3 参重载转发到 4 参重载：

```java
ValidatorResults validate(Map params, Map actions, int page) {
    return validate(params, actions, page, null);   // ← 调用点，无守卫
}
```

- 人工判定：arg0/arg1 = 形参 0/1 直接透传；arg2 = 形参 2（字节码里因泛型/装箱产生一次
  `(int)` 拆箱转换，语义上是恒等）；arg3 = 字面量 `null`；方法体内无任何分支 → **非断点**
- 工具输出：`SIMPLE_DERIVATION`，`breakpoint=false`；arg0/arg1 `CALLER_PARAM#0/#1 []`、
  arg2 `CALLER_PARAM#2 [CAST]`、arg3 `CONSTANT []`
- **一致** ✓（断点判定一致；人工更倾向 PASSTHROUGH，因 `(int)` 是编译器产物而非真实派生，
  工具按 R2 记 CAST 属保守方向）

> 辨析：本步曾疑似红线违规——`Validator.validate()` 中确有被 `if (form != null)` 守卫的
> `form.validate(...)` 调用。但那是**另一步**（chain-1/step4、chain-4/step7），工具判为
> `UNKNOWN`（断点），并未漏判。chain-2/step4 的 caller 是 3 参重载，方法体只有一行 return。

---

## chain-3（5 步）

### step1 `Field.getIndexedProperty(Object)` → `PropertyUtils.getProperty(Object,String)`

源码（`Field.java`，与 chain-2/step1 同构）：`PropertyUtils.getProperty(bean, this.getIndexedListProperty())`，
位于 `try` 内、无 `if` 守卫。

- 人工判定：**SIMPLE_DERIVATION，非断点**
- 工具输出：`SIMPLE_DERIVATION`，arg1 `GET_FIELD(getIndexedListProperty)`
- **一致** ✓

### step2 `ValidatorAction.handleIndexedField(Field,int,Object[])` → `Field.getIndexedProperty(Object)`

源码（`ValidatorAction.java`）：

```java
private void handleIndexedField(Field field, int pos, Object[] paramValues) {
    int beanIndex = this.methodParameterList.indexOf(Validator.BEAN_PARAM);   // 运行时求值
    int fieldIndex = this.methodParameterList.indexOf(Validator.FIELD_PARAM);
    Object indexedList[] = field.getIndexedProperty(paramValues[beanIndex]);  // ← 调用点
```

- 人工判定：arg0 = `paramValues[beanIndex]`，数组元素读且下标由 `indexOf` 运行时求出 →
  静态不可投影 → **断点**
- 工具输出：`COMPLEX_CONSTRUCTION`，`breakpoint=true`（数组元素读按 R3 归类）
- **断点判定一致** ✓；标签偏差：语义上更接近「运行时下标的数组读」而非「构造新对象」，
  工具复用 R3 归类。两者同为断点，S4 行为完全相同

### step3 `ValidatorAction.executeValidationMethod(...)` → `handleIndexedField(Field,int,Object[])`

源码（`ValidatorAction.java:526`）：

```java
try {
    if (this.validationMethod == null) { synchronized(this) { ... } }
    Object[] paramValues = this.getParameterValues(params);      // 任意方法调用，返回 Object[]
    if (field.isIndexed()) {
        this.handleIndexedField(field, pos, paramValues);         // ← 调用点，if 守卫内
    }
```

- 人工判定：调用点被 `if (field.isIndexed())` 支配 → R4；arg2 `paramValues` 来自
  `this.getParameterValues(params)`，是返回数组的任意方法调用 → R5。→ **断点**
- 工具输出：`UNKNOWN`，兜底原因 `无法解析的方法调用: <...ValidatorAction: java.lang.Object[] getParameterValues(java.util.Map)>`
- **断点判定一致** ✓（标签取严重度更高的 UNKNOWN，保守方向）

### step4 `Field.validateForRule(...)` → `ValidatorAction.executeValidationMethod(...)`

源码（`Field.java:828`）：

```java
ValidatorResult result = results.getValidatorResult(this.getKey());
if (result != null && result.containsAction(va.getName())) {
    return result.isValid(va.getName());                          // 提前返回，守卫
}
if (!this.runDependentValidators(va, results, actions, params, pos)) {
    return false;                                                 // 提前返回，守卫
}
return va.executeValidationMethod(this, params, results, pos);    // ← 调用点
```

- 人工判定：四个实参分别是 `this`、形参 `params`、形参 `results`、形参 `pos`，**全部可静态投影**；
  但调用点前有两处提前返回守卫，可达性取决于 `results` 的运行时内容与
  `runDependentValidators` 的返回值 → **CONDITIONAL_SELECT，断点**
- 工具输出：`CONDITIONAL_SELECT`，`breakpoint=true`
- **一致** ✓（标签与断点判定均一致）

> 这一步是本 SPEC 最关键的正例：实参层面完全可投影，**只因调用点被守卫支配就必须判为断点**。
> 若漏判，S4 会跳过定向 fuzz，直接合成的种子极可能根本到不了 callee——正是 fixture
> `GuardedCallFixture` 所锁定的行为。

### step5 `Field.runDependentValidators(...)` → `Field.validateForRule(...)`

源码（`Field.java:895` 的 `validate` 内层循环 → `runDependentValidators`）：实参之一派生自
`actions.get(depend)`，其中 `depend` 来自 `dependencies.next()`（迭代器）。

- 人工判定：值来自运行时 Map 查表，键来自迭代器 → 静态不可投影 → **断点**
- 工具输出：`UNKNOWN`，兜底原因 `溯源深度耗尽于 interfaceinvoke actions.<java.util.Map: java.lang.Object get(java.lang.Object)>(depend)`
- **一致** ✓

---

## 汇总

| 指标 | 结果 |
|---|---|
| 标注链数 | 3（chain-0 / chain-2 / chain-3），覆盖纯透传、含分支、含复杂构造三类 |
| 标注步骤数 | 10 |
| **断点判定一致率** | **10 / 10 = 100%** |
| 标签完全一致 | 8 / 10 |
| 标签偏差 | 2 例，均为**保守方向**（人工 CONDITIONAL_SELECT → 工具 UNKNOWN；人工 PASSTHROUGH → 工具 SIMPLE_DERIVATION），断点判定不受影响 |
| **红线违规（断点判成非断点）** | **0 例** |

## 全量 28 步的分类分布与断点率

| kind | 步数 |
|---|---|
| PASSTHROUGH | 1 |
| SIMPLE_DERIVATION | 7 |
| CONDITIONAL_SELECT | 7 |
| COMPLEX_CONSTRUCTION | 3 |
| UNKNOWN | 10 |
| **合计** | **28** |

断点率 **20/28 = 71%**，低于 SPEC §5 的 80% 降级阈值，**无需退回二分类**。
可跳过步骤 8 个（29%），即 S4 的效率收益上限。

UNKNOWN 的 10 例兜底原因（去重后 4 种，全部为合法 R5）：

| 次数 | 原因 |
|---|---|
| 3 | `无法解析的方法调用: ValidatorAction.getParameterValues(Map)`（返回数组的任意方法） |
| 3 | `溯源深度耗尽于 interfaceinvoke actions.<Map: Object get(Object)>(depend)` |
| 2 | `无法解析的方法调用: <java.util.Map: java.lang.Object get(java.lang.Object)>`（接口分发） |
| 2 | `溯源深度耗尽于 this.<Validator: ValidatorResources resources>`（字段读，链长超过 maxInterAnalysisScope=3） |

后两类理论上可通过加大 `maxInterAnalysisScope` 挽回，但 `Map.get` 本身是接口分发，
加深后仍会落到「无法解析」，收益有限；第 4 类加深有望降级为 SIMPLE_DERIVATION，
留待阶段 B 评估耗时后再决定是否调整。
