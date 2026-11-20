#!/usr/bin/env bash
# SPEC S5：约束投影实验的一键运行脚本。
#
# 用法：
#   scripts/run_projection_experiment.sh \
#       --project <客户端工程路径> --cve <CVE 名> --mode <off|classify|full> \
#       --out <输出根目录> [--reps N] [--fuzz-time MS] [--chains N] [--retry N]
#       [--skip-fuzz] [--jar <jar 路径>] [--groundtruth <路径>]
#       [--no-inject-constraints] [--tag <子目录名>]
#
# --tag                    结果子目录名，默认取 --mode。消融实验用它区分同一模式的多个臂。
#
# --no-inject-constraints  消融用：仍然跳过非断点步骤，但不把约束文本注入 prompt。
#                          用来把「跳过带来的收益」与「注入对断点步骤的影响」分开测量。
#
# 每次重复都在独立子目录里跑（先整目录删除），输出与 gpt-cache 互不污染。LLM 凭证只从环境变量读取：
#   MAGNETO_GPT_TOKEN / MAGNETO_GPT_ENDPOINT / MAGNETO_GPT_MODEL
# 脚本本身不含任何密钥，可安全提交。
#
# 产物：
#   <out>/<mode>/rep<N>/run.log                  完整日志
#   <out>/<mode>/rep<N>/output/                  工具原始产物
#   <out>/<mode>/steps.csv                       所有重复汇总的步骤级 CSV
#   <out>/<mode>/summary.json                    该模式的聚合指标（含均值/标准差）

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PROJECT=""
CVE=""
MODE=""
OUT=""
REPS=1
FUZZ_TIME=20000
CHAINS=2
RETRY=1
SKIP_FUZZ=0
JAR="$REPO_ROOT/Magneto/magneto-engine/target/magneto-engine-1.0.jar"
GROUNDTRUTH="$REPO_ROOT/Magneto/groundtruth"
INJECT=1
TAG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project)     PROJECT="$2"; shift 2 ;;
    --cve)         CVE="$2"; shift 2 ;;
    --mode)        MODE="$2"; shift 2 ;;
    --out)         OUT="$2"; shift 2 ;;
    --reps)        REPS="$2"; shift 2 ;;
    --fuzz-time)   FUZZ_TIME="$2"; shift 2 ;;
    --chains)      CHAINS="$2"; shift 2 ;;
    --retry)       RETRY="$2"; shift 2 ;;
    --skip-fuzz)   SKIP_FUZZ=1; shift ;;
    --jar)         JAR="$2"; shift 2 ;;
    --groundtruth) GROUNDTRUTH="$2"; shift 2 ;;
    --no-inject-constraints) INJECT=0; shift ;;
    --tag)         TAG="$2"; shift 2 ;;
    -h|--help)     sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

for required in PROJECT CVE MODE OUT; do
  if [[ -z "${!required}" ]]; then
    echo "missing required option: --$(echo "$required" | tr 'A-Z' 'a-z')" >&2
    exit 2
  fi
done

case "$MODE" in
  off|classify|full) ;;
  *) echo "--mode must be off|classify|full, got: $MODE" >&2; exit 2 ;;
esac

[[ -f "$JAR" ]] || { echo "jar not found: $JAR (run mvn package first)" >&2; exit 1; }
[[ -d "$PROJECT" ]] || { echo "project dir not found: $PROJECT" >&2; exit 1; }
[[ -d "$GROUNDTRUTH" ]] || { echo "groundtruth dir not found: $GROUNDTRUTH" >&2; exit 1; }

# 所有会 fuzz 的臂都需要 token，off 也不例外——off 臂走的就是原始 LLM 定向 fuzz 流程。
# 缺 token 时 GPTServer 会退回仓库里的占位串，每次请求 401、askGPT 返回 null、每步都失败，
# 而 JVM 仍然 exit 0，最终会让 compare_modes.py 打出一个假的 PASS。
if [[ $SKIP_FUZZ -eq 0 ]]; then
  : "${MAGNETO_GPT_TOKEN:?MAGNETO_GPT_TOKEN must be set for a fuzzing run (all modes fuzz, including off)}"
fi

# --tag 让同一实验目录下能放多个同模式不同配置的臂（如消融：full 与 full-noinject）
# docs/s4-evidence/VERIFICATION.md 的结论：预算接近某步实际所需时间时，成败对预算高度敏感，
# 短预算下的成功率不具判别力。低于该阈值时给出提示，避免用噪声数据下结论。
if [[ $SKIP_FUZZ -eq 0 && $FUZZ_TIME -lt 60000 ]]; then
  echo "WARNING: --fuzz-time=${FUZZ_TIME}ms 低于 60s。短预算下断点步骤的成败接近抛硬币，" >&2
  echo "         成功率差异不具判别力（见 docs/s4-evidence/VERIFICATION.md 的归因记录）。" >&2
fi

MODE_DIR="$OUT/${TAG:-$MODE}"
mkdir -p "$MODE_DIR"

FUZZ_ARGS=()
[[ $SKIP_FUZZ -eq 1 ]] && FUZZ_ARGS+=("-skipFuzz")

for ((rep = 1; rep <= REPS; rep++)); do
  RUN_DIR="$MODE_DIR/rep$rep"
  rm -rf "$RUN_DIR"
  mkdir -p "$RUN_DIR"

  {
    echo "config.ground-truth-path=$GROUNDTRUTH"
    echo "config.output-dir=output"
    echo "config.projection-mode=$MODE"
    echo "config.max-fuzz-chain-number=$CHAINS"
    echo "config.max-fuzz-time=$FUZZ_TIME"
    echo "config.max-retry-count=$RETRY"
    # token 与 endpoint 刻意不写进文件：GPTServer 会优先读 MAGNETO_GPT_TOKEN /
    # MAGNETO_GPT_ENDPOINT 环境变量。落盘会让密钥有被误提交的风险。
    [[ -n "${MAGNETO_GPT_MODEL:-}" ]] && echo "config.gpt-model-name=$MAGNETO_GPT_MODEL"
    # 消融开关：--no-inject-constraints 时只跳过、不注入约束
    [[ $INJECT -eq 0 ]] && echo "config.projection-inject-constraints=false"
  } > "$RUN_DIR/application.properties"
  chmod 600 "$RUN_DIR/application.properties"

  # gpt-cache 必然被清掉：上面 rm -rf "$RUN_DIR" 已删除整个运行目录。
  # 这是刻意的——缓存命中会让 off/full 的对照失去意义（SPEC 5 风险表）。

  echo "[$MODE rep$rep] running..."
  set +e
  # -Dmagneto.llm.calls.metric=true 让工具把真实 LLM API 请求数写进 output/llm-calls.txt。
  # 该文件默认不生成，开启后也不影响 fuzz 行为，因此 off 臂与 full 臂的计数口径可比。
  ( cd "$RUN_DIR" && java -Dmagneto.llm.calls.metric=true -jar "$JAR" -p "$PROJECT" -vul "$CVE" \
      -output "$RUN_DIR/output" ${FUZZ_ARGS[@]+"${FUZZ_ARGS[@]}"} > run.log 2>&1 )
  status=$?
  set -e
  echo "[$MODE rep$rep] exit=$status"
  echo "$status" > "$RUN_DIR/exit-status"
done

python3 "$REPO_ROOT/scripts/aggregate_projection_results.py" \
  --mode-dir "$MODE_DIR" --mode "$MODE" --reps "$REPS"

echo "[$MODE] done -> $MODE_DIR/steps.csv , $MODE_DIR/summary.json"
