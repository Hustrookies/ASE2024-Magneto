#!/usr/bin/env bash
# SPEC S5：约束投影实验的一键运行脚本。
#
# 用法：
#   scripts/run_projection_experiment.sh \
#       --project <客户端工程路径> --cve <CVE 名> --mode <off|classify|full> \
#       --out <输出根目录> [--reps N] [--fuzz-time MS] [--chains N] [--retry N]
#       [--skip-fuzz] [--jar <jar 路径>] [--groundtruth <路径>] [--keep-cache]
#       [--no-inject-constraints]
#
# --no-inject-constraints  消融用：仍然跳过非断点步骤，但不把约束文本注入 prompt。
#                          用来把「跳过带来的收益」与「注入对断点步骤的影响」分开测量。
#
# 每次重复都在独立子目录里跑，输出互不污染。LLM 凭证只从环境变量读取：
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
KEEP_CACHE=0
INJECT=1

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
    --keep-cache)  KEEP_CACHE=1; shift ;;
    --no-inject-constraints) INJECT=0; shift ;;
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

if [[ $SKIP_FUZZ -eq 0 && "$MODE" != "off" ]]; then
  : "${MAGNETO_GPT_TOKEN:?MAGNETO_GPT_TOKEN must be set for a fuzzing run}"
fi

MODE_DIR="$OUT/$MODE"
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

  # 清 gpt-cache：缓存命中会让 off/full 的对照失去意义（SPEC 5 风险表）
  if [[ $KEEP_CACHE -eq 0 ]]; then
    rm -f "$RUN_DIR/output/gpt-cache.json" "$RUN_DIR/gpt-cache.json"
  fi

  echo "[$MODE rep$rep] running..."
  set +e
  ( cd "$RUN_DIR" && java -jar "$JAR" -p "$PROJECT" -vul "$CVE" \
      -output "$RUN_DIR/output" ${FUZZ_ARGS[@]+"${FUZZ_ARGS[@]}"} > run.log 2>&1 )
  status=$?
  set -e
  echo "[$MODE rep$rep] exit=$status"
  echo "$status" > "$RUN_DIR/exit-status"
done

python3 "$REPO_ROOT/scripts/aggregate_projection_results.py" \
  --mode-dir "$MODE_DIR" --mode "$MODE" --reps "$REPS"

echo "[$MODE] done -> $MODE_DIR/steps.csv , $MODE_DIR/summary.json"
