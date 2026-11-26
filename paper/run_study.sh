#!/usr/bin/env bash
# Recompute every number in paper/main.tex and record its provenance with osaudit
# (https://github.com/ASSERT-KTH/osaudit). Run from a clean checkout, after committing any change:
#
#     bash paper/run_study.sh
#
# Needs uv. Creates .venv-paper (Python 3.13, this repository's sra-riskgate, osaudit, huggingface_hub),
# downloads the published data into paper/data/, writes paper/results/*.json, then runs `osaudit`.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
if [ -n "$(git status --porcelain -- paper/study osaudit.toml sra_riskgate)" ]; then
  echo "Commit your changes to paper/study, osaudit.toml and sra_riskgate first: osaudit records the commit." >&2
  exit 1
fi
[ -d .venv-paper ] || uv venv -q --python 3.13 .venv-paper
uv pip install -q -p .venv-paper -e . "osaudit==0.7.0" huggingface_hub
source .venv-paper/bin/activate

python paper/fetch_data.py > /dev/null
B=paper/data/sra-bench-results
S=paper/data/sra-stablecoin-risk-bench/data/benchmark
W=paper/data/sra-real-world-poisoning
mkdir -p paper/results

run() {  # run OUTPUT INSTRUMENT INPUT...
  local out=$1 instrument=$2; shift 2
  local args=()
  for f in "$@"; do args+=(--input "$f"); done
  osaudit run "${args[@]}" -o "paper/results/$out" -- python "paper/study/$instrument" "$@"
  echo "wrote paper/results/$out"
}

run benchmark.json benchmark.py \
  $B/qwen3-4b-instruct-base/scores.json $B/sra-riskgate-4b/scores.json $B/sra-riskgate-4b-v2/scores.json \
  $B/sra-riskgate-4b-v2-no-window/scores.json $B/sra-riskgate-4b-q8_0/scores.json \
  $B/sra-riskgate-4b-q4_k_m/scores.json $B/sra-real-v1/qwen3-4b-instruct-base/scores.json \
  $B/sra-real-v1/sra-riskgate-4b-v1/scores.json $B/sra-real-v1/sra-riskgate-4b-v2/scores.json \
  $B/sra-real-v1/summary.json

run failures.json failures.py \
  $S/test.jsonl $S/train.jsonl $B/sra-riskgate-4b/predictions.jsonl \
  $B/sra-riskgate-4b-v2/predictions.jsonl $B/sra-riskgate-4b-q4_k_m/predictions.jsonl

run real_world.json real_world.py \
  $W/attacks.csv $W/normal.csv $W/summary.json $W/model_eval/model_summary.json

# The library measures itself: its inputs are the source files that decide the results.
osaudit run --input sra_riskgate/bench.py --input sra_riskgate/threats.py --input sra_riskgate/evidence.py \
  --input sra_riskgate/check.py -o paper/results/library.json -- python paper/study/library.py
echo "wrote paper/results/library.json"

echo
echo "osaudit:"
osaudit && echo "osaudit: clean (exit 0)"
