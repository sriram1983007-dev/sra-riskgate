#!/usr/bin/env bash
# One-shot GPU pipeline: baseline eval -> train -> eval -> safety gate -> merge + publish (private).
# Usage (inside tmux on the GPU machine):  HF_USER=yourname bash scripts/gpu_pipeline.sh
set -euo pipefail
: "${HF_USER:?Set HF_USER to your Hugging Face username}"
DATASET="${DATASET:-$HF_USER/sra-stablecoin-risk-bench}"
MODEL_REPO="${MODEL_REPO:-$HF_USER/SRA-RiskGate-4B}"
BASE="${BASE:-Qwen/Qwen3-4B-Instruct-2507}"
ADAPTER=checkpoints/sra-risk-gate/final_adapter
mkdir -p results logs

echo "== 0/5 tests";            python -m pytest -q | tee logs/tests.log
echo "== 1/5 baseline eval";    python scripts/evaluate_model.py --model "$BASE" --dataset "$DATASET" --tag base --batch-size 16 | tee logs/eval_base.log
echo "== 2/5 train";            python scripts/train.py --model "$BASE" --data "$DATASET" | tee logs/train.log
echo "== 3/5 trained eval";     python scripts/evaluate_model.py --adapter "$ADAPTER" --dataset "$DATASET" --tag model --batch-size 16 | tee logs/eval_model.log
echo "== 4/5 safety gate"
if ! python scripts/check_release.py --metrics results/metrics_model.json | tee logs/gate.log; then
  echo "Safety gate FAILED: not publishing. Send results/metrics_model.json for review."; exit 1
fi
echo "== 5/5 merge + publish (private)"
python scripts/merge_and_publish_model.py --adapter "$ADAPTER" --repo "$MODEL_REPO" --dataset-repo "$DATASET" \
  --metrics results/metrics_model.json --base-metrics results/metrics_base.json --private | tee logs/publish.log
echo "Done. Review https://huggingface.co/$MODEL_REPO, then make it public. STOP THE POD to end billing."
