# Training SRA-RiskGate-4B

These are the scripts that trained the published model
([SRA-RiskGate-4B](https://huggingface.co/sriram1983007/SRA-RiskGate-4B), adapter:
[SRA-RiskGate-4B-LoRA](https://huggingface.co/sriram1983007/SRA-RiskGate-4B-LoRA)), committed unchanged.

- **`train.py`** fine-tunes `Qwen/Qwen3-4B-Instruct-2507` on the `sft` config of
  [sra-stablecoin-risk-bench](https://huggingface.co/datasets/sriram1983007/sra-stablecoin-risk-bench).
- **`gpu_pipeline.sh`** is the one-shot GPU run that called it: baseline evaluation, training, evaluation,
  a release safety gate, then merge and private publish. Only its training step (`train.py`) is included
  here. The evaluation, gate and publish scripts it calls were part of the original project and are not
  needed to reproduce the published numbers: those were measured afterwards with
  [`eval/run_eval.py`](../eval/run_eval.py) and the dataset's `score.py` (see
  [Reproduce the paper](../README.md#reproduce-the-paper)).

## Configuration used

The pipeline runs `train.py --model Qwen/Qwen3-4B-Instruct-2507 --data <dataset>` with no other flags, so the
script's defaults apply:

| Setting | Value |
|---|---|
| Method | QLoRA: base in 4-bit NF4, double quantization, bfloat16 compute |
| LoRA | rank 32, alpha 64, dropout 0.05, on q/k/v/o and gate/up/down projections |
| Trainer | TRL `SFTTrainer`, loss on the verdict only (`completion_only_loss=True`) |
| Epochs | 1 (18,000 training cases) |
| Learning rate | 1e-4, cosine schedule, 3% warmup |
| Effective batch | 16 (2 per device x 8 gradient accumulation steps) |
| Max sequence length | 3,072 tokens (prompts are about 1,300-2,000 tokens) |
| Checkpoint kept | lowest loss on 300 cases sampled from the `sft` test split, evaluated every 200 steps |

The hardware model and wall-clock time were not logged. The original runbook targeted a single 24 GB GPU
(RTX 4090).

**Checkpoint selection used test cases.** `load_best_model_at_end=True` with `eval_dataset` drawn from the
test split means the kept checkpoint was chosen by loss on 300 test cases. The paper discloses this as a
limitation; a re-run should select on a validation split carved from the training data instead.

```bash
pip install torch transformers peft trl datasets bitsandbytes accelerate
python training/train.py --data sriram1983007/sra-stablecoin-risk-bench
```

Training on a different GPU or library version will not reproduce the weights bit for bit. The published
predictions are what the paper's numbers are computed from.
