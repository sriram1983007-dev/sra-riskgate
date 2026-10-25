from __future__ import annotations
#!/usr/bin/env python3
"""
Fine-tune a small Apache-2.0 model as an SRA payment risk gate.

    python scripts/train.py --data your-username/sra-stablecoin-risk-bench     # from the Hub
    python scripts/train.py --data data/full                                   # from local files
    python scripts/train.py --data data/full --model <other-base> --no-4bit    # bf16 LoRA (>=40 GB GPU)

Defaults: QLoRA r=32 on all projections, 1 epoch, max_length 3072, loss on the verdict only.
"""
import argparse
from pathlib import Path

import torch
from datasets import load_dataset
from peft import LoraConfig
import transformers
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import SFTConfig, SFTTrainer

ap = argparse.ArgumentParser()
ap.add_argument("--model", default="Qwen/Qwen3-4B-Instruct-2507",
                help="Any chat model with a chat template. Newer small Apache-2.0 models (e.g. Qwen3.5, "
                     "Gemma 4 small variants) also work; check the exact repo id on the Hub.")
ap.add_argument("--data", required=True, help="Hub dataset repo id or local dir with sft_*.jsonl")
ap.add_argument("--out", default="checkpoints/sra-risk-gate")
ap.add_argument("--epochs", type=float, default=1.0)
ap.add_argument("--lr", type=float, default=1e-4)
ap.add_argument("--max-length", type=int, default=3072)
ap.add_argument("--eval-samples", type=int, default=300)
ap.add_argument("--no-4bit", action="store_true")
a = ap.parse_args()

if Path(a.data).is_dir():
    ds = load_dataset("json", data_files={"train": f"{a.data}/sft_train.jsonl", "test": f"{a.data}/sft_test.jsonl"})
else:
    ds = load_dataset(a.data, "sft")
eval_ds = ds["test"].shuffle(seed=0).select(range(min(a.eval_samples, len(ds["test"]))))

tok = AutoTokenizer.from_pretrained(a.model)
if tok.pad_token is None or tok.pad_token_id == tok.eos_token_id:
    raise SystemExit("Tokenizer needs a pad token distinct from EOS; set one for this model before training.")
tok.padding_side = "right"

quant = None if a.no_4bit else BitsAndBytesConfig(
    load_in_4bit=True, bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
model = AutoModelForCausalLM.from_pretrained(a.model, quantization_config=quant,
                                             dtype=torch.bfloat16, device_map="auto")

peft_config = LoraConfig(
    r=32, lora_alpha=64, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"])

# transformers 5 folded warmup_ratio into warmup_steps (a float < 1 is read as a ratio).
WARMUP = ({"warmup_steps": 0.03} if int(transformers.__version__.split(".")[0]) >= 5
          else {"warmup_ratio": 0.03})

args = SFTConfig(
    output_dir=a.out,
    num_train_epochs=a.epochs,
    per_device_train_batch_size=2,
    gradient_accumulation_steps=8,          # effective batch 16
    learning_rate=a.lr,
    lr_scheduler_type="cosine",
    **WARMUP,
    bf16=True,
    gradient_checkpointing=True,
    max_length=a.max_length,                # prompts are ~1.3k-2k tokens; nothing should truncate
    completion_only_loss=True,              # learn the verdict, not the payload
    eval_strategy="steps", eval_steps=200,
    save_strategy="steps", save_steps=200, save_total_limit=2,
    load_best_model_at_end=True, metric_for_best_model="eval_loss",
    logging_steps=10,
    report_to="none",
)

trainer = SFTTrainer(model=model, args=args, train_dataset=ds["train"], eval_dataset=eval_ds,
                     peft_config=peft_config, processing_class=tok)

# Pre-flight: check for truncation and confirm only the verdict is trained on.
lengths = [len(x["input_ids"]) for x in trainer.train_dataset.select(range(200))]
print(f"token length sample: max {max(lengths)}, mean {sum(lengths) / len(lengths):.0f} (limit {a.max_length})")
ex = trainer.train_dataset[0]
if "completion_mask" in ex:
    print(f"trained tokens in sample 0: {sum(ex['completion_mask'])} of {len(ex['input_ids'])}")

trainer.train()
trainer.model.save_pretrained(f"{a.out}/final_adapter")
tok.save_pretrained(f"{a.out}/final_adapter")
print(f"Adapter saved to {a.out}/final_adapter. Next: python scripts/evaluate_model.py --adapter {a.out}/final_adapter")
