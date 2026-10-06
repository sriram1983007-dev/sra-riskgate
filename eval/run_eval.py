#!/usr/bin/env python3
"""Run a model on the sra-stablecoin-risk-bench test split and score it with score.py.

Every model gets the exact training prompts from the dataset's `sft` split (task-specific
system prompt + tagged user message), so all comparisons use identical instructions.

Backends
  transformers  run a Hugging Face model on a local GPU (e.g. Colab T4/L4/A100)
  openai        any OpenAI-compatible API: OpenRouter, vLLM, llama-server, Ollama, OpenAI, ...

Examples
  # Your model on a Colab GPU
  python run_eval.py --name sra-riskgate-4b --model sriram1983007/SRA-RiskGate-4B

  # The base model, same GPU
  python run_eval.py --name qwen3-4b-instruct-base --model Qwen/Qwen3-4B-Instruct-2507

  # A larger model through OpenRouter (check the exact model id on openrouter.ai/models)
  OPENROUTER_API_KEY=sk-or-... python run_eval.py --name llama-3.3-70b \\
      --backend openai --base-url https://openrouter.ai/api/v1 --api-key-env OPENROUTER_API_KEY \\
      --model meta-llama/llama-3.3-70b-instruct --workers 16

Outputs in results/<name>/
  predictions.jsonl   {"id": ..., "prediction": "<raw model output>"}   (the format score.py reads)
  test.jsonl          gold rows, exactly as score.py expects
  scores.json         full metrics from score.py
  run_config.json     model, backend, decoding settings, dtype, timing
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DATASET = "sriram1983007/sra-stablecoin-risk-bench"
ALIASES = {"human": "user", "gpt": "assistant", "bot": "assistant", "model": "assistant"}


# ---------------------------------------------------------------- prompts
def as_msgs(v):
    if isinstance(v, str) and v.strip().startswith("["):
        try:
            v = json.loads(v)
        except json.JSONDecodeError:
            return None
    if not isinstance(v, list) or not v or not all(isinstance(m, dict) for m in v):
        return None
    out = []
    for m in v:
        role, content = m.get("role", m.get("from")), m.get("content", m.get("value"))
        if role is None or content is None:
            return None
        out.append({"role": ALIASES.get(role, role), "content": content})
    return out


def training_prompt(row):
    """(system, user) exactly as used in training."""
    for key in ("prompt", "messages", "conversations", "chat"):
        msgs = as_msgs(row.get(key))
        if msgs and any(m["role"] == "user" for m in msgs):
            system = next((m["content"] for m in msgs if m["role"] == "system"), "")
            user = next(m["content"] for m in msgs if m["role"] == "user")
            return system, user
    if isinstance(row.get("prompt"), str):
        return row.get("system") or "", row["prompt"]
    return None


def load_rows(split, limit, bench_file=None, sft_file=None):
    if bench_file:
        bench = [json.loads(l) for l in open(bench_file) if l.strip()]
        sft = [json.loads(l) for l in open(sft_file) if l.strip()]
    else:
        from datasets import load_dataset
        bench = [dict(r) for r in load_dataset(DATASET, "benchmark", split=split)]
        sft = [dict(r) for r in load_dataset(DATASET, "sft", split=split)]
    if len(bench) != len(sft):
        sys.exit(f"benchmark has {len(bench)} rows but sft has {len(sft)}; cannot align.")
    sft_by_id = {r["id"]: r for r in sft} if sft and "id" in sft[0] else None

    rows = []
    for i, b in enumerate(bench):
        s = sft_by_id.get(b["id"]) if sft_by_id else sft[i]
        found = training_prompt(s) if s else None
        if not found:
            sys.exit(f"Could not read the training prompt for {b['id']}. sft columns: {list(sft[0])}")
        system, user = found
        # Sanity check: the prompt must describe this benchmark row.
        inp = json.loads(b["input"]) if isinstance(b.get("input"), str) else (b.get("input") or {})
        now = inp.get("now_unix", inp.get("now")) if isinstance(inp, dict) else None
        if now is not None and str(now) not in user:
            sys.exit(f"Row {b['id']}: sft prompt does not match benchmark input (now={now}); splits are misaligned.")
        rows.append({"id": b["id"], "system": system, "user": user, "gold": b})
        if limit and len(rows) >= limit:
            break
    return rows


# ---------------------------------------------------------------- backends
class TransformersBackend:
    def __init__(self, model_id, max_new_tokens, batch_size):
        os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.torch = torch
        # bf16 where the GPU supports it (L4, A100, H100); fp16 on older GPUs such as the T4
        self.dtype = torch.bfloat16 if torch.cuda.is_available() and torch.cuda.is_bf16_supported() else torch.float16
        self.tok = AutoTokenizer.from_pretrained(model_id)
        self.tok.padding_side = "left"
        if self.tok.pad_token is None:
            self.tok.pad_token = self.tok.eos_token
        self.model = AutoModelForCausalLM.from_pretrained(model_id, dtype=self.dtype, device_map="cuda")
        self.model.eval()
        self.max_new_tokens, self.batch_size = max_new_tokens, batch_size

    def _generate(self, batch):
        """Generate for a batch; if it doesn't fit in GPU memory, split it in half and retry."""
        oom = getattr(self.torch, "OutOfMemoryError", None) or self.torch.cuda.OutOfMemoryError
        prompts = [self.tok.apply_chat_template(
            [{"role": "system", "content": r["system"]}, {"role": "user", "content": r["user"]}],
            tokenize=False, add_generation_prompt=True) for r in batch]
        enc = self.tok(prompts, return_tensors="pt", padding=True).to("cuda")
        try:
            with self.torch.no_grad():
                out = self.model.generate(**enc, max_new_tokens=self.max_new_tokens, do_sample=False,
                                          pad_token_id=self.tok.pad_token_id)
        except oom:
            del enc
            self.torch.cuda.empty_cache()
            if len(batch) == 1:
                raise
            mid = len(batch) // 2
            print(f"  (GPU memory full at batch {len(batch)}; splitting into {mid} + {len(batch) - mid})", flush=True)
            return self._generate(batch[:mid]) + self._generate(batch[mid:])
        texts = [self.tok.decode(o[enc.input_ids.shape[1]:], skip_special_tokens=True) for o in out]
        del out, enc
        return list(zip(batch, texts))

    def run(self, rows, on_result):
        # Batch prompts of similar length together: much faster with left padding
        order = sorted(rows, key=lambda r: len(r["user"]))
        for i in range(0, len(order), self.batch_size):
            for r, text in self._generate(order[i:i + self.batch_size]):
                on_result(r["id"], text)


class OpenAIBackend:
    def __init__(self, model_id, base_url, api_key, max_new_tokens, workers, extra):
        self.model_id, self.url = model_id, base_url.rstrip("/") + "/chat/completions"
        self.key, self.max_new_tokens, self.workers, self.extra = api_key, max_new_tokens, workers, extra
        self.dtype = "api"
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0}
        self.lock = threading.Lock()

    def _one(self, r):
        body = {"model": self.model_id, "temperature": 0, "max_tokens": self.max_new_tokens,
                "messages": [{"role": "system", "content": r["system"]}, {"role": "user", "content": r["user"]}],
                **self.extra}
        data = json.dumps(body).encode()
        for attempt in range(7):
            try:
                req = urllib.request.Request(self.url, data=data, headers={
                    "Content-Type": "application/json", "Authorization": f"Bearer {self.key}"})
                with urllib.request.urlopen(req, timeout=300) as resp:
                    j = json.load(resp)
                u = j.get("usage") or {}
                with self.lock:
                    self.usage["prompt_tokens"] += u.get("prompt_tokens", 0)
                    self.usage["completion_tokens"] += u.get("completion_tokens", 0)
                return (j["choices"][0]["message"].get("content") or "")
            except urllib.error.HTTPError as e:
                if e.code in (400, 401, 403, 404):  # not retryable: bad model id, key, or request
                    raise SystemExit(f"API error {e.code}: {e.read().decode()[:500]}")
                time.sleep(min(60, 2 ** attempt))
            except Exception:
                time.sleep(min(60, 2 ** attempt))
        return ""  # recorded as an empty prediction -> scored as invalid, never dropped

    def run(self, rows, on_result):
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futs = {pool.submit(self._one, r): r for r in rows}
            for f in as_completed(futs):
                on_result(futs[f]["id"], f.result())


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True, help="short label for the results folder and table")
    ap.add_argument("--model", required=True)
    ap.add_argument("--backend", choices=["transformers", "openai"], default="transformers")
    ap.add_argument("--base-url", default="https://openrouter.ai/api/v1")
    ap.add_argument("--api-key-env", default="OPENROUTER_API_KEY")
    ap.add_argument("--extra-json", default="{}", help='extra API body fields, e.g. \'{"reasoning": {"enabled": false}}\'')
    ap.add_argument("--workers", type=int, default=8, help="parallel API requests (openai backend)")
    ap.add_argument("--batch-size", type=int, default=8, help="prompts per GPU batch (transformers backend)")
    ap.add_argument("--max-new-tokens", type=int, default=512)
    ap.add_argument("--split", default="test")
    ap.add_argument("--limit", type=int, help="only the first N rows (smoke test / cost check)")
    ap.add_argument("--score-script", default="score.py")
    ap.add_argument("--out-dir", default="results")
    ap.add_argument("--bench-file", help=argparse.SUPPRESS)  # local testing only
    ap.add_argument("--sft-file", help=argparse.SUPPRESS)
    args = ap.parse_args()

    out = Path(args.out_dir) / args.name
    out.mkdir(parents=True, exist_ok=True)
    pred_path, gold_path = out / "predictions.jsonl", out / "test.jsonl"

    rows = load_rows(args.split, args.limit, args.bench_file, args.sft_file)
    with gold_path.open("w") as f:
        for r in rows:
            f.write(json.dumps(r["gold"]) + "\n")

    done = set()
    if pred_path.exists():  # resume after an interruption
        done = {json.loads(l)["id"] for l in pred_path.open() if l.strip()}
    todo = [r for r in rows if r["id"] not in done]
    print(f"{len(rows)} rows | {len(done)} already done | {len(todo)} to run", flush=True)

    if todo:
        if args.backend == "transformers":
            backend = TransformersBackend(args.model, args.max_new_tokens, args.batch_size)
        else:
            key = os.environ.get(args.api_key_env)
            if not key:
                sys.exit(f"Set the {args.api_key_env} environment variable first.")
            backend = OpenAIBackend(args.model, args.base_url, key, args.max_new_tokens, args.workers,
                                    json.loads(args.extra_json))
        lock, count, t0 = threading.Lock(), [0], time.time()
        with pred_path.open("a") as f:
            def on_result(rid, text):
                with lock:
                    f.write(json.dumps({"id": rid, "prediction": text}) + "\n")
                    f.flush()
                    count[0] += 1
                    if count[0] % 25 == 0 or count[0] == len(todo):
                        el = time.time() - t0
                        print(f"  {count[0]}/{len(todo)}  ({el / count[0]:.2f}s/row, ~{el / count[0] * (len(todo) - count[0]) / 60:.0f} min left)", flush=True)
            backend.run(todo, on_result)
        cfg = {"name": args.name, "model": args.model, "backend": args.backend, "split": args.split,
               "rows": len(rows), "decoding": "greedy / temperature 0", "max_new_tokens": args.max_new_tokens,
               "dtype": str(backend.dtype), "prompts": "exact training prompts from the sft split",
               "extra": json.loads(args.extra_json), "seconds": round(time.time() - t0)}
        if isinstance(backend, OpenAIBackend):
            cfg["usage"] = backend.usage
        json.dump(cfg, (out / "run_config.json").open("w"), indent=2)

    if not Path(args.score_script).exists():
        sys.exit(f"Done. score.py not found; run: python score.py --gold {gold_path} --pred {pred_path}")
    res = subprocess.run([sys.executable, args.score_script, "--gold", str(gold_path), "--pred", str(pred_path),
                          "--out", str(out / "scores.json")], capture_output=True, text=True)
    if res.returncode:
        sys.exit(res.stderr)
    m = json.load((out / "scores.json").open())
    rg, dp = m.get("risk_gate", {}), m.get("dispute", {})
    print(f"\n=== {args.name} ===")
    print(f"SRA score              {m['sra_score']}")
    print(f"Risk-gate accuracy     {rg.get('decision_accuracy')}   unsafe approvals {rg.get('unsafe_approval_rate')}   over-blocking {rg.get('over_blocking_rate')}")
    print(f"Dispute score          {dp.get('dispute_score')}   impossible remedies {dp.get('impossible_remedy_rate')}   wrongful refunds {dp.get('wrongful_refund_rate')}")
    print(f"Schema valid           risk {rg.get('schema_valid_rate')}   dispute {dp.get('schema_valid_rate')}")
    print(f"Full metrics: {out / 'scores.json'}")


if __name__ == "__main__":
    main()
