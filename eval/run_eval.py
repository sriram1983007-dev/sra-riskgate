#!/usr/bin/env python3
"""Run a model on the sra-stablecoin-risk-bench test split and score it with score.py.

Every model gets the exact training prompts from the dataset's `sft` split (task-specific
system prompt + tagged user message), so all comparisons use identical instructions.

Prompt variants
  training      (default) the exact training prompts, as used for every published run
  spec          the training prompt plus the allowed labels and decision rules published with the
                benchmark (schema/*.json and SPEC.md, see spec_prompt.json). Use this to give general
                models the same rulebook without fine-tuning.

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

  # A reasoning model with the published spec: no temperature, larger output budget
  python run_eval.py --name some-model-spec --backend openai --model provider/model-id \\
      --prompt-variant spec --reasoning low --no-temperature --max-new-tokens 8192

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
import random
from collections import Counter
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


def load_rows(split, limit, bench_file=None, sft_file=None, spec=None, sample=None, seed=0):
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
        if spec is not None:
            task = b.get("task", "risk_gate")
            if task not in spec:
                sys.exit(f"spec prompt has no section for task {task!r}")
            system = system + spec[task]
        rows.append({"id": b["id"], "system": system, "user": user, "gold": b})
        if limit and len(rows) >= limit:
            break
    if sample and sample < len(rows):
        # Stratified by task so the payment/dispute mix matches the full test split.
        rng, by_task = random.Random(seed), {}
        for r in rows:
            by_task.setdefault(r["gold"].get("task", "risk_gate"), []).append(r)
        keep = set()
        for task, group in by_task.items():
            n = round(sample * len(group) / len(rows))
            keep.update(r["id"] for r in rng.sample(group, n))
        rows = [r for r in rows if r["id"] in keep]
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
    def __init__(self, model_id, base_url, api_key, max_new_tokens, workers, extra, temperature=True):
        self.model_id, self.url = model_id, base_url.rstrip("/") + "/chat/completions"
        self.key, self.max_new_tokens, self.workers, self.extra = api_key, max_new_tokens, workers, extra
        self.temperature = temperature
        self.openrouter = "openrouter.ai" in base_url
        self.dtype = "api"
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0, "reasoning_tokens": 0, "cost_usd": 0.0}
        self.finish = Counter()   # finish_reason per row: 'length' means the output budget ran out
        self.failed = 0           # rows that still failed after all retries (scored as invalid)
        self.lock = threading.Lock()

    @staticmethod
    def _text(message):
        c = message.get("content")
        if isinstance(c, list):  # some providers return content parts
            c = "".join(p.get("text", "") for p in c if isinstance(p, dict))
        return c or ""

    def _one(self, r):
        body = {"model": self.model_id, "max_tokens": self.max_new_tokens,
                "messages": [{"role": "system", "content": r["system"]}, {"role": "user", "content": r["user"]}]}
        if self.temperature:
            body["temperature"] = 0
        if self.openrouter:
            body["usage"] = {"include": True}  # OpenRouter reports the cost of each call
        body.update(self.extra)
        data = json.dumps(body).encode()
        for attempt in range(7):
            try:
                req = urllib.request.Request(self.url, data=data, headers={
                    "Content-Type": "application/json", "Authorization": f"Bearer {self.key}",
                    "User-Agent": "sra-riskgate-eval"})  # Runpod's proxy refuses Python-urllib with 403
                with urllib.request.urlopen(req, timeout=300) as resp:
                    j = json.load(resp)
                u = j.get("usage") or {}
                choice = j["choices"][0]
                with self.lock:
                    self.usage["prompt_tokens"] += u.get("prompt_tokens") or 0
                    self.usage["completion_tokens"] += u.get("completion_tokens") or 0
                    self.usage["reasoning_tokens"] += (u.get("completion_tokens_details") or {}).get("reasoning_tokens") or 0
                    self.usage["cost_usd"] += float(u.get("cost") or 0)
                    self.finish[choice.get("finish_reason") or "unknown"] += 1
                return self._text(choice.get("message") or {})
            except urllib.error.HTTPError as e:
                if e.code in (400, 401, 403, 404):  # not retryable: bad model id, key, or request
                    msg = e.read().decode()[:500]
                    hint = (" (if it mentions temperature, rerun with --no-temperature and a new --name)"
                            if e.code == 400 and self.temperature and "temperature" in msg.lower() else "")
                    raise SystemExit(f"API error {e.code}: {msg}{hint}")
                time.sleep(min(60, 2 ** attempt))
            except Exception:
                time.sleep(min(60, 2 ** attempt))
        with self.lock:
            self.failed += 1
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
    ap.add_argument("--max-new-tokens", type=int, default=512,
                    help="output budget; reasoning models count their thinking here, so give them 4096-16384")
    ap.add_argument("--prompt-variant", choices=["training", "spec"], default="training")
    ap.add_argument("--spec-file", default=str(Path(__file__).with_name("spec_prompt.json")))
    ap.add_argument("--reasoning", choices=["default", "off", "low", "medium", "high"], default="default",
                    help="OpenRouter reasoning setting (openai backend); recorded in run_config.json")
    ap.add_argument("--no-temperature", action="store_true",
                    help="omit temperature (some reasoning models reject temperature=0)")
    ap.add_argument("--sample", type=int, help="stratified random subset of N rows (cheaper; not comparable "
                                                  "to full-split numbers)")
    ap.add_argument("--seed", type=int, default=0)
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

    spec = None
    if args.prompt_variant == "spec":
        spec = {k: v for k, v in json.load(open(args.spec_file)).items() if not k.startswith("_")}
    extra = json.loads(args.extra_json)
    if args.reasoning == "off":
        extra.setdefault("reasoning", {"enabled": False})
    elif args.reasoning != "default":
        extra.setdefault("reasoning", {"effort": args.reasoning, "exclude": True})

    # Refuse to resume into a folder made with different settings (it would mix two runs).
    meta = {"model": args.model, "prompt_variant": args.prompt_variant, "split": args.split,
            "sample": args.sample, "seed": args.seed if args.sample else None, "limit": args.limit,
            "max_new_tokens": args.max_new_tokens, "reasoning": args.reasoning,
            "temperature": None if args.no_temperature else 0, "extra": extra}
    meta_path = out / "run_meta.json"
    if meta_path.exists() and json.load(meta_path.open()) != meta:
        sys.exit(f"{out} was started with different settings ({meta_path}); use a new --name.")
    json.dump(meta, meta_path.open("w"), indent=2)

    rows = load_rows(args.split, args.limit, args.bench_file, args.sft_file, spec, args.sample, args.seed)
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
                                    extra, temperature=not args.no_temperature)
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
        prompts = ("exact training prompts from the sft split" if args.prompt_variant == "training" else
                   "training prompts + published spec (labels and decision rules, eval/spec_prompt.json)")
        cfg = {"name": args.name, "model": args.model, "backend": args.backend, "split": args.split,
               "rows": len(rows), "sample": args.sample, "seed": args.seed if args.sample else None,
               "prompt_variant": args.prompt_variant, "prompts": prompts,
               "decoding": "greedy / temperature 0" if not args.no_temperature else "provider default temperature",
               "reasoning": args.reasoning, "max_new_tokens": args.max_new_tokens,
               "dtype": str(backend.dtype), "extra": extra, "seconds": round(time.time() - t0)}
        prev = json.load((out / "run_config.json").open()) if (out / "run_config.json").exists() else {}
        cfg["seconds"] += prev.get("seconds", 0)          # resumed runs add up, never overwrite
        if isinstance(backend, OpenAIBackend):
            usage = dict(backend.usage)
            for k, v in (prev.get("usage") or {}).items():
                usage[k] = usage.get(k, 0) + v
            usage["cost_usd"] = round(usage["cost_usd"], 4)
            finish = Counter(prev.get("finish_reasons") or {})
            finish.update(backend.finish)
            backend.finish = finish
            cfg["usage"], cfg["finish_reasons"] = usage, dict(finish)
            cfg["failed_after_retries"] = backend.failed + prev.get("failed_after_retries", 0)
            if backend.finish.get("length"):
                print(f"WARNING: {backend.finish['length']} rows hit the output budget (finish_reason=length). "
                      "Raise --max-new-tokens or lower --reasoning, and rerun with a new --name.", flush=True)
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
