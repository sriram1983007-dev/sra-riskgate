# Evaluation scripts

These scripts produced the published results in
[sra-bench-results](https://huggingface.co/datasets/sriram1983007/sra-bench-results).

- **`run_eval.py`** runs a model on the test split of
  [sra-stablecoin-risk-bench](https://huggingface.co/datasets/sriram1983007/sra-stablecoin-risk-bench)
  using the exact training prompts from its `sft` split, then scores the output with the dataset's
  `score.py`. It supports a local GPU (`--backend transformers`) or any OpenAI-compatible server
  such as vLLM, llama.cpp, Ollama or OpenRouter (`--backend openai`). Runs can be resumed.
- **`make_table.py`** turns `results/*/scores.json` into a Markdown (and optional CSV) comparison table,
  including the prompt track and API cost of each run.
- **`spec_prompt.json`** is the text added to the system prompt with `--prompt-variant spec`: the allowed
  labels (from the dataset's `schema/*.json`) and the decision rules (from its `SPEC.md`). It contains
  nothing from the private generator.

## Comparing general-purpose models fairly

SRA-RiskGate-4B learned the label vocabulary (reason codes, dispute outcomes) during training; a general
model reading only the training prompt cannot know it. So every model can be run in two tracks:

| Track | Flag | What the model gets |
|---|---|---|
| Drop-in | `--prompt-variant training` (default) | The exact training prompt, as used for every published run |
| With the spec | `--prompt-variant spec` | The training prompt plus the published labels and decision rules |

The safety metrics (unsafe approvals, over-blocking, injected payments approved) do not depend on the
label vocabulary, so they are comparable across tracks.

Reasoning models count their thinking against the output budget and some reject `temperature=0`:

```bash
python run_eval.py --name some-reasoner-spec --backend openai --model provider/model-id \
    --prompt-variant spec --reasoning low --no-temperature --max-new-tokens 8192 --workers 16
```

`run_config.json` records the prompt track, reasoning setting, token usage, OpenRouter cost and how many
rows ran out of output budget (`finish_reasons`). A run folder refuses to resume with different settings.
`--sample N` runs a stratified subset for a cheap check; sampled numbers are not comparable to full runs.

## Example (vLLM)

```bash
pip install vllm datasets
hf download sriram1983007/sra-stablecoin-risk-bench score.py --repo-type dataset --local-dir .

vllm serve sriram1983007/SRA-RiskGate-4B --served-model-name sra-riskgate-4b \
    --dtype half --max-model-len 12288 --port 8000 &

export VLLM_KEY=none
python run_eval.py --name sra-riskgate-4b --backend openai \
    --base-url http://localhost:8000/v1 --api-key-env VLLM_KEY \
    --model sra-riskgate-4b --workers 32

python make_table.py
```

Outputs go to `results/<name>/`: `predictions.jsonl`, `test.jsonl`, `scores.json` and `run_config.json`.
