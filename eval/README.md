# Evaluation scripts

These scripts produced the published results in
[sra-bench-results](https://huggingface.co/datasets/sriram1983007/sra-bench-results).

- **`run_eval.py`** runs a model on the test split of
  [sra-stablecoin-risk-bench](https://huggingface.co/datasets/sriram1983007/sra-stablecoin-risk-bench)
  using the exact training prompts from its `sft` split, then scores the output with the dataset's
  `score.py`. It supports a local GPU (`--backend transformers`) or any OpenAI-compatible server
  such as vLLM, llama.cpp, Ollama or OpenRouter (`--backend openai`). Runs can be resumed.
- **`make_table.py`** turns `results/*/scores.json` into a Markdown comparison table.

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
