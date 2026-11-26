"""Download the published files the paper's instruments read, into paper/data/ (not committed).

    python paper/fetch_data.py

Every file is public on the Hugging Face Hub. Each results file records the sha256 of every input it read,
so a later run on different files is detected (`osaudit results --inputs`).
"""
from pathlib import Path

from huggingface_hub import hf_hub_download

OUT = Path(__file__).resolve().parent / "data"
FILES = {
    "sriram1983007/sra-bench-results": [
        f"{run}/scores.json" for run in ("qwen3-4b-instruct-base", "sra-riskgate-4b", "sra-riskgate-4b-v2",
                                          "sra-riskgate-4b-v2-no-window", "sra-riskgate-4b-q8_0",
                                          "sra-riskgate-4b-q4_k_m")
    ] + [f"{run}/predictions.jsonl" for run in ("sra-riskgate-4b", "sra-riskgate-4b-v2", "sra-riskgate-4b-q4_k_m")]
      + [f"sra-real-v1/{run}/scores.json" for run in ("qwen3-4b-instruct-base", "sra-riskgate-4b-v1",
                                                      "sra-riskgate-4b-v2")]
      + ["sra-real-v1/summary.json"],
    "sriram1983007/sra-stablecoin-risk-bench": ["data/benchmark/test.jsonl", "data/benchmark/train.jsonl"],
    "sriram1983007/sra-real-world-poisoning": ["attacks.csv", "normal.csv", "summary.json",
                                               "model_eval/model_summary.json"],
}

for repo, files in FILES.items():
    for f in files:
        path = hf_hub_download(repo, f, repo_type="dataset", local_dir=OUT / repo.split("/")[1])
        print(path)
