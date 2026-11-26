"""Helpers shared by the paper's instruments. Standard library only."""
import json
import re


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def parse(text):
    """The first JSON object in a model answer (the published scorer's rule), or None."""
    if isinstance(text, dict):
        return text
    if not isinstance(text, str):
        return None
    text = re.sub(r"```(?:json)?", "", text)
    dec = json.JSONDecoder()
    for m in re.finditer(r"\{", text):
        try:
            obj, _ = dec.raw_decode(text, m.start())
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    return None


def predictions(path):
    return {r["id"]: parse(r["prediction"]) or {} for r in load_jsonl(path)}


def label(row):
    return json.loads(row["label"])


def emit(obj):
    print(json.dumps(obj, indent=2, sort_keys=True))
