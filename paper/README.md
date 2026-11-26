# Paper

`main.tex` and `references.bib` are the source of `SRA-RiskGate-paper.pdf`.

## Every number, traced

The repository passes [osaudit](https://github.com/ASSERT-KTH/osaudit) (`osaudit.toml` at the root): every
number printed in `main.tex` is a value in a results file under `results/`, a derivation from one, or an
allowed number with its reason (a standard's name such as EIP-3009, a year, a training setting).

Each results file is written by an instrument in `study/` through `osaudit run`, which records the command,
the commit, and the SHA-256 of every input:

| Results file | Instrument | Inputs |
| --- | --- | --- |
| `results/benchmark.json` | `study/benchmark.py` | published `scores.json` of every run (sra-bench-results) |
| `results/failures.json` | `study/failures.py` | benchmark test and train splits, published predictions of v1, v2 and Q4_K_M |
| `results/real_world.json` | `study/real_world.py` | `attacks.csv`, `normal.csv` and summaries of sra-real-world-poisoning |
| `results/library.json` | `study/library.py` | the library's own source (guard benchmark, self-check, OWASP coverage) |

To recompute everything and re-run the audit (needs [uv](https://docs.astral.sh/uv/); downloads about 90 MB
of public data into `data/`, which is not committed):

```bash
bash paper/run_study.sh
```

To check the recorded results without re-running them: `osaudit`; to also check the inputs' SHA-256:
`osaudit results --inputs` after `python paper/fetch_data.py`; to re-run every instrument and compare:
`osaudit results --rerun`.

## Build the PDF

```bash
cd paper && latexmk -pdf main.tex
```
