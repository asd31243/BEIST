# BEIST: Behavioural Evidence Integrity and Stress Testing

Reproducible code, derived evidence records, evaluation manifests, result tables, and figures for the BEIST study on auditing evidence support in ransomware sandbox reports.

## Repository contents

- `src/`: deterministic pipeline, analyses, validation, and figure-generation scripts.
- `config/`: frozen BEIST protocol rules.
- `data/`: the 2,000-report evaluation cohort, manifests, derived evidence records, normalized atoms, and perturbation manifests.
- `results/`: machine-readable primary, supplementary, ablation, sensitivity, mutation, and downstream-analysis results.
- `figures/`: generated figures in SVG, PNG, and PDF formats.
- `docs/`: data and reproducibility notes.

The repository contains derived records from the RanDS ransomware dataset. The original RanDS dataset remains subject to its own license and redistribution terms; see `docs/DATA_AND_LICENSES.md`.

## Dataset summary

| Layer | Ransomware | Benign | Ransomware families |
|---|---:|---:|---:|
| Published source dataset | 104,616 | 110,788 | 533 |
| Successful dynamic executions | 51,985 | 30,855 | — |
| Locally eligible JSON reports | 49,066 | 27,697 | 390 |
| Final evaluation cohort | 1,000 | 1,000 | 102 |

The final cohort is fixed by seed `20260912`. SHA-256 values and selection details are stored in `data/sample_manifest.csv`.

## Requirements

Python 3.10 or newer is recommended. Install dependencies with:

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Reproduction

The published derived cohort can be analyzed directly:

```bash
python src/beist_analysis.py
python src/beist_supplementary.py
python src/make_protocol_figures.py
python src/make_chinese_figures.py
```

Outputs are written to `results/` and `figures/`. The pipeline that constructs a new cohort from the full source archive is available as `src/beist_pipeline.py`; it requires a local RanDS archive configured with the `RANDS_BEHAVIOUR_ROOT` environment variable.

The scripts operate on JSON reports and derived records. They do not execute PE binaries.

## Reproducibility records

`results/run_metadata.json` records the protocol version, seed, selected counts, and output hashes. The conformance cases, mutation manifests, and validation tables provide checks for the deterministic protocol implementation.

## Citation

If you use this repository, cite the BEIST paper and the original RanDS dataset paper. A machine-readable citation template is provided in `CITATION.cff`.

## License

Code is released under the MIT License. Derived data are released under the Creative Commons Attribution 4.0 International license where redistribution is permitted. Third-party source data remain governed by their original terms.
