# BEIST: Auditable Evidence Analysis for Ransomware Sandbox Reports

This repository contains the code, frozen configuration, tabular data and machine-readable results used for the BEIST paper.

## Data source

The study uses the source dataset released with **RanDS: A large-Scale open dataset of raw binaries and extracted features for ransomware research**. The original source archive contains the JSON behaviour reports used to construct the evaluation cohort. Those reports are not redistributed here. Users who need the underlying reports should download them from the [original dataset repository](https://ran-ds.com/home) and follow its licence and access conditions. This repository contains only the derived selection table, the frozen protocol configuration, and the published aggregate results.

## Repository contents

- `src/`: deterministic BEIST analysis, supplementary analysis and validation.
- `config/protocol_rules.json`: frozen BEIST capability rules and observability guards.
- `data/sample_manifest.csv`: the fixed 2,000-report evaluation manifest (1,000 benign and 1,000 ransomware), with labels, hashes, metadata, and report-level measures.
- `data/eligibility_selection_table.csv`: row-level eligibility and selection decisions used to construct the final cohort.
- `results/`: primary results, inferential tests, corroboration, fragility, mutation validation, sensitivity analyses, ablations, search-bound validation, volume analysis, and downstream utility results.
- `requirements.txt`: Python dependencies for the analysis scripts.

No raw binaries, raw JSON behaviour reports, or per-report derived evidence records are included.

## Paper-to-artifact map

| Paper content | Released artifact |
|---|---|
| Cohort composition and report structure | `results/overall_summary.json`, `results/year_summary.csv`, `data/sample_manifest.csv` |
| Capability support rates and inferential tests | `results/capability_summary.csv`, `results/capability_inferential_tests.csv` |
| Corroboration analysis | `results/corroboration_summary.csv` |
| Evidence fragility profile | `results/fragility_summary.csv`, `results/fragility_points.csv` |
| Mutation and protocol validation | `results/mutation_validation_results.csv`, `results/mutation_validation_summary.json`, `results/protocol_conformance_results.csv`, `results/protocol_conformance_cases.json` |
| Rule and contradiction sensitivity | `results/sensitivity_analysis.csv`, `results/predicate_sensitivity.csv`, `results/contradiction_sensitivity.csv` |
| Ablation comparison | `results/ablation_summary.csv`, `results/ablation_deletion_comparison.csv` |
| Search-bound validation | `results/efp_search_validation_summary.csv`, `results/efp_search_validation_per_claim.csv`, `results/efp_search_validation_meta.json` |
| Volume and evidentiary-strength analysis | `results/volume_strength_correlations.csv`, `results/volume_strength_quartiles.csv`, `results/volume_strength_extremes.json` |
| Downstream discrimination analysis | `results/downstream_utility.csv` |

The file names in this table identify released artifacts; they are not additional data sources.

## Reproduction

Create a Python 3.10+ environment and install the dependencies:

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
```

After the source archive has been placed locally, the pipeline can regenerate the derived records and the analyses can then be run:

```bash
python src/beist_analysis.py
python src/beist_supplementary.py
```

The cohort-construction script is `src/beist_pipeline.py`. It requires a local copy of the source archive and the corresponding input-root configuration. It parses report data and computes derived evidence. The scripts write regenerated derived records and tables to `data/` and `results/`. The released tables provide the reference outputs.

The frozen run used seed `20260912`, 1,000 reports per label, a balanced 300-report fragility cohort, and 1,437 mutation instances.




