from __future__ import annotations

import csv
import hashlib
import itertools
import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
import numpy as np
from scipy.stats import spearmanr
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    brier_score_loss,
    log_loss,
    roc_auc_score,
    cohen_kappa_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

SRC = Path(__file__).resolve().parent
ROOT = SRC.parents[1]
NEW = ROOT / "data"
EXP = ROOT
RES = EXP / "results"
FIG = ROOT / "figures"
SEED = 20260912
CAPS = [
    "file_impact", "backup_impairment", "persistence",
    "privilege_manipulation", "process_interference", "network_staging",
    "execution_proxy", "anti_analysis", "ransomware_impact",
]

sys.path.insert(0, str(SRC))
import beist_pipeline as bp 


def configure_cjk_font() -> None:
    """Register a bundled Windows CJK font so publication PNG/SVG labels render."""
    candidates = [Path(r"C:\Windows\Fonts\msyh.ttc"), Path(r"C:\Windows\Fonts\simhei.ttf"), Path(r"C:\Windows\Fonts\NotoSansSC-VF.ttf")]
    for candidate in candidates:
        if candidate.is_file():
            font_manager.fontManager.addfont(str(candidate))
            family = font_manager.FontProperties(fname=str(candidate)).get_name()
            plt.rcParams.update({"font.family": family, "font.sans-serif": [family, "DejaVu Sans"], "axes.unicode_minus": False})
            return
    plt.rcParams.update({"font.sans-serif": ["DejaVu Sans"], "axes.unicode_minus": False})


def load_suite() -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    rows = list(csv.DictReader((NEW / "sample_manifest.csv").open(encoding="utf-8-sig", newline="")))
    records: Dict[str, Dict[str, Any]] = {}
    raw: Dict[str, Dict[str, Any]] = {}
    atoms: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        sha = row["sha256"]
        records[sha] = json.loads((NEW / "evidence_records" / f"{sha}.json").read_text(encoding="utf-8"))
        raw[sha] = json.loads((NEW / row["raw_report"]).read_text(encoding="utf-8"))
        atom_path = NEW / "normalized_atoms" / f"{sha}.json"
        atoms[sha] = json.loads(atom_path.read_text(encoding="utf-8"))
    return rows, records, raw, atoms


def write_csv(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(dict.fromkeys(key for row in rows for key in row.keys()))
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def save_svg_first(fig, stem: str) -> None:
    """Save the SVG manuscript source, a vector companion, and a PNG preview."""
    FIG.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIG / f"{stem}.svg", bbox_inches="tight")
    fig.savefig(FIG / f"{stem}_svg-raw.pdf", format="pdf", bbox_inches="tight")
    fig.savefig(FIG / f"{stem}.png", dpi=220, bbox_inches="tight")


def make_volume_figure(rows, records) -> None:
    report_rows = []
    for row in rows:
        strength = record_strength(records[row["sha256"]])
        report_rows.append({"label": row["label"], "atom_count": float(row["atom_count"]), **strength})
    for suffix, title, xlabel, ylabel, legend in [
        ("", "Report volume and corroboration", "log10(atom count + 1)", "Corroboration rate", ("Benign", "Ransomware")),
        ("_zh", "报告体量与佐证率", "log10(原子数 + 1)", "佐证率", ("良性", "勒索软件")),
    ]:
        fig, ax = plt.subplots(figsize=(7.5, 4.5), constrained_layout=True)
        for label, color, name in [("benign", "#2F6B9A", legend[0]), ("ransomware", "#C4553D", legend[1])]:
            vals = [r for r in report_rows if r["label"] == label and np.isfinite(r["corroboration_rate"])]
            ax.scatter(np.log10(np.asarray([r["atom_count"] for r in vals]) + 1), [r["corroboration_rate"] for r in vals], s=12, alpha=0.35, label=name, color=color)
        ax.set_title(title); ax.set_xlabel(xlabel); ax.set_ylabel(ylabel); ax.set_ylim(-0.05, 1.05); ax.grid(alpha=.2); ax.legend(frameon=False, markerscale=2)
        save_svg_first(fig, f"fig4_volume_strength{suffix}"); plt.close(fig)


def make_downstream_figure() -> None:
    path = RES / "downstream_utility.csv"
    rows = list(csv.DictReader(path.open(encoding="utf-8-sig", newline="")))
    aucs = [float(row["roc_auc"]) for row in rows if row.get("feature_set")][:3]
    for suffix, names, ylabel, title in [
        ("", ["Volume", "Volume + binary", "Volume + BEIST"], "Out-of-fold AUROC", "Downstream discrimination analysis"),
        ("_zh", ["仅体量", "体量 + 二值支持", "体量 + BEIST"], "折外 AUROC", "下游区分分析"),
    ]:
        fig, ax = plt.subplots(figsize=(7.5, 4.2), constrained_layout=True)
        bars = ax.bar(names, aucs, color=["#8BA6B8", "#6F8FA6", "#C4553D"])
        for bar, value in zip(bars, aucs):
            ax.text(bar.get_x() + bar.get_width()/2, value + .008, f"{value:.4f}", ha="center", va="bottom", fontsize=9)
        ax.set_ylim(0.45, 1.0); ax.set_ylabel(ylabel); ax.set_title(title); ax.grid(axis="y", alpha=.2)
        save_svg_first(fig, f"fig6_downstream_utility{suffix}"); plt.close(fig)


def wilson(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    if n <= 0:
        return (float("nan"), float("nan"))
    p = k / n
    den = 1 + z * z / n
    mid = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return mid - half, mid + half


def bootstrap_stat(values: Sequence[float], statistic, seed: int, n_boot: int = 1000) -> Tuple[float, float]:
    vals = np.asarray(values, dtype=float)
    if len(vals) < 3:
        return (float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    estimates = []
    for _ in range(n_boot):
        sample = rng.choice(vals, size=len(vals), replace=True)
        estimates.append(float(statistic(sample)))
    return float(np.quantile(estimates, 0.025)), float(np.quantile(estimates, 0.975))


def record_strength(record: Dict[str, Any]) -> Dict[str, float]:
    corr = record["corroboration"]
    supported = int(corr["supported_claims"])
    corroborated = int(corr["corroborated_claims"])
    single = int(corr["single_field_supported_claims"])
    fields = [
        len(record["capabilities"][cap].get("support_fields", []))
        for cap in CAPS if record["capabilities"][cap]["state"] == "S"
    ]
    return {
        "supported_claims": supported,
        "corroborated_claims": corroborated,
        "single_field_claims": single,
        "corroboration_rate": corroborated / supported if supported else float("nan"),
        "single_field_rate": single / supported if supported else float("nan"),
        "mean_support_fields": float(np.mean(fields)) if fields else float("nan"),
        "any_fragility_computed": float(any(record.get("fragility_profile", {}).get(c, {}).get("pareto_minimal") for c in CAPS)),
    }


def run_ablation(rows, records) -> None:
    """Quantify what is lost when BEIST distinctions are collapsed."""
    methods = {
        "full_beist": lambda cap, rec, row: rec["capabilities"][cap]["state"],
        "naive_two_state": lambda cap, rec, row: "S" if rec["capabilities"][cap]["state"] == "S" else "N",
        "report_guard_only": lambda cap, rec, row: (
            "S" if rec["capabilities"][cap]["state"] == "S"
            else ("N" if float(row["readiness"]) >= bp.RULES["assessability"]["readiness_threshold"] else "I")
        ),
    }
    out = []
    for method, state_fn in methods.items():
        counts = {s: 0 for s in "SNI"}
        full_i_to_n = 0
        for row in rows:
            rec = records[row["sha256"]]
            for cap in CAPS:
                state = state_fn(cap, rec, row)
                counts[state] += 1
                full_i_to_n += int(rec["capabilities"][cap]["state"] == "I" and state == "N")
        out.append({
            "method": method,
            "supported_claim_states": counts["S"],
            "not_supported_states": counts["N"],
            "indeterminate_states": counts["I"],
            "full_beist_indeterminate_claims_mapped_to_N": full_i_to_n,
            "state_space": "S/N/I" if method == "full_beist" or method == "report_guard_only" else "S/N",
            "corroboration": "independent fields retained" if method == "full_beist" else "not used",
            "provenance": "claim paths retained" if method == "full_beist" else "not retained by baseline",
            "fragility": "bounded EFP" if method == "full_beist" else "not computed",
        })
    write_csv(RES / "ablation_summary.csv", out)

    validation_path = RES / "mutation_validation_results.csv"
    deletion = []
    if validation_path.is_file():
        for row in csv.DictReader(validation_path.open(encoding="utf-8-sig", newline="")):
            if row["operation"] != "delete_critical_atom":
                continue
            baseline = json.loads(row["baseline_states"])
            raw_after = json.loads(row["parser_states_before_missingness_guard"])
            affected = [c for c in row["affected_capabilities"].split(";") if c]
            for cap in affected:
                if baseline.get(cap) == "S" and raw_after.get(cap) != "S":
                    deletion.append({
                        "method": "naive_two_state",
                        "cases": 1,
                        "declared_missingness_to_I": 0,
                        "false_negative_N": 1,
                    })
                    deletion.append({
                        "method": "beist_core_without_fault_context",
                        "cases": 1,
                        "declared_missingness_to_I": int(raw_after.get(cap) == "I"),
                        "false_negative_N": int(raw_after.get(cap) == "N"),
                    })
                    deletion.append({
                        "method": "beist_with_declared_fault_context",
                        "cases": 1,
                        "declared_missingness_to_I": 1,
                        "false_negative_N": 0,
                    })
    grouped = []
    for method in ["naive_two_state", "beist_core_without_fault_context", "beist_with_declared_fault_context"]:
        vals = [r for r in deletion if r["method"] == method]
        grouped.append({
            "method": method,
            "disrupted_supported_claims": len(vals),
            "mapped_to_I": sum(r["declared_missingness_to_I"] for r in vals),
            "mapped_to_N": sum(r["false_negative_N"] for r in vals),
            "false_negative_rate": sum(r["false_negative_N"] for r in vals) / len(vals) if vals else "NA",
            "interpretation": "known record-loss stress test; not execution-level ground truth",
        })
    write_csv(RES / "ablation_deletion_comparison.csv", grouped)


def variant_support(cap: str, atoms: Sequence[Dict[str, Any]], data: Dict[str, Any], scenario: str) -> bool:
    cfg = bp.CAPABILITIES[cap]
    threshold_file = 10
    threshold_impact = 20
    if scenario == "file_events_5":
        threshold_file = 5
    elif scenario == "file_events_20":
        threshold_file = 20
    elif scenario == "impact_events_10":
        threshold_impact = 10
    elif scenario == "impact_events_40":
        threshold_impact = 40
    if cap == "file_impact":
        fields = [f for f in ["created_files", "deleted_files", "changed_files", "accessed_files"] if bp.values_for(data, f)]
        return len(fields) >= 2 or sum(len(bp.values_for(data, f)) for f in fields) >= threshold_file
    if cap == "network_staging":
        net = bool(bp.values_for(data, "network_traffic_ips") or bp.values_for(data, "network_dns_lookups"))
        if scenario == "network_no_file_staging":
            return net and bool(bp.values_for(data, "executed_commands") or bp.values_for(data, "created_process"))
        return net and bool(bp.values_for(data, "executed_commands") or bp.values_for(data, "created_process") or bp.values_for(data, "created_files"))
    if cap == "ransomware_impact":
        file_fields = [f for f in ["created_files", "deleted_files", "changed_files", "accessed_files"] if bp.values_for(data, f)]
        file_ok = len(file_fields) >= 2 or sum(len(bp.values_for(data, f)) for f in file_fields) >= threshold_file
        backup_tokens = cfg["tokens"]
        if scenario == "tokens_minus_20pct":
            backup_tokens = [t for i, t in enumerate(backup_tokens) if i % 5 != 4]
        backup = bp.matching_atoms(atoms, bp.CAPABILITIES["backup_impairment"]["fields"], backup_tokens)
        file_count = sum(len(bp.values_for(data, f)) for f in ["created_files", "deleted_files", "changed_files"])
        return file_ok and (bool(backup) or file_count >= threshold_impact)
    tokens = cfg["tokens"]
    if scenario == "tokens_minus_20pct" and tokens:
        tokens = [t for i, t in enumerate(tokens) if i % 5 != 4]
    return bool(bp.matching_atoms(atoms, cfg["fields"], tokens))


def variant_state(cap: str, atoms: Sequence[Dict[str, Any]], data: Dict[str, Any], scenario: str) -> str:
    rough = bp.rough_features(data)
    if scenario == "frozen":
        return bp.assess_state(cap, atoms, data, rough)[0]
    if variant_support(cap, atoms, data, scenario):
        return "S"
    observed = bp.atom_texts(atoms, bp.CAPABILITIES[cap]["fields"])
    observed_fields = {a["field"] for a in observed}
    guard = bp.CAPABILITY_OBSERVABILITY[cap]
    if len(observed_fields) >= guard["min_fields"] and len(observed) >= guard["min_atoms"] and rough["readiness"] >= bp.RULES["assessability"]["readiness_threshold"]:
        return "N"
    return "I"


def run_predicate_sensitivity(rows, records, raw, atoms) -> None:
    scenarios = ["frozen", "file_events_5", "file_events_20", "impact_events_10", "impact_events_40", "network_no_file_staging", "tokens_minus_20pct"]
    out = []
    for scenario in scenarios:
        for label in ["benign", "ransomware"]:
            subset = [r for r in rows if r["label"] == label]
            for cap in CAPS:
                states = [variant_state(cap, atoms[r["sha256"]]["atoms"], raw[r["sha256"]], scenario) for r in subset]
                frozen = [records[r["sha256"]]["capabilities"][cap]["state"] for r in subset]
                agreement = sum(a == b for a, b in zip(states, frozen)) / len(states)
                out.append({
                    "scenario": scenario,
                    "label": label,
                    "capability": cap,
                    "supported_rate": states.count("S") / len(states),
                    "not_supported_rate": states.count("N") / len(states),
                    "indeterminate_rate": states.count("I") / len(states),
                    "support_rate_delta_from_frozen": states.count("S") / len(states) - frozen.count("S") / len(frozen),
                    "state_agreement": agreement,
                    "state_kappa": cohen_kappa_score(frozen, states),
                })
    write_csv(RES / "predicate_sensitivity.csv", out)


def candidate_profile(data, record, cap: str, one_prefix: int, pair_prefix: int, exhaustive: bool, cache: Dict[Tuple[Tuple[str, int], ...], Dict[str, str]]) -> List[Dict[str, Any]]:
    baseline = {c: record["capabilities"][c]["state"] for c in CAPS}
    if baseline[cap] != "S":
        return []
    support_ids = set(record["capabilities"][cap].get("support_atom_ids", []))
    atoms = [a for a in bp.atomize(data) if a["atom_id"] in support_ids]
    atoms = sorted(atoms, key=lambda a: (a["environment_dependent"], a["atom_id"]))
    singles = atoms if exhaustive else atoms[:one_prefix]
    pair_atoms = atoms if exhaustive else atoms[:pair_prefix]
    combos = [(a,) for a in singles]
    combos.extend(itertools.combinations(pair_atoms, 2))
    points = []
    for combo in combos:
        keys = tuple(sorted(bp.atom_key(a) for a in combo))
        if keys not in cache:
            cache[keys] = bp.recompute_after_removal(data, set(keys))
        states = cache[keys]
        if states[cap] == "S":
            continue
        collateral = sum(1 for other in CAPS if other != cap and baseline[other] == "S" and states[other] != "S")
        points.append({
            "removed_atom_ids": [a["atom_id"] for a in combo],
            "cost_vector": [len(combo), len({a["field"] for a in combo}), collateral],
            "target_after": states[cap],
        })
    return bp.pareto_minimal(points)


def run_efp_search_validation(rows, records, raw) -> None:
    import itertools
    sample = [r for r in rows if r["label"] == "benign"][:50] + [r for r in rows if r["label"] == "ransomware"][:50]
    bounds = [(5, 4), (10, 6), (20, 10)]
    claim_rows = []
    excluded = 0
    for row in sample:
        sha = row["sha256"]
        data = raw[sha]
        rec = records[sha]
        for cap in CAPS:
            if rec["capabilities"][cap]["state"] != "S":
                continue
            support_n = len(rec["capabilities"][cap].get("support_atom_ids", []))
            if support_n > 30:
                excluded += 1
                continue
            cache: Dict[Tuple[Tuple[str, int], ...], Dict[str, str]] = {}
            exhaustive = candidate_profile(data, rec, cap, 0, 0, True, cache)
            exhaustive_vectors = {tuple(p["cost_vector"]) for p in exhaustive}
            exhaustive_min = min((p["cost_vector"][0] for p in exhaustive), default=None)
            for one, pair in bounds:
                bound = candidate_profile(data, rec, cap, one, pair, False, cache)
                vectors = {tuple(p["cost_vector"]) for p in bound}
                bound_min = min((p["cost_vector"][0] for p in bound), default=None)
                claim_rows.append({
                    "sha256": sha,
                    "label": row["label"],
                    "capability": cap,
                    "support_atom_count": support_n,
                    "bound": f"{one}/{pair}",
                    "exhaustive_order2_disruption": int(bool(exhaustive)),
                    "bounded_disruption": int(bool(bound)),
                    "minimum_atom_cost_exhaustive": exhaustive_min if exhaustive_min is not None else "NA",
                    "minimum_atom_cost_bounded": bound_min if bound_min is not None else "NA",
                    "minimum_cost_agreement": int(exhaustive_min == bound_min) if exhaustive_min is not None else "NA",
                    "pareto_vector_recall": len(vectors & exhaustive_vectors) / len(exhaustive_vectors) if exhaustive_vectors else "NA",
                })
    write_csv(RES / "efp_search_validation_per_claim.csv", claim_rows)
    summary = []
    for bound in [f"{a}/{b}" for a, b in bounds]:
        subset = [r for r in claim_rows if r["bound"] == bound]
        for cap in CAPS:
            vals = [r for r in subset if r["capability"] == cap]
            ex = [r for r in vals if r["exhaustive_order2_disruption"]]
            found = [r for r in ex if r["bounded_disruption"]]
            agreements = [r for r in ex if r["minimum_cost_agreement"] is not None and r["minimum_cost_agreement"] != "NA"]
            recalls = [float(r["pareto_vector_recall"]) for r in ex if r["pareto_vector_recall"] != "NA"]
            summary.append({
                "bound": bound,
                "capability": cap,
                "claims_evaluated": len(vals),
                "exhaustive_order2_disruptions": len(ex),
                "bounded_disruptions": len(found),
                "disruption_recall": len(found) / len(ex) if ex else "NA",
                "minimum_atom_cost_agreement": sum(int(r["minimum_cost_agreement"]) for r in agreements) / len(agreements) if agreements else "NA",
                "pareto_vector_recall_mean": float(np.mean(recalls)) if recalls else "NA",
            })
    write_csv(RES / "efp_search_validation_summary.csv", summary)
    (RES / "efp_search_validation_meta.json").write_text(json.dumps({
        "reports_per_label": 50,
        "reports_total": len(sample),
        "max_support_atoms_for_exhaustive_order2": 30,
        "excluded_supported_claims_with_more_than_30_atoms": excluded,
        "exhaustive_definition": "all one- and two-atom deletions among the support atoms; higher-order disruptions are outside this validation",
        "bounded_definitions": {"5/4": "five singletons plus pairs among four atoms", "10/6": "ten singletons plus pairs among six atoms", "20/10": "twenty singletons plus pairs among ten atoms"},
    }, ensure_ascii=False, indent=2), encoding="utf-8")


def run_volume_analysis(rows, records) -> None:
    report_rows = []
    claim_rows = []
    for row in rows:
        sha = row["sha256"]
        rec = records[sha]
        strength = record_strength(rec)
        raw_size = (NEW / row["raw_report"]).stat().st_size
        report = {"sha256": sha, "label": row["label"], "atom_count": float(row["atom_count"]), "json_bytes": raw_size, "readiness": float(row["readiness"]), **strength}
        report_rows.append(report)
        for cap in CAPS:
            c = rec["capabilities"][cap]
            if c["state"] == "S":
                claim_rows.append({"sha256": sha, "label": row["label"], "capability": cap, "atom_count": float(row["atom_count"]), "json_bytes": raw_size, "corroborated": int(c.get("corroborated", False)), "support_field_count": len(c.get("support_fields", []))})

    corr_rows = []
    for scope, subset in [("all", report_rows), ("benign", [r for r in report_rows if r["label"] == "benign"]), ("ransomware", [r for r in report_rows if r["label"] == "ransomware"])]:
        for predictor in ["atom_count", "json_bytes", "readiness"]:
            for outcome in ["corroboration_rate", "single_field_rate", "mean_support_fields"]:
                vals = [r for r in subset if np.isfinite(r[outcome])]
                x = [r[predictor] for r in vals]
                y = [r[outcome] for r in vals]
                rho, p = spearmanr(x, y) if len(vals) >= 4 and len(set(x)) > 1 and len(set(y)) > 1 else (float("nan"), float("nan"))
                ci = bootstrap_stat(np.arange(len(vals)), lambda idx: spearmanr(np.asarray(x, dtype=float)[idx.astype(int)], np.asarray(y, dtype=float)[idx.astype(int)])[0], SEED + len(corr_rows), 500) if np.isfinite(rho) else (float("nan"), float("nan"))
                corr_rows.append({"scope": scope, "predictor": predictor, "outcome": outcome, "n": len(vals), "spearman_rho": rho, "p_value": p, "bootstrap_ci_low": ci[0], "bootstrap_ci_high": ci[1]})
    for scope, subset in [("all", claim_rows), ("benign", [r for r in claim_rows if r["label"] == "benign"]), ("ransomware", [r for r in claim_rows if r["label"] == "ransomware"])]:
        for predictor in ["atom_count", "json_bytes"]:
            x = np.asarray([r[predictor] for r in subset], dtype=float)
            y = np.asarray([r["corroborated"] for r in subset], dtype=float)
            rho, p = spearmanr(x, y) if len(subset) >= 4 and len(set(x)) > 1 and len(set(y)) > 1 else (float("nan"), float("nan"))
            corr_rows.append({"scope": f"supported_claims_{scope}", "predictor": predictor, "outcome": "corroborated_claim", "n": len(subset), "spearman_rho": rho, "p_value": p, "bootstrap_ci_low": "NA", "bootstrap_ci_high": "NA"})
    write_csv(RES / "volume_strength_correlations.csv", corr_rows)

    quartiles = []
    for label in ["benign", "ransomware"]:
        subset = [r for r in report_rows if r["label"] == label]
        values = np.asarray([r["atom_count"] for r in subset], dtype=float)
        cuts = np.quantile(values, [0.25, 0.5, 0.75])
        for q in range(4):
            group = [r for r in subset if (r["atom_count"] <= cuts[0] if q == 0 else r["atom_count"] <= cuts[q] and r["atom_count"] > cuts[q - 1] if q < 3 else r["atom_count"] > cuts[2])]
            corr = [r["corroboration_rate"] for r in group if np.isfinite(r["corroboration_rate"])]
            single = [r["single_field_rate"] for r in group if np.isfinite(r["single_field_rate"])]
            frag = [r["any_fragility_computed"] for r in group]
            quartiles.append({"label": label, "atom_count_quartile": q + 1, "n": len(group), "mean_atom_count": np.mean([r["atom_count"] for r in group]) if group else "NA", "mean_corroboration_rate": np.mean(corr) if corr else "NA", "mean_single_field_rate": np.mean(single) if single else "NA", "reports_with_computed_fragility": sum(frag), "computed_fragility_rate": np.mean(frag) if frag else "NA"})
    write_csv(RES / "volume_strength_quartiles.csv", quartiles)

    extremes = {}
    for label in ["benign", "ransomware"]:
        subset = [r for r in report_rows if r["label"] == label]
        values = np.asarray([r["atom_count"] for r in subset], dtype=float)
        high = float(np.quantile(values, 0.75)); low = float(np.quantile(values, 0.25))
        high_rows = [r for r in subset if r["atom_count"] >= high]
        low_rows = [r for r in subset if r["atom_count"] <= low]
        extremes[label] = {
            "high_volume_threshold": high,
            "low_volume_threshold": low,
            "high_volume_reports_with_fragility": sum(r["any_fragility_computed"] for r in high_rows),
            "low_volume_reports_with_fragility": sum(r["any_fragility_computed"] for r in low_rows),
            "high_volume_mean_corroboration_rate": float(np.nanmean([r["corroboration_rate"] for r in high_rows])),
            "low_volume_mean_corroboration_rate": float(np.nanmean([r["corroboration_rate"] for r in low_rows])),
        }
    (RES / "volume_strength_extremes.json").write_text(json.dumps(extremes, ensure_ascii=False, indent=2), encoding="utf-8")

    make_volume_figure(rows, records)


def _features(rows, records, kind: str) -> np.ndarray:
    out = []
    for row in rows:
        rec = records[row["sha256"]]
        base = [math.log1p(float(row["atom_count"])), float(row["nonempty_fields"]), float(row["readiness"]), float(row["environment_dependence_rate"])]
        if kind == "volume_only":
            out.append(base)
            continue
        binary = [int(rec["capabilities"][cap]["state"] == "S") for cap in CAPS]
        if kind == "volume_plus_binary":
            out.append(base + binary)
            continue
        audit = []
        for cap in CAPS:
            c = rec["capabilities"][cap]
            audit.extend([int(c["state"] == "S"), int(c["state"] == "N"), int(c["state"] == "I"), int(c.get("corroborated", False)), len(c.get("support_fields", []))])
        corr = rec["corroboration"]
        out.append(base + audit + [float(corr["corroboration_rate"] or 0.0), float(corr["single_field_supported_claims"])])
    return np.asarray(out, dtype=float)


def run_downstream_utility(rows, records) -> None:
    y = np.asarray([int(r["label"] == "ransomware") for r in rows], dtype=int)
    splitter = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    out = []
    predictions = {}
    for kind in ["volume_only", "volume_plus_binary", "volume_plus_full_audit"]:
        X = _features(rows, records, kind)
        oof = np.zeros(len(rows), dtype=float)
        for train, test in splitter.split(X, y):
            model = make_pipeline(StandardScaler(), LogisticRegression(C=1.0, max_iter=2000, solver="liblinear", random_state=SEED))
            model.fit(X[train], y[train]); oof[test] = model.predict_proba(X[test])[:, 1]
        predictions[kind] = oof
        out.append({"feature_set": kind, "feature_count": X.shape[1], "roc_auc": roc_auc_score(y, oof), "average_precision": average_precision_score(y, oof), "balanced_accuracy": balanced_accuracy_score(y, oof >= 0.5), "brier_score": brier_score_loss(y, oof), "log_loss": log_loss(y, oof, labels=[0, 1])})
    rng = np.random.default_rng(SEED)
    deltas = []
    for kind in ["volume_plus_binary", "volume_plus_full_audit"]:
        diff_auc = []; diff_brier = []
        for _ in range(1000):
            idx_b = rng.choice(np.where(y == 0)[0], np.sum(y == 0), replace=True)
            idx_m = rng.choice(np.where(y == 1)[0], np.sum(y == 1), replace=True)
            idx = np.concatenate([idx_b, idx_m])
            diff_auc.append(roc_auc_score(y[idx], predictions[kind][idx]) - roc_auc_score(y[idx], predictions["volume_only"][idx]))
            diff_brier.append(brier_score_loss(y[idx], predictions[kind][idx]) - brier_score_loss(y[idx], predictions["volume_only"][idx]))
        deltas.append({"comparison": f"{kind} minus volume_only", "delta_roc_auc": float(np.mean(diff_auc)), "delta_roc_auc_ci_low": float(np.quantile(diff_auc, .025)), "delta_roc_auc_ci_high": float(np.quantile(diff_auc, .975)), "delta_brier_score": float(np.mean(diff_brier)), "delta_brier_ci_low": float(np.quantile(diff_brier, .025)), "delta_brier_ci_high": float(np.quantile(diff_brier, .975))})
    write_csv(RES / "downstream_utility.csv", out + deltas)
    make_downstream_figure()


def status_part(value: str) -> Tuple[str | None, str | None]:
    low = value.lower()
    polarity = None
    if re.search(r"\bsuccess(?:ful)?\b", low): polarity = "success"
    elif re.search(r"\b(?:fail(?:ed|ure)?|error)\b", low): polarity = "failure"
    if polarity is None:
        return None, None
    key = re.sub(r"\b(?:success(?:ful)?|fail(?:ed|ure)?|error)\b", " ", low)
    key = re.sub(r"[^a-z0-9]+", " ", key).strip()
    return polarity, key if len(key) >= 3 else None


def run_contradiction_sensitivity(rows, raw, records) -> None:
    out = []
    for rule in ["frozen_same_field_same_context", "same_field_any_context", "cross_field_same_context", "any_field_any_context"]:
        report_count = 0; pair_count = 0
        for row in rows:
            data = raw[row["sha256"]]
            field_events = []
            for field in bp.FIELDS:
                for idx, value in enumerate(bp.values_for(data, field)):
                    pol, key = status_part(value)
                    if pol:
                        field_events.append((field, idx, pol, key))
            pairs = 0
            for i, a in enumerate(field_events):
                for b in field_events[i + 1:]:
                    if a[2] == b[2]:
                        continue
                    same_field = a[0] == b[0]
                    same_key = a[3] is not None and a[3] == b[3]
                    ok = {
                        "frozen_same_field_same_context": same_field and same_key,
                        "same_field_any_context": same_field,
                        "cross_field_same_context": (not same_field) and same_key,
                        "any_field_any_context": True,
                    }[rule]
                    pairs += int(ok)
            report_count += int(pairs > 0); pair_count += pairs
        out.append({"rule": rule, "reports_flagged": report_count, "candidate_pairs": pair_count, "interpretation": "Only the frozen rule is a BEIST-1.0 contradiction; relaxed rules are upper-bound sensitivity audits."})
    write_csv(RES / "contradiction_sensitivity.csv", out)


def make_search_figure() -> None:
    path = RES / "efp_search_validation_summary.csv"
    if not path.is_file():
        return
    rows = list(csv.DictReader(path.open(encoding="utf-8-sig", newline="")))
    bounds = ["5/4", "10/6", "20/10"]
    vals = []
    for bound in bounds:
        subset = [r for r in rows if r["bound"] == bound and r["disruption_recall"] not in ("NA", "")]
        vals.append(np.mean([float(r["disruption_recall"]) for r in subset]) if subset else np.nan)
    for suffix, title, xlabel, ylabel in [("", "Bounded EFP search validation", "Search bound (single/pair prefix)", "Mean recall of exhaustive order-2 disruptions"), ("_zh", "有界 EFP 搜索边界验证", "搜索边界（单点/成对前缀）", "穷举二阶破坏的平均召回率")]:
        fig, ax = plt.subplots(figsize=(7.5, 4.2), constrained_layout=True)
        ax.bar(bounds, vals, color="#2F6B9A"); ax.set_ylim(0, 1.05); ax.set_xlabel(xlabel); ax.set_ylabel(ylabel); ax.set_title(title); ax.grid(axis="y", alpha=.2)
        save_svg_first(fig, f"fig5_efp_search{suffix}"); plt.close(fig)


def main() -> None:
    configure_cjk_font()
    if "--figures-only" in sys.argv[1:]:
        rows = list(csv.DictReader((NEW / "sample_manifest.csv").open(encoding="utf-8-sig", newline="")))
        records = {row["sha256"]: json.loads((NEW / "evidence_records" / f"{row['sha256']}.json").read_text(encoding="utf-8")) for row in rows}
        make_volume_figure(rows, records)
        make_search_figure()
        make_downstream_figure()
        print(json.dumps({"figures_only": True, "reports": len(rows)}, ensure_ascii=False))
        return
    skip_predicate = "--skip-predicate" in sys.argv[1:]
    skip_efp = "--skip-efp" in sys.argv[1:]
    skip_volume = "--skip-volume" in sys.argv[1:]
    rows, records, raw, atoms = load_suite()
    run_ablation(rows, records)
    if not skip_predicate:
        run_predicate_sensitivity(rows, records, raw, atoms)
    if not skip_efp:
        run_efp_search_validation(rows, records, raw)
    if not skip_volume:
        run_volume_analysis(rows, records)
    run_downstream_utility(rows, records)
    run_contradiction_sensitivity(rows, raw, records)
    make_search_figure()
    summary = {
        "protocol_version": bp.PROTOCOL_VERSION,
        "seed": SEED,
        "cohort": {"reports": len(rows), "benign": sum(r["label"] == "benign" for r in rows), "ransomware": sum(r["label"] == "ransomware" for r in rows)},
        "experiments": ["baseline_ablation", "predicate_sensitivity", "bounded_vs_exhaustive_order2_efp", "volume_strength", "downstream_utility", "contradiction_sensitivity"],
        "semantic_annotation_status": "not performed; requires independent analysts and is retained as an external-validity limitation",
        "execution_repetition_status": "not performed; the supplied archive contains one report per selected SHA-256 and no controlled rerun metadata",
    }
    (RES / "supplementary_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
