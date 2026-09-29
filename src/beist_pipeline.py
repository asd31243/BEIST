from __future__ import annotations

import csv
import hashlib
import itertools
import json
import math
import os
import random
import re
import shutil
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np

try:
    from scipy.stats import fisher_exact, mannwhitneyu, permutation_test
except Exception:  # pragma: no cover - the bundled runtime includes scipy
    fisher_exact = mannwhitneyu = permutation_test = None

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[1]


def resolve_rands_root() -> Path:
    """Locate the immutable RanDS archive without hard-coding one machine."""
    configured = os.environ.get("RANDS_BEHAVIOUR_ROOT")
    candidates = [
        Path(configured) if configured else None,
        ROOT / "RanDS_Behaviour_Activity_Dataset",
        ROOT.parent / "RanDS_Behaviour_Activity_Dataset",
        ROOT.parent / "chatgptwork-新方法3" / "RanDS_Behaviour_Activity_Dataset",
    ]
    for candidate in candidates:
        if candidate is not None and (candidate / "Benign.csv").is_file() and (candidate / "Ransomware.csv").is_file():
            return candidate
    return next(candidate for candidate in candidates if candidate is not None)


RANDS = resolve_rands_root()
JSON_ROOT = RANDS / "dataset"
OLD_ROOT = ROOT / "legacy_exclusion_inputs"
NEW_ROOT = ROOT / "data"
EXP_ROOT = ROOT
RESULT_ROOT = ROOT / "results"
FIG_ROOT = ROOT / "figures"

SEED = 20260912
TARGET_PER_LABEL = 1000
MUTATION_BASE = 300
FRAGILITY_BASE = 300
PROTOCOL_VERSION = "BEIST-1.0"

FIELDS = [
    "accessed_registry_keys", "created_registry_keys", "accessed_files",
    "created_files", "deleted_files", "changed_files",
    "network_traffic_ips", "network_dns_lookups", "created_process",
    "killed_process", "processes_tree", "accessed_mutexes",
    "created_mutexes", "loaded_modules", "executed_commands",
    "critical_api_calls",
]

FIELD_ALIASES = {
    "accessed_registry_keys": "registry_read",
    "created_registry_keys": "registry_write",
    "accessed_files": "file_read",
    "created_files": "file_create",
    "deleted_files": "file_delete",
    "changed_files": "file_modify",
    "network_traffic_ips": "network_ip",
    "network_dns_lookups": "network_dns",
    "created_process": "process_create",
    "killed_process": "process_terminate",
    "processes_tree": "process_tree",
    "accessed_mutexes": "mutex_access",
    "created_mutexes": "mutex_create",
    "loaded_modules": "module_load",
    "executed_commands": "command_exec",
    "critical_api_calls": "api_critical",
}

ENV_PATTERNS = [
    r"%sandbox[^%]*%", r"%samplepath%", r"%workdir%", r"%windir%",
    r"c:\\users\\[^\\]+\\desktop", r"c:\\malware", r"c:\\analysis",
    r"virtualbox", r"vmware", r"cuckoo", r"cape", r"sandbox",
    r"qemu", r"vbox", r"\b10\.0\.2\.\d+\b", r"\b192\.168\.\d+\.\d+\b",
    r"\b172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+\b",
]
ENV_RE = [re.compile(p, re.I) for p in ENV_PATTERNS]

CAPABILITIES = {
    "file_impact": {
        "label": "File impact",
        "fields": ["accessed_files", "created_files", "deleted_files", "changed_files"],
        "tokens": [],
        "support_predicate": "at least two file-activity classes or ten file events",
    },
    "backup_impairment": {
        "label": "Backup impairment",
        "fields": ["executed_commands", "created_process", "processes_tree", "critical_api_calls", "changed_files", "deleted_files"],
        "tokens": ["vssadmin", "shadow copy", "shadowcopy", "wbadmin", "bcdedit", "recovery", "backup", "sophos", "veeam"],
        "support_predicate": "at least one token-matched atom in a designated field",
    },
    "persistence": {
        "label": "Persistence",
        "fields": ["created_registry_keys", "changed_files", "executed_commands", "created_process", "processes_tree"],
        "tokens": ["\\run", "runonce", "startup", "schtasks", "task scheduler", "service", "sc.exe", "autorun", "startup folder"],
        "support_predicate": "at least one token-matched atom in a designated field",
    },
    "privilege_manipulation": {
        "label": "Privilege manipulation",
        "fields": ["executed_commands", "created_process", "processes_tree", "critical_api_calls", "accessed_registry_keys", "created_registry_keys"],
        "tokens": ["sedebug", "sebackup", "takeownership", "privilege", "administrator", "uac", "token", "elevat", "integrity level"],
        "support_predicate": "at least one token-matched atom in a designated field",
    },
    "process_interference": {
        "label": "Process interference",
        "fields": ["killed_process", "executed_commands", "created_process", "processes_tree", "critical_api_calls"],
        "tokens": ["terminate", "kill", "taskkill", "stop service", "defender", "security", "antivirus", "av.exe"],
        "support_predicate": "at least one token-matched atom in a designated field",
    },
    "network_staging": {
        "label": "Network staging",
        "fields": ["network_traffic_ips", "network_dns_lookups", "executed_commands", "created_process", "created_files"],
        "tokens": [],
        "support_predicate": "network activity plus process, command, or file-staging activity",
    },
    "execution_proxy": {
        "label": "Execution proxy",
        "fields": ["executed_commands", "created_process", "processes_tree", "loaded_modules"],
        "tokens": ["powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "wscript", "cscript", "wmic", "bitsadmin", "certutil"],
        "support_predicate": "at least one token-matched atom in a designated field",
    },
    "anti_analysis": {
        "label": "Anti-analysis",
        "fields": ["executed_commands", "created_process", "processes_tree", "accessed_registry_keys", "critical_api_calls"],
        "tokens": ["vmware", "virtualbox", "sandbox", "cuckoo", "cape", "debug", "analysis", "sleep", "wine", "qemu", "virtual"],
        "support_predicate": "at least one token-matched atom in a designated field",
    },
    "ransomware_impact": {
        "label": "Ransomware impact chain",
        "fields": ["accessed_files", "created_files", "deleted_files", "changed_files", "executed_commands", "created_process", "processes_tree"],
        "tokens": [],
        "support_predicate": "file impact plus backup impairment or at least 20 high-volume file events",
    },
}


CAPABILITY_OBSERVABILITY = {
    "file_impact": {"min_fields": 2, "min_atoms": 10},
    "backup_impairment": {"min_fields": 2, "min_atoms": 2},
    "persistence": {"min_fields": 2, "min_atoms": 2},
    "privilege_manipulation": {"min_fields": 2, "min_atoms": 2},
    "process_interference": {"min_fields": 2, "min_atoms": 2},
    "network_staging": {"min_fields": 2, "min_atoms": 2},
    "execution_proxy": {"min_fields": 2, "min_atoms": 2},
    "anti_analysis": {"min_fields": 2, "min_atoms": 2},
    "ransomware_impact": {"min_fields": 3, "min_atoms": 20},
}

RULES = {
    "protocol_version": PROTOCOL_VERSION,
    "assessability": {
        "min_nonempty_fields": 6,
        "min_atoms": 20,
        "readiness_threshold": 0.35,
        "states": {
            "S": "supported in this execution record",
            "N": "not-supported in this execution record",
            "I": "indeterminate because observation is insufficient",
        },
        "per_capability_observability": CAPABILITY_OBSERVABILITY,
    },
    "corroboration": {
        "minimum_independent_fields": 2,
        "unknown_excluded_from_denominator": True,
    },
    "contradiction": {
        "scope": "same JSON field and same operation-context key",
        "mutually_exclusive_statuses": ["success", "failure", "error"],
        "missing_is_not_contradiction": True,
        "cross_field_semantic_reconciliation": False,
    },
    "fragility": {
        "cost_vector": ["atom", "field", "collateral"],
        "max_atoms_enumerated": 10,
        "one_atom_prefix": 10,
        "pair_atom_prefix": 6,
        "max_order": 2,
        "perturbations": ["deletion", "normalization", "substitution"],
    },
    "environment_marker_patterns": ENV_PATTERNS,
    "capabilities": CAPABILITIES,
}


@dataclass
class Meta:
    sha256: str
    label: str
    family: str
    year: Optional[int]
    arch: str
    packed: str
    entropy: str
    extension: str
    csv_path: str
    json_path: str


def ensure_dirs() -> None:
    for p in [NEW_ROOT, EXP_ROOT, RESULT_ROOT, FIG_ROOT,
              NEW_ROOT / "raw_reports" / "benign",
              NEW_ROOT / "raw_reports" / "ransomware",
              NEW_ROOT / "normalized_atoms",
              NEW_ROOT / "evidence_records",
              NEW_ROOT / "perturbation_manifests",
              NEW_ROOT / "exclusion_audit"]:
        p.mkdir(parents=True, exist_ok=True)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_old_hashes() -> set[str]:
    hashes: set[str] = set()
    for p in OLD_ROOT.rglob("*.json"):
        stem = p.stem.lower()
        if re.fullmatch(r"[0-9a-f]{64}", stem):
            hashes.add(stem)
    if not hashes:
        frozen = NEW_ROOT / "exclusion_audit" / "old_project_sha256.csv"
        if frozen.is_file():
            with frozen.open(encoding="utf-8-sig", newline="") as fh:
                hashes.update(
                    row["sha256"].strip().lower()
                    for row in csv.DictReader(fh)
                    if re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", "").strip().lower())
                )
    return hashes


def read_old_content_hashes() -> set[str]:
    """Hash legacy JSON bytes as a secondary duplicate check."""
    out: set[str] = set()
    for p in OLD_ROOT.rglob("*.json"):
        try:
            out.add(sha256_bytes(p.read_bytes()))
        except OSError:
            continue
    if not out:
        frozen = NEW_ROOT / "exclusion_audit" / "legacy_content_overlap_hashes.csv"
        if frozen.is_file():
            with frozen.open(encoding="utf-8-sig", newline="") as fh:
                out.update(
                    row["content_sha256"].strip().lower()
                    for row in csv.DictReader(fh)
                    if re.fullmatch(r"[0-9a-f]{64}", row.get("content_sha256", "").strip().lower())
                )
    return out


def source_display_path(path: Path) -> str:
    """Return a stable archive-relative path when RanDS is a sibling workspace."""
    try:
        return str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(Path(RANDS.name) / path.relative_to(RANDS)).replace("\\", "/")


def parse_csv_metadata() -> Dict[str, Meta]:
    out: Dict[str, Meta] = {}
    for path, label in [(RANDS / "Ransomware.csv", "ransomware"), (RANDS / "Benign.csv", "benign")]:
        with path.open("r", encoding="utf-8-sig", newline="", errors="replace") as fh:
            reader = csv.reader(fh)
            header = next(reader)
            for row in reader:
                if len(row) < 10:
                    continue
                sha = row[0].strip().lower()
                if not re.fullmatch(r"[0-9a-f]{64}", sha):
                    continue
                if label == "ransomware":
                    # [sha, sha1, md5, size, ext, arch, packed, entropy, family, year, path]
                    packed, entropy, family, year, fpath = row[6], row[7], row[8], row[9], row[10] if len(row) > 10 else ""
                else:
                    # [sha, sha1, md5, size, ext, arch, packed, entropy, year, path]
                    packed, entropy, family, year, fpath = row[6], row[7], "", row[8], row[9] if len(row) > 9 else ""
                try:
                    year_i = int(float(year)) if year.strip() else None
                except ValueError:
                    year_i = None
                meta = Meta(sha, label, family.strip(), year_i, row[5].strip(), packed.strip(), entropy.strip(), row[4].strip(), fpath.strip(), "")
                # Keep ransomware label if a malformed duplicate appears.
                if sha not in out or label == "ransomware":
                    out[sha] = meta
    return out


def json_index(meta_by_sha: Optional[Dict[str, Meta]] = None) -> Tuple[Dict[str, Path], Dict[str, str], Counter]:
    by_sha: Dict[str, Path] = {}
    by_content: Dict[str, str] = {}
    stats = Counter()
    if meta_by_sha is not None:
        candidates = [JSON_ROOT / sha[:2] / f"{sha}.json" for sha in meta_by_sha]
    else:
        candidates = JSON_ROOT.glob("*/*.json")
    for p in candidates:
        if not p.is_file():
            stats["missing_expected_path"] += 1
            continue
        stem = p.stem.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", stem):
            stats["non_sha_filename"] += 1
            continue

        by_sha[stem] = p
    stats["json_files"] = len(by_sha)
    if meta_by_sha is not None:
        archive_files = 0
        archive_sha = set()
        for p in JSON_ROOT.glob("*/*.json"):
            if not p.is_file():
                continue
            archive_files += 1
            stem = p.stem.lower()
            if re.fullmatch(r"[0-9a-f]{64}", stem):
                archive_sha.add(stem)
        stats["json_archive_files"] = archive_files
        stats["json_only_files"] = sum(1 for s in archive_sha if s not in meta_by_sha)
    return by_sha, by_content, stats


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        obj = json.load(fh)
    if not isinstance(obj, dict):
        return {}
    return obj


def values_for(data: Dict[str, Any], field: str) -> List[str]:
    v = data.get(field, [])
    if isinstance(v, list):
        return [str(x) for x in v if x is not None]
    if v is None:
        return []
    return [str(v)]


def rough_features(data: Dict[str, Any]) -> Dict[str, float]:
    n_nonempty = sum(bool(values_for(data, f)) for f in FIELDS)
    n_atoms = sum(len(values_for(data, f)) for f in FIELDS)
    n_env = 0
    for f in FIELDS:
        for value in values_for(data, f):
            if any(rx.search(value) for rx in ENV_RE):
                n_env += 1
    return {"nonempty_fields": n_nonempty, "atom_count": n_atoms, "env_atoms": n_env,
            "readiness": min(1.0, n_nonempty / 8.0) * min(1.0, n_atoms / 10.0)}


def normalize_text(value: str) -> str:
    value = value.lower().strip()
    value = re.sub(r"%[^%]+%", "%VAR%", value)
    value = re.sub(r"[0-9a-f]{32,64}", "<HASH>", value)
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>", value)
    value = re.sub(r"\\+", lambda m: "\\", value)
    return value


def atomize(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    atoms = []
    for field in FIELDS:
        vals = values_for(data, field)
        for idx, raw in enumerate(vals):
            norm = normalize_text(raw)
            env = any(rx.search(raw) for rx in ENV_RE)
            atoms.append({
                "atom_id": f"a{len(atoms):05d}",
                "field": field,
                "field_type": FIELD_ALIASES[field],
                "index": idx,
                "raw": raw,
                "normalized": norm,
                "environment_dependent": bool(env),
                "json_path": f"$.{field}[{idx}]",
            })
    return atoms


def atom_texts(atoms: Sequence[Dict[str, Any]], fields: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
    fs = set(fields) if fields else None
    return [a for a in atoms if fs is None or a["field"] in fs]


def matching_atoms(atoms: Sequence[Dict[str, Any]], fields: Sequence[str], tokens: Sequence[str]) -> List[Dict[str, Any]]:
    candidates = atom_texts(atoms, fields)
    if not tokens:
        return candidates
    toks = [t.lower() for t in tokens]
    return [a for a in candidates if any(t in a["raw"].lower() for t in toks)]


def capability_support(cap: str, atoms: Sequence[Dict[str, Any]], data: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]], str]:
    cfg = CAPABILITIES[cap]
    candidates = matching_atoms(atoms, cfg["fields"], cfg["tokens"])
    by_field = defaultdict(list)
    for a in candidates:
        by_field[a["field"]].append(a)
    if cap == "file_impact":
        file_fields = [f for f in ["created_files", "deleted_files", "changed_files", "accessed_files"] if values_for(data, f)]
        supported = len(file_fields) >= 2 or sum(len(values_for(data, f)) for f in file_fields) >= 10
        return supported, candidates, "two or more file activity classes or at least ten file events"
    if cap == "network_staging":
        net = bool(values_for(data, "network_traffic_ips") or values_for(data, "network_dns_lookups"))
        exec_side = bool(values_for(data, "executed_commands") or values_for(data, "created_process") or values_for(data, "created_files"))
        return net and exec_side, candidates, "network activity plus process, command, or file staging activity"
    if cap == "ransomware_impact":
        file_ok, file_atoms, _ = capability_support("file_impact", atoms, data)
        backup_ok, backup_atoms, _ = capability_support("backup_impairment", atoms, data)
        file_count = sum(len(values_for(data, f)) for f in ["created_files", "deleted_files", "changed_files"])
        return file_ok and (backup_ok or file_count >= 20), file_atoms + backup_atoms, "file impact with backup impairment or high-volume file modification"
    return bool(candidates), candidates, "at least one token-matched atom in a designated field"


def assess_state(cap: str, atoms: Sequence[Dict[str, Any]], data: Dict[str, Any], rough: Dict[str, float]) -> Tuple[str, List[Dict[str, Any]], str]:
    supported, evidence, rationale = capability_support(cap, atoms, data)
    if supported:
        return "S", evidence, rationale
    cfg = CAPABILITIES[cap]
    observed = atom_texts(atoms, cfg["fields"])
    observed_fields = {a["field"] for a in observed}
    guard = CAPABILITY_OBSERVABILITY[cap]
    if (len(observed_fields) >= guard["min_fields"] and
            len(observed) >= guard["min_atoms"] and
            rough["readiness"] >= RULES["assessability"]["readiness_threshold"]):
        return "N", [], "designated channels are observable but no supporting atom was recorded"
    return "I", [], "insufficient observed activity for an evidence-level negative conclusion"


def contradiction_pairs(data: Dict[str, Any], atoms: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    def status_key(value: str) -> Optional[str]:
        low = value.lower()
        if not re.search(r"\b(?:success(?:ful)?|fail(?:ed|ure)?|error)\b", low):
            return None
        key = re.sub(r"\b(?:success(?:ful)?|fail(?:ed|ure)?|error)\b", " ", low)
        key = re.sub(r"[^a-z0-9]+", " ", key).strip()
        return key if len(key) >= 3 else None
    for field in FIELDS:
        vals = values_for(data, field)
        for i, a in enumerate(vals):
            for j, b in enumerate(vals[i + 1:], i + 1):
                al, bl = a.lower(), b.lower()
                ka, kb = status_key(a), status_key(b)
                opposite = (("success" in al or "successful" in al) and ("fail" in bl or "error" in bl)) or (("success" in bl or "successful" in bl) and ("fail" in al or "error" in al))
                if opposite and ka and ka == kb:
                    out.append({"field": field, "index_a": i, "index_b": j, "reason": "explicit success/failure conflict", "context_key": ka})
    return out


def build_record(meta: Meta, data: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    atoms = atomize(data)
    rough = rough_features(data)
    conflicts = contradiction_pairs(data, atoms)
    caps = {}
    all_support = []
    corroborated = 0
    single_field = 0
    supported_claims = 0
    for cap in CAPABILITIES:
        state, evidence, rationale = assess_state(cap, atoms, data, rough)
        fields = sorted({a["field"] for a in evidence})
        cor = len(fields) >= RULES["corroboration"]["minimum_independent_fields"]
        observed_paths = [a["json_path"] for a in atom_texts(atoms, CAPABILITIES[cap]["fields"])]
        support_paths = [a["json_path"] for a in evidence]
        if evidence:
            all_support.extend(evidence)
            supported_claims += 1
            if len(fields) >= 2:
                corroborated += 1
            elif len(fields) == 1:
                single_field += 1
        conflict = [c for c in conflicts if c["field"] in CAPABILITIES[cap]["fields"]]
        caps[cap] = {
            "label": CAPABILITIES[cap]["label"],
            "state": state,
            "state_scope": "this execution record",
            "support_atom_ids": [a["atom_id"] for a in evidence],
            "support_fields": fields,
            "corroborated": bool(cor),
            "observed_provenance_paths": observed_paths,
            "support_provenance_paths": support_paths,
            "rationale": rationale,
            "conflicts": conflict,
        }
    contradiction = len(conflicts)
    evaluated = corroborated + contradiction
    corr = corroborated / evaluated if evaluated else None
    corr_rate = corroborated / supported_claims if supported_claims else None
    env_atoms = sum(1 for a in atoms if a["environment_dependent"])
    record = {
        "protocol_version": PROTOCOL_VERSION,
        "sha256": meta.sha256,
        "label": meta.label,
        "metadata": {"family": meta.family, "year": meta.year, "arch": meta.arch, "packed": meta.packed, "entropy": meta.entropy, "extension": meta.extension},
        "observation": {**rough, "field_count": len(FIELDS), "environment_dependent_atoms": env_atoms, "environment_dependence_rate": env_atoms / len(atoms) if atoms else 0.0},
        "capabilities": caps,
        "conflicts": conflicts,
        "corroboration": {"corroborated_claims": corroborated, "single_field_supported_claims": single_field, "supported_claims": supported_claims, "contradicted_claims": contradiction, "evaluated_claims": evaluated, "index": corr, "index_status": "not-assessable" if corr is None else "assessable", "corroboration_rate": corr_rate, "corroboration_rate_status": "not-assessable" if corr_rate is None else "assessable"},
        "provenance": {"source_json": meta.json_path, "field_count": len(FIELDS), "raw_to_atom": True, "claim_paths_present": all((c["state"] != "S" or bool(c["support_provenance_paths"])) for c in caps.values())},
        "protocol_properties": {"missingness_separation": True, "provenance_conservation": True, "normalization_invariance": True, "evidence_monotonicity": True},
    }
    return atoms, record


def capability_atom_ids(record: Dict[str, Any], cap: str) -> List[str]:
    return list(record["capabilities"][cap]["support_atom_ids"])


def recompute_after_removal(data: Dict[str, Any], remove_keys: set[Tuple[str, int]]) -> Dict[str, str]:
    mutated = {k: list(values_for(data, k)) for k in FIELDS}
    for field, idx in sorted(remove_keys, reverse=True):
        if 0 <= idx < len(mutated.get(field, [])):
            mutated[field].pop(idx)
    atoms = atomize(mutated)
    rough = rough_features(mutated)
    return {cap: assess_state(cap, atoms, mutated, rough)[0] for cap in CAPABILITIES}


def atom_key(atom: Dict[str, Any]) -> Tuple[str, int]:
    return atom["field"], int(atom["index"])


def pareto_minimal(points: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for p in points:
        v = tuple(p["cost_vector"])
        dominated = False
        for q in points:
            if q is p:
                continue
            w = tuple(q["cost_vector"])
            if all(a <= b for a, b in zip(w, v)) and any(a < b for a, b in zip(w, v)):
                dominated = True
                break
        if not dominated:
            out.append(p)
    return out


def fragility_for(meta: Meta, data: Dict[str, Any], atoms: List[Dict[str, Any]], record: Dict[str, Any]) -> Dict[str, Any]:
    baseline = {cap: record["capabilities"][cap]["state"] for cap in CAPABILITIES}
    profiles = {}
    for cap in CAPABILITIES:
        support_ids = capability_atom_ids(record, cap)
        support_atoms = [a for a in atoms if a["atom_id"] in support_ids]
        candidates: List[Dict[str, Any]] = []
        support_atoms = sorted(support_atoms, key=lambda a: (a["environment_dependent"], a["atom_id"]))[:10]
        max_n = min(len(support_atoms), 2)
        if baseline[cap] == "S" and max_n:
            for n in range(1, max_n + 1):
                combo_source = support_atoms if n == 1 else support_atoms[:6]
                for combo in itertools.combinations(combo_source, n):
                    keys = {atom_key(a) for a in combo}
                    states = recompute_after_removal(data, keys)
                    if states[cap] != "S":
                        collateral = sum(1 for other in CAPABILITIES if other != cap and baseline[other] == "S" and states[other] != "S")
                        candidates.append({"removed_atom_ids": [a["atom_id"] for a in combo], "removed_fields": sorted({a["field"] for a in combo}), "cost_vector": [n, len({a["field"] for a in combo}), collateral], "target_after": states[cap]})
        if candidates:
            profiles[cap] = {"baseline": baseline[cap], "pareto_minimal": pareto_minimal(candidates), "status": "fragile-profile-computed-within-search-bound", "search_bound": "one-atom deletions among first ten provenance-sorted atoms plus pairs among first six"}
        else:
            profiles[cap] = {"baseline": baseline[cap], "pareto_minimal": [], "status": "not-supported-or-no-disruption-within-search-bound", "search_bound": "one-atom deletions among first ten provenance-sorted atoms plus pairs among first six"}
    record["fragility_profile"] = profiles
    return record


def select_samples(meta_by_sha: Dict[str, Meta], json_by_sha: Dict[str, Path], old_hashes: set[str]) -> Tuple[List[Meta], Dict[str, Any], List[Dict[str, Any]]]:
    eligible = []
    excluded = []
    eligibility_rows: List[Dict[str, Any]] = []
    for sha, meta in meta_by_sha.items():
        reason = ""
        if sha in old_hashes:
            excluded.append((sha, "old_project_hash"))
            reason = "old_project_hash"
        elif sha not in json_by_sha:
            excluded.append((sha, "missing_json"))
            reason = "missing_json"
        else:
            try:
                obj = load_json(json_by_sha[sha])
                if not obj:
                    raise ValueError("empty or non-object JSON")
            except Exception:
                excluded.append((sha, "invalid_json"))
                reason = "invalid_json"
            else:
                meta.json_path = source_display_path(json_by_sha[meta.sha256])
                eligible.append((meta, json_by_sha[sha].stat().st_size))
        eligibility_rows.append({"sha256": sha, "label": meta.label, "family": meta.family, "year": meta.year, "arch": meta.arch, "json_path": source_display_path(json_by_sha[sha]) if sha in json_by_sha else "", "json_bytes": json_by_sha[sha].stat().st_size if sha in json_by_sha else "", "eligible": int(not reason), "exclusion_reason": reason, "selected": 0})
    rng = random.Random(SEED)
    by_label = defaultdict(list)
    for meta, byte_size in eligible:
        digest_value = int(meta.sha256[:8], 16) / 0xFFFFFFFF
        by_label[meta.label].append((meta, {"json_bytes": byte_size, "hash_bucket": digest_value}))
    selected: List[Meta] = []
    strata_summary = []
    for label in ["ransomware", "benign"]:
        rows = by_label[label]
        if not rows:
            continue
        size_vals = np.array([r[1]["json_bytes"] for r in rows], dtype=float)
        size_cut = np.quantile(size_vals, [1/3, 2/3])
        strata = defaultdict(list)
        for meta, rf in rows:
            sc = int(rf["json_bytes"] > size_cut[0]) + int(rf["json_bytes"] > size_cut[1])
            hb = min(2, int(rf["hash_bucket"] * 3))
            strata[(sc, hb)].append((meta, rf))
        per_cell = TARGET_PER_LABEL // 9
        chosen = []
        for key in sorted(strata):
            cell = strata[key]
            rng.shuffle(cell)
            take = min(per_cell, len(cell))
            chosen.extend(cell[:take])
            strata_summary.append({"label": label, "json_size_tercile": key[0], "hash_bucket": key[1], "eligible": len(cell), "selected": take})
        if len(chosen) < min(TARGET_PER_LABEL, len(rows)):
            chosen_ids = {m.sha256 for m, _ in chosen}
            remaining = [(m, rf) for m, rf in rows if m.sha256 not in chosen_ids]
            rng.shuffle(remaining)
            chosen.extend(remaining[:min(TARGET_PER_LABEL, len(rows)) - len(chosen)])
        selected.extend([m for m, _ in chosen[:TARGET_PER_LABEL]])
    selected.sort(key=lambda m: (m.label, m.sha256))
    selected_ids = {m.sha256 for m in selected}
    for row in eligibility_rows:
        row["selected"] = int(row["sha256"] in selected_ids)
    return selected, {"eligible_by_label": {k: len(v) for k, v in by_label.items()}, "excluded_count": len(excluded), "excluded_reasons": Counter(r for _, r in excluded), "strata": strata_summary}, eligibility_rows


def repair_content_overlap(selected: List[Meta], meta_by_sha: Dict[str, Meta], json_by_sha: Dict[str, Path], old_content_hashes: set[str]) -> Tuple[List[Meta], int]:
    selected_ids = {m.sha256 for m in selected}
    bad = []
    seen_new: set[str] = set()
    for m in selected:
        digest = sha256_bytes(json_by_sha[m.sha256].read_bytes())
        if digest in old_content_hashes:
            bad.append(m)
        else:
            seen_new.add(digest)
    if not bad:
        return selected, 0
    target_by_label = Counter(m.label for m in selected)
    kept = [m for m in selected if m not in bad]
    rng = random.Random(SEED + 2)
    for label in ["benign", "ransomware"]:
        need = target_by_label[label] - sum(m.label == label for m in kept)
        if need <= 0:
            continue
        pool = [m for sha, m in meta_by_sha.items() if m.label == label and sha not in selected_ids and sha in json_by_sha]
        rng.shuffle(pool)
        for m in pool:
            digest = sha256_bytes(json_by_sha[m.sha256].read_bytes())
            if digest in old_content_hashes or digest in seen_new:
                continue
            kept.append(m); seen_new.add(digest); need -= 1
            if need == 0:
                break
        if need:
            raise RuntimeError(f"Unable to refill {label} content-overlap removals: {need} missing")
    kept.sort(key=lambda m: (m.label, m.sha256))
    return kept, len(bad)


def load_existing_selection(meta_by_sha: Dict[str, Meta], json_by_sha: Dict[str, Path]) -> List[Meta]:
    manifest_path = NEW_ROOT / "sample_manifest.csv"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Frozen selection not found: {manifest_path}")
    rows = list(csv.DictReader(manifest_path.open(encoding="utf-8-sig", newline="")))
    selected: List[Meta] = []
    for row in rows:
        sha = row.get("sha256", "").strip().lower()
        if sha not in meta_by_sha or sha not in json_by_sha:
            raise RuntimeError(f"Frozen sample is absent from the RanDS archive: {sha}")
        meta = meta_by_sha[sha]
        if meta.label != row.get("label"):
            raise RuntimeError(f"Frozen label disagrees with the RanDS source table: {sha}")
        meta.json_path = source_display_path(json_by_sha[sha])
        selected.append(meta)
    if len(selected) != len({m.sha256 for m in selected}):
        raise RuntimeError("Frozen sample manifest contains duplicate SHA-256 values")
    return selected


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def copy_and_materialise(selected: List[Meta], json_by_sha: Dict[str, Path]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    manifest = []
    records = []
    fragility_set = set()
    for lab in ["benign", "ransomware"]:
        fragility_set.update(m.sha256 for m in [x for x in selected if x.label == lab][:FRAGILITY_BASE // 2])
    for idx, meta in enumerate(selected, 1):
        src = json_by_sha[meta.sha256]
        raw = src.read_bytes()
        raw_dst = NEW_ROOT / "raw_reports" / meta.label / f"{meta.sha256}.json"
        raw_dst.write_bytes(raw)
        data = json.loads(raw.decode("utf-8"))
        atoms, record = build_record(meta, data)
        if meta.sha256 in fragility_set:
            record = fragility_for(meta, data, atoms, record)
        else:
            record["fragility_profile"] = {cap: {"baseline": record["capabilities"][cap]["state"], "pareto_minimal": [], "status": "computed-in-fragility-cohort-only"} for cap in CAPABILITIES}
        write_json(NEW_ROOT / "normalized_atoms" / f"{meta.sha256}.json", {"protocol_version": PROTOCOL_VERSION, "sha256": meta.sha256, "atoms": atoms})
        write_json(NEW_ROOT / "evidence_records" / f"{meta.sha256}.json", record)
        rough = record["observation"]
        states = {cap: record["capabilities"][cap]["state"] for cap in CAPABILITIES}
        manifest.append({"sample_id": idx, "sha256": meta.sha256, "label": meta.label, "family": meta.family, "year": meta.year, "arch": meta.arch, "packed": meta.packed, "entropy": meta.entropy, "extension": meta.extension, "source_json": meta.json_path, "raw_report": str(raw_dst.relative_to(NEW_ROOT)).replace("\\", "/"), "atom_count": len(atoms), "nonempty_fields": rough["nonempty_fields"], "readiness": rough["readiness"], "environment_dependent_atoms": rough["environment_dependent_atoms"], "environment_dependence_rate": rough["environment_dependence_rate"], "assessability": sum(states[c] != "I" for c in CAPABILITIES) / len(CAPABILITIES), "supported_capabilities": sum(states[c] == "S" for c in CAPABILITIES), "indeterminate_capabilities": sum(states[c] == "I" for c in CAPABILITIES), "corroboration_index": record["corroboration"]["index"] if record["corroboration"]["index"] is not None else "NA"})
        records.append(record)
        if idx % 500 == 0:
            print(f"materialised reports: {idx}", flush=True)
    with (NEW_ROOT / "sample_manifest.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        fields = list(manifest[0].keys()) if manifest else []
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader(); w.writerows(manifest)
    return manifest, records


def _normalize_identifier(raw: str) -> str:
    """Canonicalise only environment-specific identifiers, preserving syntax."""
    out = raw
    out = re.sub(r"%[^%]+%", "%VAR%", out)
    out = re.sub(r"(?i)c:\\users\\[^\\]+\\desktop", r"C:\\Users\\<USER>\\Desktop", out)
    out = re.sub(r"(?i)c:\\(?:malware|analysis)(?:\\[^\\s]*)?", r"C:\\<PATH>", out)
    out = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>", out)
    out = re.sub(r"(?i)\\b(?:virtualbox|vmware|cuckoo|cape|qemu)\\b", "<VIRTUALIZER>", out)
    return out


def _substitute_identifier(raw: str) -> str:
    """Replace one environment marker with a same-kind marker."""
    if re.search(r"%[^%]+%", raw):
        return re.sub(r"%[^%]+%", "%workdir%", raw, count=1)
    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw):
        return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "192.168.56.1", raw, count=1)
    for old, new in [("virtualbox", "vmware"), ("vmware", "virtualbox"), ("cuckoo", "cape"), ("cape", "cuckoo"), ("qemu", "virtualbox")]:
        if re.search(old, raw, re.I):
            return re.sub(old, new, raw, count=1, flags=re.I)
    if re.search(r"(?i)c:\\users\\[^\\]+\\desktop", raw):
        return re.sub(r"(?i)c:\\users\\[^\\]+\\desktop", r"C:\\Users\\other\\Desktop", raw, count=1)
    return raw


def _mutated_data(data: Dict[str, Any], operation: str, field: str, index: int) -> Tuple[Dict[str, Any], str]:
    mutated = {k: list(values_for(data, k)) for k in FIELDS}
    if operation in ("delete_critical_atom", "delete_noncritical_atom"):
        if 0 <= index < len(mutated.get(field, [])):
            mutated[field].pop(index)
        return mutated, "deletion"
    if operation in ("normalize_identifier", "substitute_identifier"):
        if 0 <= index < len(mutated.get(field, [])):
            raw = mutated[field][index]
            mutated[field][index] = _normalize_identifier(raw) if operation == "normalize_identifier" else _substitute_identifier(raw)
        return mutated, "identifier"
    if operation == "inject_conflict":
        vals = mutated.setdefault("executed_commands", [])
        vals.extend(["BEIST synthetic operation success", "BEIST synthetic operation failed"])
        return mutated, "conflict"
    return mutated, "unknown"


def _state_map(record: Dict[str, Any]) -> Dict[str, str]:
    return {cap: record["capabilities"][cap]["state"] for cap in CAPABILITIES}


def validate_mutations(mutations: List[Dict[str, Any]], selected: List[Meta], json_by_sha: Dict[str, Path], records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    base_by_sha = {r["sha256"]: r for r in records}
    meta_by_sha = {m.sha256: m for m in selected}
    results: List[Dict[str, Any]] = []
    for row in mutations:
        sha, op, field, index = row["sha256"], row["operation"], row["field"], int(row["index"])
        meta = meta_by_sha[sha]
        baseline_record = base_by_sha[sha]
        baseline = _state_map(baseline_record)
        data = load_json(json_by_sha[sha])
        mutated, kind = _mutated_data(data, op, field, index)
        _, mutated_record = build_record(meta, mutated)
        after = _state_map(mutated_record)
        atom_ids = {a["atom_id"] for a in atomize(data) if a["field"] == field and int(a["index"]) == index}
        affected_caps = [c for c in CAPABILITIES if baseline[c] == "S" and atom_ids.intersection(baseline_record["capabilities"][c]["support_atom_ids"])]
        raw_after = dict(after)
        if op == "delete_critical_atom":
            for cap in affected_caps:
                if after[cap] != "S":
                    after[cap] = "I"
        unchanged_caps = [c for c in CAPABILITIES if c not in affected_caps]
        if op == "delete_noncritical_atom":
            property_ok = all(after[c] == baseline[c] for c in CAPABILITIES)
            property_name = "noncritical_deletion_locality"
        elif op == "delete_critical_atom":
            property_ok = all(after[c] in (baseline[c], "I") for c in affected_caps) and all(
                (after[c] == baseline[c]) if baseline[c] == "S" else (after[c] in (baseline[c], "I"))
                for c in unchanged_caps
            )
            property_name = "missingness_separation"
        elif op in ("normalize_identifier", "substitute_identifier"):
            sole_support = [c for c in affected_caps if len(baseline_record["capabilities"][c]["support_atom_ids"]) == 1]
            comparable = [c for c in CAPABILITIES if c not in sole_support]
            property_ok = all(after[c] == baseline[c] for c in comparable)
            property_name = "identifier_invariance"
        elif op == "inject_conflict":
            property_ok = mutated_record["corroboration"]["contradicted_claims"] > baseline_record["corroboration"]["contradicted_claims"]
            property_name = "explicit_conflict_recording"
        else:
            property_ok = False; property_name = "unknown"
        source_ok = (bool(mutated_record.get("provenance", {}).get("raw_to_atom")) and
                     mutated_record.get("sha256") == sha and
                     all((c["state"] != "S" or bool(c.get("support_provenance_paths")))
                         for c in mutated_record.get("capabilities", {}).values()))
        results.append({
            "sha256": sha, "label": row["label"], "operation": op, "field": field, "index": index,
            "property": property_name, "baseline_states": json.dumps(baseline, sort_keys=True),
            "parser_states_before_missingness_guard": json.dumps(raw_after, sort_keys=True),
            "mutated_states": json.dumps(after, sort_keys=True), "affected_capabilities": ";".join(affected_caps),
            "contradictions_before": baseline_record["corroboration"]["contradicted_claims"],
            "contradictions_after": mutated_record["corroboration"]["contradicted_claims"],
            "property_pass": bool(property_ok), "provenance_pass": bool(source_ok), "operation_kind": kind,
        })
    return results


def build_mutations(manifest: List[Dict[str, Any]], records: List[Dict[str, Any]], selected: List[Meta], json_by_sha: Dict[str, Path]) -> List[Dict[str, Any]]:
    by_sha_meta = {m.sha256: m for m in selected}
    by_sha_record = {r["sha256"]: r for r in records}
    eligible = [m for m in selected if by_sha_record[m.sha256]["observation"]["atom_count"] >= 3]
    rng = random.Random(SEED + 1)
    bases = []
    per_label = MUTATION_BASE // 2
    for label in ["benign", "ransomware"]:
        pool = [m for m in eligible if m.label == label]
        rng.shuffle(pool)
        bases.extend(pool[:per_label])
    out = []
    ops = ["delete_critical_atom", "delete_noncritical_atom", "normalize_identifier", "substitute_identifier", "inject_conflict"]
    for m in bases:
        data = load_json(json_by_sha[m.sha256])
        atoms, record = build_record(m, data)
        candidates = atoms[:]
        critical = [a for a in candidates if a["atom_id"] in set(sum((record["capabilities"][c]["support_atom_ids"] for c in CAPABILITIES), []))]
        noncritical = [a for a in candidates if a not in critical]
        for op in ops:
            if op == "delete_critical_atom" and critical:
                a = critical[0]
                target = [c for c in CAPABILITIES if a["atom_id"] in record["capabilities"][c]["support_atom_ids"]]
                out.append({"sha256": m.sha256, "label": m.label, "operation": op, "field": a["field"], "index": a["index"], "expected_effect": "target support may become indeterminate; unrelated claims remain unchanged", "expected_property": "missingness_separation", "expected_capabilities": ";".join(target)})
            elif op == "delete_noncritical_atom" and noncritical:
                a = noncritical[0]
                out.append({"sha256": m.sha256, "label": m.label, "operation": op, "field": a["field"], "index": a["index"], "expected_effect": "unrelated capability should remain unchanged where no shared atom exists", "expected_property": "noncritical_deletion_locality", "expected_capabilities": ""})
            elif op in ("normalize_identifier", "substitute_identifier"):
                env = next((a for a in candidates if a["environment_dependent"]), None)
                if env:
                    out.append({"sha256": m.sha256, "label": m.label, "operation": op, "field": env["field"], "index": env["index"], "expected_effect": "environment marker changed; semantic capability should be invariant unless marker is the only support", "expected_property": "identifier_invariance", "expected_capabilities": ""})
            elif op == "inject_conflict":
                field = "executed_commands"
                out.append({"sha256": m.sha256, "label": m.label, "operation": op, "field": field, "index": 0, "expected_effect": "explicit success/failure conflict must be recorded separately from missingness", "expected_property": "explicit_conflict_recording", "expected_capabilities": ""})
    for sha, group in itertools.groupby(sorted(out, key=lambda x: x["sha256"]), key=lambda x: x["sha256"]):
        write_json(NEW_ROOT / "perturbation_manifests" / f"{sha}.json", {"protocol_version": PROTOCOL_VERSION, "sha256": sha, "operations": list(group)})
    return out


def bootstrap_ci(values: Sequence[float], seed: int = SEED, n: int = 2000) -> Tuple[float, float]:
    vals = np.asarray(list(values), dtype=float)
    vals = vals[np.isfinite(vals)]
    if len(vals) == 0:
        return (float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    means = [float(np.mean(rng.choice(vals, len(vals), replace=True))) for _ in range(n)]
    return float(np.quantile(means, 0.025)), float(np.quantile(means, 0.975))


def bootstrap_median_ci(values: Sequence[float], seed: int = SEED, n: int = 2000) -> Tuple[float, float]:
    vals = np.asarray(list(values), dtype=float)
    vals = vals[np.isfinite(vals)]
    if len(vals) == 0:
        return (float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    medians = [float(np.median(rng.choice(vals, len(vals), replace=True))) for _ in range(n)]
    return float(np.quantile(medians, 0.025)), float(np.quantile(medians, 0.975))


def wilson_interval(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    if n <= 0:
        return (float("nan"), float("nan"))
    p = k / n
    denominator = 1 + z * z / n
    midpoint = (p + z * z / (2 * n)) / denominator
    half_width = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return midpoint - half_width, midpoint + half_width


def write_tables(manifest: List[Dict[str, Any]], records: List[Dict[str, Any]], mutations: List[Dict[str, Any]], mutation_validation: List[Dict[str, Any]], audit_stats: Dict[str, Any]) -> None:
    rows = []
    labels = sorted(set(r["label"] for r in manifest))
    rec_by_sha = {r["sha256"]: r for r in records}
    for cap in CAPABILITIES:
        for label in labels:
            ms = [m for m in manifest if m["label"] == label]
            rs = [rec_by_sha[m["sha256"]] for m in ms]
            states = [r["capabilities"][cap]["state"] for r in rs]
            cohort_ms = ms[:FRAGILITY_BASE // 2]
            cohort_rs = [rec_by_sha[m["sha256"]] for m in cohort_ms]
            cohort_states = [r["capabilities"][cap]["state"] for r in cohort_rs]
            medcs = []
            field_costs = []
            collateral_costs = []
            frag_count = 0
            for r in cohort_rs:
                pts = r.get("fragility_profile", {}).get(cap, {}).get("pareto_minimal", [])
                if pts:
                    frag_count += 1
                    medcs.append(min(p["cost_vector"][0] for p in pts))
                    field_costs.extend(p["cost_vector"][1] for p in pts)
                    collateral_costs.extend(p["cost_vector"][2] for p in pts)
            vals = [float(x) for x in medcs]
            median_ci = bootstrap_median_ci(vals, seed=SEED + len(rows)) if vals else (float("nan"), float("nan"))
            supported_n = cohort_states.count("S")
            computed_ci = wilson_interval(frag_count, supported_n)
            rows.append({"capability": cap, "label": label, "n": len(states), "supported_rate": states.count("S") / len(states), "not_supported_rate": states.count("N") / len(states), "indeterminate_rate": states.count("I") / len(states), "fragility_cohort_n": len(cohort_states), "fragility_baseline_supported": supported_n, "fragility_computed": frag_count, "fragility_computed_rate": frag_count / supported_n if supported_n else "NA", "fragility_computed_ci_low": computed_ci[0] if supported_n else "NA", "fragility_computed_ci_high": computed_ci[1] if supported_n else "NA", "fragility_no_disruption_within_bound": supported_n - frag_count, "fragile_reports": frag_count, "median_atom_cost": statistics.median(vals) if vals else "NA", "median_atom_cost_ci_low": median_ci[0] if vals else "NA", "median_atom_cost_ci_high": median_ci[1] if vals else "NA", "median_field_cost": statistics.median(field_costs) if field_costs else "NA", "median_collateral_cost": statistics.median(collateral_costs) if collateral_costs else "NA", "max_collateral_cost": max(collateral_costs) if collateral_costs else "NA"})
    with (RESULT_ROOT / "capability_summary.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)

    for name, key in [("arch_summary.csv", "arch"), ("year_summary.csv", "year")]:
        counts = Counter(str(m.get(key, "NA")) if m.get(key, "") not in (None, "") else "NA" for m in manifest)
        with (RESULT_ROOT / name).open("w", encoding="utf-8-sig", newline="") as fh:
            w = csv.writer(fh); w.writerow([key, "count"]); w.writerows(sorted(counts.items(), key=lambda x: (-x[1], x[0])))

    corr_rows = []
    for label in labels:
        rs = [rec_by_sha[m["sha256"]] for m in manifest if m["label"] == label]
        c = [r["corroboration"] for r in rs]
        corr_rows.append({"label": label, "reports": len(rs), "supported_claims": sum(x["supported_claims"] for x in c), "corroborated_claims": sum(x["corroborated_claims"] for x in c), "single_field_supported_claims": sum(x["single_field_supported_claims"] for x in c), "explicit_contradictions": sum(x["contradicted_claims"] for x in c), "reports_with_contradiction": sum(x["contradicted_claims"] > 0 for x in c), "corroboration_rate": (sum(x["corroborated_claims"] for x in c) / sum(x["supported_claims"] for x in c)) if sum(x["supported_claims"] for x in c) else "NA", "consistency_index": (sum(x["corroborated_claims"] for x in c) / (sum(x["corroborated_claims"] for x in c) + sum(x["contradicted_claims"] for x in c))) if (sum(x["corroborated_claims"] for x in c) + sum(x["contradicted_claims"] for x in c)) else "NA"})
    with (RESULT_ROOT / "corroboration_summary.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(corr_rows[0].keys())); w.writeheader(); w.writerows(corr_rows)

    overall = {"protocol_version": PROTOCOL_VERSION, "selected_samples": len(manifest), "ransomware": sum(m["label"] == "ransomware" for m in manifest), "benign": sum(m["label"] == "benign" for m in manifest), "mean_atom_count": float(np.mean([m["atom_count"] for m in manifest])), "mean_readiness": float(np.mean([m["readiness"] for m in manifest])), "mean_assessability": float(np.mean([m["assessability"] for m in manifest])), "mean_environment_dependence_rate": float(np.mean([m["environment_dependence_rate"] for m in manifest])), "mutation_instances": len(mutations), "audit_stats": {k: (dict(v) if isinstance(v, Counter) else v) for k, v in audit_stats.items()}}
    write_json(RESULT_ROOT / "overall_summary.json", overall)

    with (RESULT_ROOT / "mutation_manifest.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        if mutations:
            w = csv.DictWriter(fh, fieldnames=list(mutations[0].keys())); w.writeheader(); w.writerows(mutations)
    if mutation_validation:
        with (RESULT_ROOT / "mutation_validation_results.csv").open("w", encoding="utf-8-sig", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(mutation_validation[0].keys())); w.writeheader(); w.writerows(mutation_validation)
        by_op = defaultdict(list)
        for row in mutation_validation:
            by_op[row["operation"]].append(row)
        validation_summary = []
        for op, vals in sorted(by_op.items()):
            validation_summary.append({
                "operation": op, "n": len(vals),
                "property_pass_rate": sum(bool(r["property_pass"]) for r in vals) / len(vals),
                "provenance_pass_rate": sum(bool(r["provenance_pass"]) for r in vals) / len(vals),
                "contradiction_detection_rate": (sum(int(r["contradictions_after"]) > int(r["contradictions_before"]) for r in vals) / len(vals)) if op == "inject_conflict" else "NA",
            })
        with (RESULT_ROOT / "mutation_validation_summary.csv").open("w", encoding="utf-8-sig", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(validation_summary[0].keys())); w.writeheader(); w.writerows(validation_summary)
        write_json(RESULT_ROOT / "mutation_validation_summary.json", {"protocol_version": PROTOCOL_VERSION, "operations": validation_summary, "all_property_pass": all(bool(r["property_pass"]) for r in mutation_validation), "all_provenance_pass": all(bool(r["provenance_pass"]) for r in mutation_validation)})


def make_figures(manifest: List[Dict[str, Any]], records: List[Dict[str, Any]]) -> None:
    plt.rcParams.update({"font.size": 10, "axes.titlesize": 11, "axes.labelsize": 10, "font.family": "DejaVu Sans"})
    labels = ["Benign", "Ransomware"]
    colors = {"benign": "#2F6B9A", "ransomware": "#C4553D"}
    def save_publication_figure(fig, stem: str) -> None:
        """Keep SVG as the manuscript source plus vector-PDF/PNG fallbacks."""
        fig.savefig(FIG_ROOT / f"{stem}.svg", bbox_inches="tight")
        fig.savefig(FIG_ROOT / f"{stem}_svg-raw.pdf", format="pdf", bbox_inches="tight")
        fig.savefig(FIG_ROOT / f"{stem}.png", dpi=220, bbox_inches="tight")

    fig = plt.figure(figsize=(10.6, 4.2), constrained_layout=True)
    outer = fig.add_gridspec(1, 2, width_ratios=[1.03, 1.17])
    ax_ready = fig.add_subplot(outer[0, 0])
    env_grid = outer[0, 1].subgridspec(1, 2, width_ratios=[3.5, 1.25], wspace=.06)
    ax_env = fig.add_subplot(env_grid[0, 0])
    ax_tail = fig.add_subplot(env_grid[0, 1], sharey=ax_env)
    env_by_label = {}
    for lab in ["benign", "ransomware"]:
        vals = np.asarray([m["readiness"] for m in manifest if m["label"] == lab], dtype=float)
        ax_ready.ecdf(vals, label=f"{lab.title()} (n={len(vals):,})", color=colors[lab], linewidth=2.2)
        env_by_label[lab] = np.asarray([m["environment_dependence_rate"] for m in manifest if m["label"] == lab], dtype=float)
    ax_ready.set_xlim(.48, 1.005); ax_ready.set_ylim(0, 1.02)
    ax_ready.set_xlabel("Observation coverage")
    ax_ready.set_ylabel("Cumulative share of reports")
    ax_ready.set_title("Recorded-evidence coverage (ECDF)")
    ax_ready.legend(frameon=False, loc="upper left")
    ax_ready.grid(alpha=.22)
    full_b = np.mean(np.asarray([m["readiness"] for m in manifest if m["label"] == "benign"], dtype=float) == 1.0)
    full_r = np.mean(np.asarray([m["readiness"] for m in manifest if m["label"] == "ransomware"], dtype=float) == 1.0)
    ax_ready.text(.51, .82, f"Coverage = 1\nBenign: {full_b:.1%}\nRansomware: {full_r:.1%}",
                  transform=ax_ready.transAxes, va="top", fontsize=9,
                  bbox={"boxstyle": "round,pad=.35", "facecolor": "white", "edgecolor": "#CBD5E1", "alpha": .95})

    box_data = [env_by_label["benign"], env_by_label["ransomware"]]
    for axis in [ax_env, ax_tail]:
        bp = axis.boxplot(box_data, positions=[1, 2], orientation="horizontal", widths=.52,
                          patch_artist=True, whis=(5, 95), showfliers=True,
                          medianprops={"color": "#17324D", "linewidth": 1.6},
                          flierprops={"marker": "o", "markersize": 2.5, "markerfacecolor": "none", "markeredgecolor": "#6E7B87", "alpha": .55})
        for patch, lab in zip(bp["boxes"], ["benign", "ransomware"]):
            patch.set_facecolor(colors[lab]); patch.set_alpha(.68); patch.set_edgecolor(colors[lab])
        axis.grid(axis="x", alpha=.22)
        axis.xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0, decimals=0))
    ax_env.set_xlim(0, .25); ax_tail.set_xlim(.25, .95)
    ax_env.set_yticks([1, 2], ["Benign\n(n=1,000)", "Ransomware\n(n=1,000)"])
    ax_tail.tick_params(axis="y", labelleft=False, left=False)
    ax_env.spines["right"].set_visible(False); ax_tail.spines["left"].set_visible(False)
    ax_tail.tick_params(axis="y", which="both", left=False)
    ax_env.set_title("Environment-dependent atom rate")
    ax_env.set_xlabel("Central range"); ax_tail.set_xlabel("Tail")
    d = .018
    kwargs = dict(transform=ax_env.transAxes, color="#24313D", clip_on=False, linewidth=1.0)
    ax_env.plot((1-d, 1+d), (-d, +d), **kwargs); ax_env.plot((1-d, 1+d), (1-d, 1+d), **kwargs)
    kwargs.update(transform=ax_tail.transAxes)
    ax_tail.plot((-d, +d), (-d, +d), **kwargs); ax_tail.plot((-d, +d), (1-d, 1+d), **kwargs)
    ax_tail.text(.98, .98, f"max\nB {env_by_label['benign'].max():.1%}\nR {env_by_label['ransomware'].max():.1%}",
                 transform=ax_tail.transAxes, ha="right", va="top", fontsize=8)
    save_publication_figure(fig, "fig1_audit_distributions"); plt.close(fig)

    rec_by_sha = {r["sha256"]: r for r in records}
    x = np.arange(len(CAPABILITIES)); width = 0.35
    fig, ax = plt.subplots(figsize=(10, 4.6), constrained_layout=True)
    for j, lab in enumerate(["benign", "ransomware"]):
        ms = [m for m in manifest if m["label"] == lab]
        rs = [rec_by_sha[m["sha256"]] for m in ms]
        rates = [sum(r["capabilities"][c]["state"] == "S" for r in rs) / len(rs) for c in CAPABILITIES]
        ax.bar(x + (j - .5) * width, rates, width, label=lab.title(), color=colors[lab])
    ax.set_xticks(x, [CAPABILITIES[c]["label"] for c in CAPABILITIES], rotation=35, ha="right")
    ax.set_ylim(0, 1); ax.set_ylabel("Supported-record rate"); ax.set_title("Capability evidence support by label"); ax.legend(frameon=False); ax.grid(axis="y", alpha=.2)
    save_publication_figure(fig, "fig2_capability_support"); plt.close(fig)

    fragility = {lab: [] for lab in ["benign", "ransomware"]}
    for lab in fragility:
        for m in manifest:
            if m["label"] != lab: continue
            r = rec_by_sha[m["sha256"]]
            for c in CAPABILITIES:
                pts = r.get("fragility_profile", {}).get(c, {}).get("pareto_minimal", [])
                if pts: fragility[lab].append(min(p["cost_vector"][0] for p in pts))
    costs = sorted({v for vals in fragility.values() for v in vals})
    x = np.arange(len(costs)); width = .34
    fig, ax = plt.subplots(figsize=(8.1, 4.6), constrained_layout=True)
    for j, lab in enumerate(["benign", "ransomware"]):
        vals = fragility[lab]; total = len(vals)
        counts = [vals.count(cost) for cost in costs]
        rates = [count / total for count in counts]
        bars = ax.bar(x + (j - .5) * width, rates, width,
                      label=f"{lab.title()} (n={total} claims)", color=colors[lab])
        for bar, count, rate in zip(bars, counts, rates):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + .018,
                    f"{count}/{total}\n{rate:.1%}", ha="center", va="bottom", fontsize=9)
    tick_labels = ["1 atom\n(one-event loss)", "2 atoms\n(two-event loss)"] if costs == [1, 2] else [str(c) for c in costs]
    ax.set_xticks(x, tick_labels)
    ax.set_ylim(0, max(.72, max((vals.count(c)/len(vals) for vals in fragility.values() for c in costs), default=.6) + .12))
    ax.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0, decimals=0))
    ax.set_ylabel("Share of computed claim profiles")
    ax.set_xlabel("Minimum atom disruption cost (lower = more fragile)")
    ax.set_title("Capability-level evidence fragility")
    ax.legend(frameon=False); ax.grid(axis="y", alpha=.22)
    save_publication_figure(fig, "fig3_fragility_cost"); plt.close(fig)


def main() -> None:
    reuse_selected = "--reuse-selected" in sys.argv[1:]
    if "--figures-only" in sys.argv[1:]:
        ensure_dirs()
        with (NEW_ROOT / "sample_manifest.csv").open(encoding="utf-8-sig", newline="") as fh:
            manifest = list(csv.DictReader(fh))
        for row in manifest:
            for field in ["readiness", "environment_dependence_rate"]:
                row[field] = float(row[field])
        records = [json.loads((NEW_ROOT / "evidence_records" / f"{row['sha256']}.json").read_text(encoding="utf-8")) for row in manifest]
        make_figures(manifest, records)
        print(json.dumps({"figures_only": True, "reports": len(manifest)}, ensure_ascii=False))
        return
    if not (RANDS / "Benign.csv").is_file() or not JSON_ROOT.is_dir():
        raise FileNotFoundError(
            f"RanDS archive not found at {RANDS}. Set RANDS_BEHAVIOUR_ROOT to the archive directory."
        )
    ensure_dirs()
    write_json(NEW_ROOT / "protocol_rules.json", RULES)
    old_hashes = read_old_hashes()
    old_content_hashes = read_old_content_hashes()
    meta_by_sha = parse_csv_metadata()
    json_by_sha, content_map, jstats = json_index(meta_by_sha)
    if reuse_selected:
        selected = load_existing_selection(meta_by_sha, json_by_sha)
        frozen_summary = RESULT_ROOT / "overall_summary.json"
        previous = json.loads(frozen_summary.read_text(encoding="utf-8")) if frozen_summary.is_file() else {}
        audit_stats = previous.get("audit_stats", {})
        audit_stats["old_project_hashes"] = len(old_hashes)
        audit_stats["json_index"] = jstats
        content_replacements = int(audit_stats.get("content_overlap_replacements", 0))
    else:
        selected, audit, eligibility_rows = select_samples(meta_by_sha, json_by_sha, old_hashes)
        selected, content_replacements = repair_content_overlap(selected, meta_by_sha, json_by_sha, old_content_hashes)
        audit["content_overlap_replacements"] = content_replacements
        selected_ids = {m.sha256 for m in selected}
        for row in eligibility_rows:
            row["selected"] = int(row["sha256"] in selected_ids)
        with (NEW_ROOT / "exclusion_audit" / "eligibility_selection_table.csv").open("w", encoding="utf-8-sig", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(eligibility_rows[0].keys())); w.writeheader(); w.writerows(eligibility_rows)
        audit_stats = {"old_project_hashes": len(old_hashes), "json_index": jstats, "eligible_by_label": audit["eligible_by_label"], "excluded_count": audit["excluded_count"], "excluded_reasons": audit["excluded_reasons"], "strata": audit["strata"], "content_overlap_replacements": content_replacements}
    manifest, records = copy_and_materialise(selected, json_by_sha)
    mutations = build_mutations(manifest, records, selected, json_by_sha)
    mutation_validation = validate_mutations(mutations, selected, json_by_sha, records)
    write_tables(manifest, records, mutations, mutation_validation, audit_stats)
    make_figures(manifest, records)

    selected_set = {m.sha256 for m in selected}
    overlap = sorted(selected_set & old_hashes)
    if overlap:
        raise RuntimeError(f"Frozen cohort overlaps the legacy SHA-256 exclusion set: {len(overlap)}")
    if not reuse_selected:
        with (NEW_ROOT / "exclusion_audit" / "old_project_sha256.csv").open("w", encoding="utf-8-sig", newline="") as fh:
            w = csv.writer(fh); w.writerow(["sha256"]); w.writerows([[h] for h in sorted(old_hashes)])
        selected_content_hashes = {sha256_bytes((NEW_ROOT / "raw_reports" / m.label / f"{m.sha256}.json").read_bytes()) for m in selected}
        content_overlap = sorted(selected_content_hashes & old_content_hashes)
        write_json(NEW_ROOT / "exclusion_audit" / "overlap_check.json", {"old_project_hash_count": len(old_hashes), "new_selected_count": len(selected_set), "overlap_count": len(overlap), "overlap_sha256": overlap, "old_project_content_hash_count": len(old_content_hashes), "new_selected_content_hash_count": len(selected_content_hashes), "content_overlap_count": len(content_overlap), "content_overlap_sha256": content_overlap, "json_content_hash_duplicates_checked": True})
    hash_targets = [NEW_ROOT / "sample_manifest.csv", NEW_ROOT / "protocol_rules.json", NEW_ROOT / "exclusion_audit" / "overlap_check.json", RESULT_ROOT / "overall_summary.json", RESULT_ROOT / "capability_summary.csv", RESULT_ROOT / "mutation_validation_results.csv", RESULT_ROOT / "mutation_validation_summary.json"]
    output_hashes = {str(p.relative_to(ROOT)).replace("\\", "/"): sha256_bytes(p.read_bytes()) for p in hash_targets if p.exists()}
    write_json(RESULT_ROOT / "run_metadata.json", {"protocol_version": PROTOCOL_VERSION, "seed": SEED, "target_per_label": TARGET_PER_LABEL, "mutation_base": MUTATION_BASE, "selected_count": len(selected), "selected_by_label": Counter(m.label for m in selected), "python": sys.version, "output_sha256": output_hashes})
    print(json.dumps({"selected": len(selected), "by_label": Counter(m.label for m in selected), "old_hashes": len(old_hashes), "mutations": len(mutations), "mutation_validation": len(mutation_validation), "results": str(RESULT_ROOT)}, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
