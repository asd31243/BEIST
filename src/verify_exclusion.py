"""Secondary byte-content duplicate audit for the disjoint RanDS-BEIST cohort."""
from pathlib import Path
import hashlib, json

ROOT = Path(__file__).resolve().parents[1]
NEW = ROOT / "data"
OLD = ROOT / "之前用的数据集"
OLD_MANIFEST = NEW / "exclusion_audit" / "old_project_sha256.csv"

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main() -> None:
    # The old project archive is intentionally not part of the deliverable.
    # Always use its frozen hash manifest for the name-level audit; only
    # recompute byte-content overlap when that archive is actually present.
    old_name = {line.strip().lower() for line in OLD_MANIFEST.read_text(encoding="utf-8-sig").splitlines()[1:] if len(line.strip()) == 64}
    old_content = {digest(p) for p in OLD.rglob("*.json")} if OLD.is_dir() else None
    new_paths = list((NEW / "raw_reports").rglob("*.json"))
    new_name = {p.stem.lower() for p in new_paths}
    new_content = {digest(p) for p in new_paths}
    frozen_summary = ROOT / "." / "results" / "overall_summary.json"
    frozen_replacements = None
    if frozen_summary.is_file():
        try:
            frozen = json.loads(frozen_summary.read_text(encoding="utf-8"))
            frozen_replacements = frozen.get("audit_stats", {}).get("content_overlap_replacements")
        except (OSError, ValueError, TypeError):
            frozen_replacements = None
    result = {
        "old_project_hash_count": len(old_name),
        "new_selected_count": len(new_name),
        "overlap_count": len(old_name & new_name),
        "overlap_sha256": sorted(old_name & new_name),
        "old_project_content_hash_count": len(old_content) if old_content is not None else None,
        "new_selected_content_hash_count": len(new_content),
        "content_overlap_count": len(old_content & new_content) if old_content is not None else None,
        "content_overlap_sha256": sorted(old_content & new_content) if old_content is not None else [],
        "json_content_hash_duplicates_checked": old_content is not None,
        "frozen_content_overlap_replacements": frozen_replacements,
        "content_audit_note": "Byte-content overlap is recomputed only when the legacy archive is available; the frozen run recorded its content audit separately." if old_content is None else "Recomputed from the available legacy archive.",
    }
    (NEW / "exclusion_audit" / "overlap_check.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))

if __name__ == "__main__":
    main()

