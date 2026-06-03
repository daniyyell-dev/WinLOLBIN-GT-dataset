#!/usr/bin/env python3
"""
Merge all LOLBin-related data in the repo, extract explicit ML features, write CSV.

Author:  Daniel Jeremiah
GitHub:  https://github.com/daniyyell-dev
LinkedIn: https://www.linkedin.com/in/daniel-jeremiah/
Project: WinLOLBIN-GT — https://github.com/daniyyell-dev/WinLOLBIN-GT-dataset

Sources (deduplicated by label + process + normalized command line):
  - datasets/winlolbin_gt_unprocessed_merged_10m.csv (10M simulated Sysmon-style rows)
  - data/lolbin_dataset.jsonl
  - data/liblol/cmd_huge_known_commented.csv
  - data/lolbas_api/lolbas.csv

Usage:
  python3 extract_lolbin_features.py
  python3 extract_lolbin_features.py --max-rows 50000   # smoke test
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set

from lolbin_features import (
    ML_FEATURE_CSV_COLUMNS,
    dedup_key,
    enrich_row,
    infer_process_name,
)

SCRIPTS_DIR = Path(__file__).resolve().parent
PAPER_DIR = SCRIPTS_DIR.parent
REPO_ROOT = SCRIPTS_DIR.parents[2]
ML_DATA_DIR = REPO_ROOT / "Machine Learning" / "data"
DEFAULT_OUTPUT = PAPER_DIR / "datasets" / "winlolbin_gt_processed_features_10m_plus.csv"
DEFAULT_MANIFEST = PAPER_DIR / "winlolbin_gt_processed_features_manifest.json"
WRITE_BATCH = 50_000

UNPROCESSED_MERGED = PAPER_DIR / "datasets" / "winlolbin_gt_unprocessed_merged_10m.csv"
JSONL_PATH = ML_DATA_DIR / "lolbin_dataset.jsonl"
LIBLOL_CSV = ML_DATA_DIR / "liblol" / "cmd_huge_known_commented.csv"
LOLBAS_CSV = ML_DATA_DIR / "lolbas_api" / "lolbas.csv"


def canonical_from_unprocessed(row: Dict[str, str], origin: str) -> Dict[str, Any]:
    label = int((row.get("label") or "0").strip())
    return {
        "command_line": row.get("command_line") or "",
        "process_name": row.get("process_name") or "",
        "parent_process": row.get("parent_process") or "",
        "parent_command_line": row.get("parent_command_line") or "",
        "process_path": row.get("process_path") or "",
        "signed": row.get("signed") or "true",
        "network_connection": row.get("network_connection") or "false",
        "destination": row.get("destination") or "",
        "integrity_level": row.get("integrity_level") or "medium",
        "mitre_technique": row.get("mitre_technique") or "",
        "command_source": row.get("command_source") or "",
        "rule_category": row.get("rule_category") or "",
        "label": label,
        "dataset_origin": origin,
    }


def iter_unprocessed_csv(path: Path, origin: str) -> Iterator[Dict[str, Any]]:
    if not path.is_file():
        return
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            if not isinstance(row, dict):
                continue
            yield canonical_from_unprocessed(row, origin)


def iter_jsonl(path: Path) -> Iterator[Dict[str, Any]]:
    if not path.is_file():
        return
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            label = int(obj.get("label", 0))
            cmd = str(obj.get("command_line") or "")
            proc = infer_process_name(cmd, str(obj.get("lolbin_binary") or ""))
            origin = f"jsonl:{obj.get('source', 'unknown')}"
            yield {
                "command_line": cmd,
                "process_name": proc,
                "parent_process": "",
                "process_path": "",
                "signed": "true",
                "network_connection": "false",
                "destination": "",
                "integrity_level": "medium",
                "mitre_technique": "",
                "command_source": str(obj.get("source") or ""),
                "rule_category": "",
                "label": label,
                "dataset_origin": origin,
            }


def iter_liblol_csv(path: Path) -> Iterator[Dict[str, Any]]:
    if not path.is_file():
        return
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            if not isinstance(row, dict):
                continue
            prompt = (row.get("prompt") or "").strip()
            if len(prompt) < 4:
                continue
            proc = infer_process_name(prompt)
            yield {
                "command_line": prompt,
                "process_name": proc,
                "parent_process": "",
                "process_path": "",
                "signed": "true",
                "network_connection": "false",
                "destination": "",
                "integrity_level": "medium",
                "mitre_technique": "",
                "command_source": "liblol",
                "rule_category": "",
                "label": 1,
                "dataset_origin": "liblol_csv",
            }


def iter_lolbas_catalog_csv(path: Path) -> Iterator[Dict[str, Any]]:
    if not path.is_file():
        return
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            if not isinstance(row, dict):
                continue
            cmd = (row.get("Command") or "").strip()
            if len(cmd) < 4:
                continue
            filename = (row.get("Filename") or "").strip().strip('"')
            proc = infer_process_name(cmd, filename)
            mitre = (row.get("MITRE ATT&CK technique") or "").strip()
            yield {
                "command_line": cmd,
                "process_name": proc,
                "parent_process": "",
                "process_path": "",
                "signed": "true",
                "network_connection": "false",
                "destination": "",
                "integrity_level": "medium",
                "mitre_technique": mitre,
                "command_source": "lolbas_catalog",
                "rule_category": (row.get("Command Category") or "").strip(),
                "label": 1,
                "dataset_origin": "lolbas_csv",
            }


def ingest_source(
    rows: Iterator[Dict[str, Any]],
    seen: Set[str],
    stats: Dict[str, int],
    source_name: str,
    max_rows: Optional[int],
    total_cap: Optional[int],
    *,
    dedup: bool,
    register_keys: bool,
) -> Iterator[Dict[str, str]]:
    """
    dedup: skip rows whose dedup_key is already in seen.
    register_keys: add each emitted row's key to seen (for aux-only dedup against synthetic).
    """
    added = 0
    skipped_dup = 0
    for row in rows:
        if total_cap is not None and stats["written"] >= total_cap:
            break
        if max_rows is not None and added >= max_rows:
            break
        stats["seen"] += 1
        label = int(row.get("label", 0))
        proc = str(row.get("process_name") or "")
        cmd = str(row.get("command_line") or "")
        key = dedup_key(label, proc, cmd)
        if dedup and key in seen:
            skipped_dup += 1
            stats["duplicate"] += 1
            continue
        if register_keys:
            seen.add(key)
        enriched = enrich_row(row)
        if enriched["dataset_origin"] != row.get("dataset_origin"):
            enriched["dataset_origin"] = str(row.get("dataset_origin") or "")
        stats["written"] += 1
        added += 1
        stats[f"from_{source_name}"] = stats.get(f"from_{source_name}", 0) + 1
        yield enriched
    stats[f"skipped_dup_{source_name}"] = skipped_dup


def write_csv_batched(
    path: Path,
    row_iter: Iterator[Dict[str, str]],
    *,
    batch_size: int = WRITE_BATCH,
) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    batch: List[Dict[str, str]] = []
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(ML_FEATURE_CSV_COLUMNS), extrasaction="ignore")
        writer.writeheader()
        for row in row_iter:
            batch.append(row)
            count += 1
            if len(batch) >= batch_size:
                writer.writerows(batch)
                batch.clear()
                print(f"  written {count:,} rows...", flush=True)
        if batch:
            writer.writerows(batch)
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract LOLBin ML features from all repo sources.")
    parser.add_argument(
        "--unprocessed-csv",
        type=Path,
        default=UNPROCESSED_MERGED,
        help="Primary merged dataset CSV (default: datasets/winlolbin_gt_unprocessed_merged_10m.csv)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output machine-ready feature CSV",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="JSON summary of row counts per source",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=WRITE_BATCH,
        help="Flush to disk every N rows",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=None,
        help="Cap total output rows (smoke test)",
    )
    parser.add_argument(
        "--skip-auxiliary",
        action="store_true",
        help="Only process synthetic merged CSV",
    )
    parser.add_argument(
        "--keep-duplicates",
        action="store_true",
        help="Keep duplicate normalized commands from the synthetic dataset (not recommended)",
    )
    args = parser.parse_args()

    if not args.unprocessed_csv.is_file():
        print(f"ERROR: unprocessed dataset CSV not found: {args.unprocessed_csv}", file=sys.stderr)
        return 1

    seen: Set[str] = set()
    stats: Dict[str, int] = {
        "seen": 0,
        "written": 0,
        "duplicate": 0,
    }

    def combined_iter() -> Iterator[Dict[str, str]]:
        unprocessed_dedup = not args.keep_duplicates
        unprocessed_register = True  # always index base dataset keys for aux dedup

        # 1) Primary simulated dataset (keep all rows unless --dedup-all)
        print(f"Loading unprocessed dataset: {args.unprocessed_csv}")
        yield from ingest_source(
            iter_unprocessed_csv(args.unprocessed_csv, "simulated_sysmon"),
            seen,
            stats,
            "simulated_sysmon",
            max_rows=None,
            total_cap=args.max_rows,
            dedup=unprocessed_dedup,
            register_keys=unprocessed_register,
        )
        if args.skip_auxiliary:
            return
        if args.max_rows is not None and stats["written"] >= args.max_rows:
            return

        # Auxiliary sources: skip rows already present in the unprocessed dataset.
        aux_dedup = True

        # 2) JSONL dataset
        print(f"Loading jsonl: {JSONL_PATH}")
        yield from ingest_source(
            iter_jsonl(JSONL_PATH),
            seen,
            stats,
            "jsonl",
            max_rows=None,
            total_cap=args.max_rows,
            dedup=aux_dedup,
            register_keys=True,
        )
        if args.max_rows is not None and stats["written"] >= args.max_rows:
            return

        # 3) libLOL raw CSV
        print(f"Loading libLOL: {LIBLOL_CSV}")
        yield from ingest_source(
            iter_liblol_csv(LIBLOL_CSV),
            seen,
            stats,
            "liblol_csv",
            max_rows=None,
            total_cap=args.max_rows,
            dedup=aux_dedup,
            register_keys=True,
        )
        if args.max_rows is not None and stats["written"] >= args.max_rows:
            return

        # 4) LOLBAS catalog commands
        print(f"Loading LOLBAS catalog: {LOLBAS_CSV}")
        yield from ingest_source(
            iter_lolbas_catalog_csv(LOLBAS_CSV),
            seen,
            stats,
            "lolbas_csv",
            max_rows=None,
            total_cap=args.max_rows,
            dedup=aux_dedup,
            register_keys=True,
        )

    t0 = time.perf_counter()
    print(f"Writing features to {args.output}")
    total = write_csv_batched(args.output, combined_iter(), batch_size=args.batch_size)
    elapsed = time.perf_counter() - t0

    manifest = {
        "output_csv": str(args.output),
        "total_rows": total,
        "elapsed_seconds": round(elapsed, 2),
        "columns": list(ML_FEATURE_CSV_COLUMNS),
        "sources": {
            "unprocessed_dataset_csv": str(args.unprocessed_csv),
            "jsonl": str(JSONL_PATH),
            "liblol_csv": str(LIBLOL_CSV),
            "lolbas_csv": str(LOLBAS_CSV),
        },
        "stats": stats,
        "dedup_mode": "keep_duplicates" if args.keep_duplicates else "dedup_all",
        "notes": [
            "attack_rationale and attack_outcome excluded from output (label leakage).",
            "host and username excluded from output (memorization risk).",
            "Default: all unprocessed dataset rows kept; jsonl/liblol/lolbas only add keys not in the base dataset.",
            "Use --dedup-all to collapse rows with identical normalized command lines.",
            "model_text and cmd_normalized included for downstream TF-IDF or neural encoders.",
        ],
    }
    args.manifest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"\nDone: {total:,} rows in {elapsed:.1f}s")
    print(f"  duplicates skipped: {stats['duplicate']:,}")
    for k, v in sorted(stats.items()):
        if k.startswith("from_"):
            print(f"  {k}: {v:,}")
    print(f"  manifest: {args.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
