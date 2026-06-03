#!/usr/bin/env python3
"""
Split processed feature CSVs by label and write 500-line sample files.

Author:  Daniel Jeremiah
GitHub:  https://github.com/daniyyell-dev
LinkedIn: https://www.linkedin.com/in/daniel-jeremiah/
Project: WinLOLBIN-GT — https://github.com/daniyyell-dev/WinLOLBIN-GT-dataset
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

PAPER_DIR = Path(__file__).resolve().parent.parent
DATASETS = PAPER_DIR / "datasets"
SAMPLE_LINES = 500


def write_sample(src: Path, dst: Path, max_lines: int = SAMPLE_LINES) -> int:
    with src.open(newline="", encoding="utf-8", errors="replace") as fin, dst.open(
        "w", newline="", encoding="utf-8"
    ) as fout:
        reader = csv.reader(fin)
        writer = csv.writer(fout)
        header = next(reader)
        writer.writerow(header)
        count = 0
        for row in reader:
            writer.writerow(row)
            count += 1
            if count >= max_lines:
                break
    return count


def split_by_label(src: Path, benign_dst: Path, malicious_dst: Path) -> tuple[int, int]:
    benign = malicious = 0
    with src.open(newline="", encoding="utf-8", errors="replace") as fin:
        reader = csv.DictReader(fin)
        fieldnames = reader.fieldnames or []
        label_idx = fieldnames.index("label")
        with benign_dst.open("w", newline="", encoding="utf-8") as f_ben, malicious_dst.open(
            "w", newline="", encoding="utf-8"
        ) as f_mal:
            w_ben = csv.writer(f_ben)
            w_mal = csv.writer(f_mal)
            w_ben.writerow(fieldnames)
            w_mal.writerow(fieldnames)
            for row in reader:
                line = [row.get(c, "") for c in fieldnames]
                if row.get("label") == "1":
                    w_mal.writerow(line)
                    malicious += 1
                else:
                    w_ben.writerow(line)
                    benign += 1
    return benign, malicious


def main() -> int:
    ap = argparse.ArgumentParser(description="Build split + sample WinLOLBIN-GT dataset artifacts.")
    ap.add_argument(
        "--processed-merged",
        type=Path,
        default=DATASETS / "winlolbin_gt_processed_features_10m_plus.csv",
    )
    ap.add_argument(
        "--unprocessed-merged",
        type=Path,
        default=DATASETS / "winlolbin_gt_unprocessed_merged_10m.csv",
    )
    args = ap.parse_args()

    if args.processed_merged.is_file():
        ben_p = DATASETS / "winlolbin_gt_processed_features_benign_5m.csv"
        mal_p = DATASETS / "winlolbin_gt_processed_features_malicious_5m.csv"
        b, m = split_by_label(args.processed_merged, ben_p, mal_p)
        print(f"Split processed: benign={b:,} malicious={m:,}")
        for kind, path in (
            ("benign", ben_p),
            ("malicious", mal_p),
            ("merged", args.processed_merged),
        ):
            dst = DATASETS / f"winlolbin_gt_sample_processed_features_{kind}_500_lines.csv"
            n = write_sample(path if kind != "merged" else args.processed_merged, dst)
            print(f"  sample {dst.name}: {n} rows")

    if args.unprocessed_merged.is_file():
        ben_u = DATASETS / "winlolbin_gt_unprocessed_benign_5m.csv"
        mal_u = DATASETS / "winlolbin_gt_unprocessed_malicious_5m.csv"
        if not ben_u.is_file() or not mal_u.is_file():
            b, m = split_by_label(
                args.unprocessed_merged,
                ben_u,
                mal_u,
            )
            print(f"Split unprocessed: benign={b:,} malicious={m:,}")
        for kind, path in (
            ("benign", DATASETS / "winlolbin_gt_unprocessed_benign_5m.csv"),
            ("malicious", DATASETS / "winlolbin_gt_unprocessed_malicious_5m.csv"),
            ("merged", args.unprocessed_merged),
        ):
            if path.is_file():
                dst = DATASETS / f"winlolbin_gt_sample_unprocessed_{kind}_500_lines.csv"
                n = write_sample(path, dst)
                print(f"  sample {dst.name}: {n} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
