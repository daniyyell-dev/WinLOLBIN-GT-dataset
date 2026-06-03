# Dataset generation scripts

WinLOLBIN-GT v1.0.1 is built in two stages: **simulate Sysmon rows**, then **extract ML features**.

All scripts are in [`../scripts/`](../scripts/). Output CSVs are published on **Zenodo** (not in this GitHub repo).

Visual overview (sources, 10M path, lab Sysmon → OpenSearch): [dataset-generation-diagrams.md](dataset-generation-diagrams.md).

## Pipeline

```
LOLBAS API + libLOL CSV + benign templates
        │
        ▼
generate_winlolbin_gt_dataset.py  (seed 20260515)
        │
        ├── winlolbin_gt_unprocessed_benign_5m.csv
        ├── winlolbin_gt_unprocessed_malicious_5m.csv
        └── winlolbin_gt_unprocessed_merged_10m.csv   ← Zenodo ships merged only
        │
        ▼
extract_lolbin_features.py
        │
        └── winlolbin_gt_processed_features_10m_plus.csv   ← Zenodo
```

Optional: `build_winlolbin_gt_dataset_artifacts.py` — class splits and 500-row samples for packaging.

## Scripts

| File | Purpose |
|------|---------|
| `generate_winlolbin_gt_dataset.py` | Build unprocessed Sysmon EID 1 rows at scale |
| `winlolbin_parametric.py` | Unique command families when catalog keys collide |
| `extract_lolbin_features.py` | Normalization, 55 features, `model_text`, dedup |
| `lolbin_features.py` | Feature and flag definitions (imported by extract) |
| `build_winlolbin_gt_dataset_artifacts.py` | Split CSVs and write sample extracts |

### `generate_winlolbin_gt_dataset.py`

- Default: **5,000,000** rows per class (`--rows-per-class`).
- **Phase A:** sample LOLBAS / libLOL / benign templates until per-class caps.
- **Phase B:** parametric commands with `-wlgtRef` indices for guaranteed unique `dedup_key`.
- Malicious mix: ~88% libLOL (`cmd_huge_known_commented.csv`), rest LOLBAS.
- Benign mix: ~36% generic desktop/admin, ~64% LOLBAS benign usage.
- Remote URLs: RFC 5737 / lab-safe hosts only.

```bash
python3 generate_winlolbin_gt_dataset.py --rows-per-class 5000000
```

### `extract_lolbin_features.py`

- Reads merged unprocessed CSV plus optional JSONL / libLOL / LOLBAS rows.
- Dedup: `SHA256(label | process_basename | lower(cmd_normalized))`.
- Drops leakage fields from export: `attack_rationale`, `attack_outcome`, `host`, `username`.

```bash
python3 extract_lolbin_features.py \
  --output /path/to/winlolbin_gt_processed_features_10m_plus.csv \
  --manifest /path/to/winlolbin_gt_processed_features_manifest.json
```

Smoke test: `--max-rows 5000`.

### `lolbin_features.py`

Shared library: path/URL/IP/B64 masking, structural counts, 22 suspicious-token flags, process/parent context. Not run directly.

### `build_winlolbin_gt_dataset_artifacts.py`

Post-processes the 10M+ processed file into benign/malicious splits and 500-line samples (used for Zenodo previews).

## External inputs

| Source | Used for |
|--------|----------|
| [LOLBAS API](https://lolbas-project.github.io/api/lolbas.json) | Command templates, MITRE IDs |
| `liblol/cmd_huge_known_commented.csv` | Malicious prompts |
| `lolbin_dataset.jsonl` | Optional extra rows at extract |
| `lolbas_api/lolbas.csv` | Optional catalog rows at extract |

In the Detecton monorepo these live under `Machine Learning/data/`. When cloning **only** this GitHub repo, provide the same paths or run from the full monorepo.

## Requirements

- Python **3.10+**
- Standard library only for generation/extract
- **~50 GB** disk for full 10M + 10M pipeline

## Zenodo bundle

The Zenodo deposit (`zenodo-submission/` in the paper repo) contains the built CSVs, samples, manifest, and `docs/column-schema.md`. This GitHub repo does not duplicate those files.
