# WinLOLBIN-GT — how the dataset is built

Audience-friendly diagrams for the **10 million row ground-truth dataset**. Live lab topology (Sysmon → OpenSearch) is in **section 5**.

Export figures from [mermaid.live](https://mermaid.live). Recommended for papers and README: **1**, **2**, **3**, **5**.

Script details: [generation-scripts.md](generation-scripts.md).

---

## 1. Big picture — how WinLOLBIN-GT ground truth is built

Every event mirrors a real **Sysmon process-creation (EID 1)** record. Labels come from the trusted knowledge each command originates from — ground truth, not inference.

```mermaid
%%{init: {"theme": "neutral", "flowchart": {"curve": "basis", "padding": 20, "nodeSpacing": 28, "rankSpacing": 52}}%%
flowchart TB

  %% ── Open-source knowledge ──────────────────────────────────
  subgraph oss["Open Source"]
    direction LR
    lolbas["LOLBAS Project<br/>documented abuse of built-in Windows tools"]
    art["Atomic Red Team<br/>real attack test procedures mapped to ATT&CK"]
    liblol["Attacker Command Library<br/>large open corpus of real malicious command lines"]
  end

  %% ── Threat intelligence ────────────────────────────────────
  subgraph ti["Threat Intelligence & Incident Reports"]
    direction LR
    cti["CTI Feeds<br/>structured threat indicators from the community"]
    vendor["Vendor Write-ups<br/>security research and malware analysis reports"]
    breach["Breach Investigation Findings<br/>real attacker techniques seen in live incidents"]
  end

  %% ── Benign sources ─────────────────────────────────────────
  subgraph ben["Benign Sources"]
    direction LR
    lolbas_b["LOLBIN Legitimate Use<br/>same Windows tools used for normal admin work"]
    benign_tpl["Windows Activity Patterns<br/>desktop tasks, installs, IT operations"]
  end

  %% ── Label authority ────────────────────────────────────────
  mitre(["MITRE ATT&CK<br/>assigns tactic and technique to every malicious row"])

  %% ── Ground-truth pipeline ──────────────────────────────────
  collect["Collect and normalise<br/>commands from all sources"]

  sysmon["Shape each command as a Sysmon EID 1 event<br/>process · parent process · command line · user · host · timestamp"]

  label["Attach verified ground-truth label<br/>benign or malicious + ATT&CK technique ID"]

  expand["Generate realistic command variations<br/>different flags, file paths, parent-child execution chains"]

  dedup["Deduplicate<br/>remove any event seen before, keyed on label + process + command"]

  balance["Balance the dataset<br/>5 million benign  +  5 million malicious, interleaved and shuffled"]

  tenm[["10 million labelled events"]]

  feat["Extract 55 behaviour signals<br/>path masking · suspicious token flags · parent context · training text"]

  output[["WinLOLBIN-GT — 10,006,645 rows<br/>ground-truth labelled · ready for machine learning"]]

  %% ── Edges ──────────────────────────────────────────────────
  oss   --> collect
  ti    --> collect
  ben   --> collect
  mitre -. "names the technique" .-> label

  collect --> sysmon
  sysmon  --> label
  label   --> expand
  expand  --> dedup
  dedup   --> balance
  balance --> tenm
  tenm    --> feat
  feat    --> output
```

Each malicious row traces to a documented real-world technique. Each benign row traces to a known legitimate Windows task.

---

## 2. How we reach 10 million labelled events

Each row is one **process start** (Sysmon Event ID 1 style): who ran what command, from which parent program, on which lab-style host.

```mermaid
%%{init: {"theme": "neutral", "flowchart": {"curve": "stepAfter", "padding": 20, "nodeSpacing": 42, "rankSpacing": 52}}%%
flowchart TB
  subgraph sources["Step 1 — Choose command content from trusted sources"]
    s1["LOLBIN catalogue<br/>documented abuse and legitimate use"]
    s2["Attack command library<br/>realistic malicious lines"]
    s3["Benign activity templates<br/>help flags, installs, daily tasks"]
  end

  subgraph build["Step 2 — Build one synthetic event per unique command"]
    b1["Fill in safe placeholders<br/>example URLs and paths only"]
    b2["Pick matching parent program<br/>e.g. Word → PowerShell chains"]
    b3["Add host name, user, time, severity<br/>synthetic lab identities"]
    b4["Attach MITRE technique where mapped"]
  end

  subgraph unique["Step 3 — Enforce uniqueness at 10M scale"]
    u1["Phase A — Sample from catalogues<br/>~400k benign · ~250k malicious keys"]
    u2["Phase B — Variant families with index tags<br/>until 5M per class is reached"]
    u3["Duplicate checker<br/>reject same label + program + command"]
  end

  subgraph out["Step 4 — Combine and publish"]
    o1["5M benign file + 5M malicious file"]
    o2["Random fair shuffle → 10M merged file"]
    o3["Zenodo: merged unprocessed CSV ~8.5 GB"]
  end

  s1 --> b1
  s2 --> b1
  s3 --> b1
  b1 --> b2
  b2 --> b3
  b3 --> b4
  b4 --> u1
  u1 --> u2
  u2 --> u3
  u3 --> o1
  o1 --> o2
  o2 --> o3
```

**Why 10,006,645 processed rows (not exactly 10M)?**  
After the 10M simulation, a small set of **extra unique rows** from supplementary catalogues is added during feature extraction (645 rows in the v1.0.1 build). The Zenodo manifest lists exact counts.

**Uniqueness rule (plain language):**  
Two rows are considered the same if they share the same **benign or malicious label**, the same **program name**, and the same **normalized command text** (paths and URLs masked so host-specific spelling does not create fake diversity).

---

## 3. Phase A and Phase B — filling 5 million per class

```mermaid
%%{init: {"theme": "neutral", "flowchart": {"curve": "stepAfter", "padding": 18, "nodeSpacing": 38, "rankSpacing": 48}}%%
flowchart LR
  subgraph phaseA["Phase A — Catalogue sampling"]
    a_m["Malicious mix<br/>~88% attack library<br/>~12% LOLBIN abuse templates"]
    a_b["Benign mix<br/>~64% LOLBIN normal use<br/>~36% everyday admin activity"]
    a_cap["Stop when catalogue keys exhausted<br/>~250k malicious · ~400k benign unique commands"]
  end

  subgraph phaseB["Phase B — Scaled variants"]
    b_fam["Rotate command families<br/>tasks, WMI, downloads, scripting, etc."]
    b_tag["Embed a unique index marker in each command<br/>so keys never collide"]
    b_goal["Continue until 5,000,000 rows per class"]
  end

  phaseA --> phaseB
```

| Phase | Audience summary |
|-------|------------------|
| **A** | Reuse **realistic command text** from public LOLBIN docs, the attack library, and benign templates. |
| **B** | When the catalogues would repeat, **generate fresh command lines** from rule-based families until five million unique lines exist per class. |

---

## 4. From raw simulated events to the ML table

```mermaid
%%{init: {"theme": "neutral", "flowchart": {"curve": "stepAfter", "padding": 20, "nodeSpacing": 40, "rankSpacing": 50}}%%
flowchart TB
  raw["10M merged raw events<br/>command line + parent + host + QA text"]

  n1["Mask volatile text<br/>paths, URLs, IPs, users, hashes"]
  n2["Build training sentence<br/>program + parent + command"]
  n3["Count structure signals<br/>length, entropy, punctuation"]
  n4["Set behaviour flags<br/>encoded PowerShell, certutil, etc."]
  n5["Drop fields that would leak answers<br/>host name, username, attack story text"]

  extra["Add a few hundred unique rows<br/>from extra catalogues if not already present"]

  out["Processed dataset<br/>10,006,645 rows · 62 columns<br/>Zenodo ~5.8 GB"]

  raw --> n1
  n1 --> n2
  n2 --> n3
  n3 --> n4
  n4 --> n5
  n5 --> extra
  extra --> out
```

**What is removed before ML export (on purpose):**  
Fields like **attack story**, **host name**, and **username** stay in the **unprocessed** Zenodo file for human review but are **not** copied into the processed training file, so models learn from **behaviour**, not from memorizing `WS-ENG-001` or `CONTOSO\user`.

---

## 5. Detecton lab — where live Sysmon logs come from

This is **separate** from the 10M CSV build, but it shows how the same kind of event (process create) is collected on real machines in the lab.

```mermaid
%%{init: {"theme": "neutral", "flowchart": {"curve": "stepAfter", "padding": 20, "nodeSpacing": 42, "rankSpacing": 52}}%%
flowchart TB
  subgraph lan["Lab network 192.168.0.0/24"]
    dc["Domain controller<br/>192.168.0.30"]
    w1["Workstation 1<br/>192.168.0.24"]
    w2["Workstation 2<br/>192.168.0.28"]
    w3["Ubuntu desktop<br/>192.168.0.29"]
    hunt["HUNT01 detection engineering<br/>192.168.0.25"]
    siem["SIEM01 OpenSearch + Dashboards<br/>192.168.0.31 :9200 / :5601"]
    llm["LLM01<br/>192.168.0.37"]
    ndr["Clear NDR optional<br/>192.168.0.36"]
  end

  subgraph endpoint["On each Windows endpoint"]
    evtx["Windows Event Logs<br/>Security · Sysmon · PowerShell"]
    fb["Fluent Bit agent<br/>tails EVTX and forwards JSON"]
  end

  subgraph siem_store["On SIEM01"]
    idx["Per-host indices<br/>detecton-win-desktop-w2<br/>detecton-win-desktop-w1 · etc."]
    sa["Security Analytics detectors<br/>findings and alerts"]
    ml["ML scores optional<br/>same command-line models"]
  end

  dc --> evtx
  w1 --> evtx
  w2 --> evtx
  evtx --> fb
  fb -->|"HTTP bulk :9200"| siem
  siem --> idx
  idx --> sa
  idx --> ml
```

| Lab asset | IP (example) | Role |
|-----------|----------------|------|
| SIEM01 | 192.168.0.31 | Stores logs; Dashboards UI port 5601 |
| Domain controller | 192.168.0.30 | AD DNS lab; optional IIS |
| Workstation 1 | 192.168.0.24 | Member PC; Sysmon + Fluent Bit |
| Workstation 2 | 192.168.0.28 | Member PC; e.g. index `detecton-win-desktop-w2` |
| HUNT01 | 192.168.0.25 | Velociraptor, Caldera, Jupyter |
| Ubuntu desktop | 192.168.0.29 | Linux logs → `detecton-linux-*` (separate indices) |

**Shipping path:** Sysmon writes **process creation** events → Fluent Bit reads channels → JSON documents POST to **OpenSearch** on SIEM01 → one index slug per hostname.

---

## 6. Synthetic hosts vs real lab hosts

Synthetic CSV rows use **fictional workstation names and users** (for example `WS-ENG-001`, `CONTOSO\ajones`) drawn from a fixed pool so the dataset is safe to share.  
Live OpenSearch documents use **real lab host slugs** from actual machine names.

```mermaid
%%{init: {"theme": "neutral", "flowchart": {"curve": "stepAfter", "padding": 16, "nodeSpacing": 36, "rankSpacing": 46}}%%
flowchart LR
  subgraph sim_pool["Synthetic event pool in generator"]
    h1["WS-ENG-001 · LAP-UK-101<br/>SRV-APP-01 · SRV-FILE-01"]
    u1["CONTOSO\\users and service accounts"]
    t1["Random timestamps over 30-day window"]
  end

  subgraph real_lab["Real lab ingest"]
    h2["detecton-win-desktop-w2<br/>detecton-win-desktop-w1"]
    u2["DANIIYELL domain accounts"]
    t2["Live @timestamp from endpoint clock"]
  end

  sim_pool --> zen["Zenodo CSV ground truth"]
  real_lab --> os["OpenSearch + WinLOLBIN-GT-Tel"]
```

---

## 7. Source catalogue — friendly names mapped to build role

| What readers see | What it provides | Used in |
|------------------|------------------|---------|
| **LOLBIN command catalogue** | Official list of Windows programs and example command lines | Malicious and benign simulation |
| **Attack command library** | Long-form realistic attack commands and narratives | Mostly malicious simulation (~88% of early malicious draws) |
| **Benign activity templates** | Ordinary admin and user workflows | Benign simulation (~36% of early benign draws) |
| **MITRE ATT&CK** | Technique IDs (e.g. PowerShell execution, ingress tools) | Tags on both synthetic and live-oriented rules |
| **Supplementary row catalogues** | Small extra JSON/CSV sources | Only at feature step; skips duplicates |
| **Safe URL policy** | Documentation-only network addresses (RFC 5737) | All synthetic downloads in CSV |

No live attacker infrastructure is embedded in the synthetic files.

---

## 8. End-to-end timeline (recommended slide order)

```mermaid
%%{init: {"theme": "neutral", "flowchart": {"curve": "stepAfter", "padding": 18, "nodeSpacing": 35, "rankSpacing": 45}}%%
flowchart LR
  t1["1. Ingest knowledge<br/>LOLBAS · libLOL · templates"]
  t2["2. Simulate 10M events<br/>unique commands"]
  t3["3. Shuffle and store<br/>unprocessed CSV"]
  t4["4. Engineer features<br/>55 + training text"]
  t5["5. Publish Zenodo<br/>~14 GB"]
  t6["6. Optional lab<br/>Sysmon → SIEM"]
  t7["7. Train and evaluate<br/>Char-CNN etc."]

  t1 --> t2 --> t3 --> t4 --> t5
  t6 --> t7
  t5 -.->|"train"| t7
```

---

## 9. Row counts reference (v1.0.1)

| Stage | Benign | Malicious | Total |
|-------|--------|-----------|-------|
| Per-class simulation target | 5,000,000 | 5,000,000 | — |
| Merged unprocessed (Zenodo) | 5,000,000 | 5,000,000 | **10,000,000** |
| Processed with features (Zenodo) | — | — | **10,006,645** |
| Live labelled telemetry (separate) | 16,727 | 15,000 | 31,727 |

---

## Related diagrams

Broader ML and Char-CNN architecture: `Research_Paper/01-dataset-paper/architecture-diagrams.md` in the monorepo.
