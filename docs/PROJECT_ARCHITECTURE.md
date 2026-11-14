# Project Architecture: Prompt Shelter

## 1. Overview
Prompt Shelter is a local, privacy-conscious security research prototype designed to inspect user prompts for prompt injection indicators, calculate risk scores, classify threat levels, and provide transparent explainability without transmitting sensitive user data to third-party APIs.

---

## 2. Architecture & Processing Pipeline

```text
User Input
    │
    ▼
Input Validation & Normalization (`normalize_input`)
    │ (Unicode NFKC, CRLF -> LF, horizontal whitespace collapse, length cap)
    ▼
Rule Matching Engine (`_COMPILED_RULES`)
    │ (Precompiled regex evaluation across 20 configured rules)
    ▼
Match Collection (`MatchedRule` list)
    │ (Rule ID, name, category, weight, matched phrase, explanation)
    ▼
Category Deduplication & Aggregation (`calculate_risk_score`)
    │ (Category-capped contribution prevents artificial inflation)
    ▼
Centralized Classification (`classify_score`)
    │ (0–24: SAFE, 25–59: SUSPICIOUS, 60–100: MALICIOUS)
    ▼
Structured Result Delivery
    ├──► Streamlit UI (`app.py`)
    │      ├── Metrics (Score, Classification, Matched Rules, Matched Categories)
    │      ├── Explainable Finding Cards (Rule ID, category, phrase, pattern)
    │      └── Dynamic 20-Rule Library Viewer
    └──► Local SQLite Storage (`storage.py`)
           ├── Redacted/truncated prompt preview (optional)
           ├── Scanned timestamp & metadata
           └── Scan Analytics & Trend Dashboards
```

---

## 3. Module Responsibilities

| Module | Core Responsibilities |
|---|---|
| `detection.py` | Input validation, Unicode NFKC normalization, precompiled rule library (20 rules), match collection, category-capped risk scoring, centralized classification, and explainable findings. |
| `storage.py` | Local SQLite database initialization, privacy-preserving redacted previews, persistence of scan metadata, and query helpers for history and analytics. |
| `app.py` | Streamlit user interface featuring Overview metrics, Prompt Scanner with explainable cards, Detection Rules library, Scan History, Analytics trends, Research Documentation, and Settings. |
| `tests/` | Repeatable unit test suites covering positive attacks, safe negatives, boundary conditions, scoring aggregation, normalization, and edge cases with labeled fixture data. |

---

## 4. Scoring Architecture & Rationale

### The Single-Vector Inflation Problem
In raw additive scanners, an attacker using several synonymous phrases in the same category (e.g., repeating multiple instruction override phrases) could artificially trigger an exaggerated score, while a prompt displaying diverse threat vectors across distinct categories would not be differentiated.

### Category-Capped Aggregation Formula
1. **Deduplication:** Multiple matches of the identical rule pattern are counted only once.
2. **Category Grouping:** Findings are grouped by their threat category.
3. **Category Contribution Capping:** Each category has a maximum contribution ceiling (e.g., `Instruction override`: 45 max, `Role manipulation`: 40 max, `Jailbreak`: 40 max).
4. **Overall Score Capping:** The aggregated sum of category contributions is clamped to `[0, 100]`.

```text
Category_Score(cat) = min(sum(weights in cat), Category_Cap(cat))
Final_Risk_Score    = min(100, sum(Category_Score(cat) for cat in categories))
```

### Classification Thresholds
- **0 – 24:** `SAFE`
- **25 – 59:** `SUSPICIOUS`
- **60 – 100:** `MALICIOUS`

---

## 5. Privacy & Storage Safeguards
- Full submitted prompt text is **never** saved to disk.
- When preview storage is explicitly enabled by the user:
  - Inputs are truncated to 120 characters max.
  - Email addresses and common API keys / bearer tokens are redacted to `[email]` and `[secret]`.
- Storage resides strictly on the local SQLite database (`prompt_shelter.db`).

---

## 6. Known Research Limitations
1. **Regular Expression Limitations:** Regex patterns identify known syntactic patterns but cannot reason over semantic intent.
2. **False Positives on Quotation:** Benign academic papers or security discussions that literally quote attack strings (e.g., explaining `SYSTEM OVERRIDE`) will trigger the corresponding rule.
3. **Obfuscation & Multilingual Attacks:** Novel rephrasing, Leetspeak, base64 encoding, and non-English injections are not covered by English-only lexical rules.
4. **Heuristic Nature:** Risk scores represent rule-activation heuristics, not formal probabilities of malice.

