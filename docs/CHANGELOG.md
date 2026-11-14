# Changelog: Prompt Shelter Detection Engine Enhancement

All notable changes to the Prompt Shelter detection engine and research application are documented here.

---

## [v1.0.0] - 2026-11-14

### Added
- **10 New Detection Rules:**
  - `ROLE_REASSIGNMENT` (Role manipulation, weight: 20)
  - `FAKE_AUTHORITY` (Authority impersonation, weight: 20)
  - `POLICY_REPLACEMENT` (Policy manipulation, weight: 25)
  - `FAKE_SYSTEM_MESSAGE` (Authority impersonation, weight: 20)
  - `BOUNDARY_MANIPULATION` (Boundary manipulation, weight: 25)
  - `CREDENTIAL_EXTRACTION` (Sensitive data extraction, weight: 30)
  - `CONTEXT_EXTRACTION` (Context extraction, weight: 25)
  - `REFUSAL_SUPPRESSION` (Safety bypass, weight: 20)
  - `INSTRUCTION_CONCEALMENT` (Covert instruction, weight: 20)
  - `INDIRECT_PROMPT_INJECTION` (Indirect injection, weight: 25)
- **Precompiled Rule Engine:** Precompiles all 20 regex patterns at startup to optimize execution speed.
- **Input Normalization & Safety:**
  - Length capping at 50,000 characters to prevent resource exhaustion / ReDoS.
  - Unicode NFKC normalization.
  - Consistent whitespace collapsing and CRLF -> LF handling.
  - Non-string and empty/None safe handling.
- **Explainable Findings:**
  - Returns `matched_phrase`, `rule_id`, and human-readable `explanation` for each matched rule.
- **Category-Aware Scoring & Deduplication:**
  - Deduplicates identical rule matches.
  - Implements category contribution capping (`CATEGORY_CAPS`) to prevent artificial inflation from overlapping synonymous rules.
  - Clamps all scores strictly to `[0, 100]`.
- **Modular Test Suite & Benchmark Dataset:**
  - `tests/fixtures/prompt_cases.json` containing 42 labeled test cases.
  - Modular test suites covering positive injection, safe negatives, scoring boundaries, normalization, and edge cases.
- **Documentation Suite:**
  - `docs/PROJECT_ARCHITECTURE.md`
  - `docs/DETECTION_RULES.md`
  - `docs/DETECTION_EVALUATION.md`
  - `docs/TESTING_GUIDE.md`
  - `docs/CHANGELOG.md`

### Changed
- **`app.py`:**
  - Updated Prompt Scanner results section to display 4-column summary metrics (Score, Classification, Matched Rules, Matched Categories), matched phrases, rule IDs, and structured explanations.
  - Detection Rules page now dynamically displays all 20 rules, category tags, unique rule IDs, risk weights, and active statuses.
- **`test_detection_storage.py`:**
  - Expanded unit test suite covering original rules, new candidate rules, explainability, category capping, and storage integrity.

### Preserved
- All 10 original detection rules, their weights, and regex patterns.
- Classification cutoffs: `SAFE` (0–24), `SUSPICIOUS` (25–59), `MALICIOUS` (60–100).
- SQLite storage schema and existing 30 historical scan records in `prompt_shelter.db`.
- Public API `analyze_prompt(prompt: str) -> tuple[int, str, list[MatchedRule]]`.

