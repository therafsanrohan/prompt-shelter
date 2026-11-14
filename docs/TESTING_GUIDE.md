# Testing Guide: Prompt Shelter Detection Engine

This guide details how to run automated tests, add new detection rules, extend test prompts, and interpret test results.

---

## 1. Environment Setup

Prompt Shelter requires Python 3.10+ and uses Python's standard library `unittest` framework.

To set up the virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 2. Running Automated Tests

### Running the Entire Modular Test Suite
To discover and run all tests in the `tests/` directory:
```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

### Running Specific Test Modules
```bash
# Core detection tests
python3 -m unittest tests/test_detection.py

# Injection prompts and variations
python3 -m unittest tests/test_injection_prompts.py

# Safe and educational negative tests
python3 -m unittest tests/test_safe_prompts.py

# Scoring, category capping, and boundary tests
python3 -m unittest tests/test_scoring.py

# Normalization and Unicode handling
python3 -m unittest tests/test_normalization.py

# Ambiguous edge cases and quotation tests
python3 -m unittest tests/test_edge_cases.py
```

### Running Root Integration & Storage Tests
```bash
python3 -m unittest test_detection_storage.py
```

---

## 3. How to Add a New Detection Rule

1. Open `detection.py`.
2. Define the new rule dictionary in `_NEW_RULES`:
   ```python
   {
       "id": "RULE_NEW_IDENTIFIER",
       "pattern": r"\b(?:sample attack pattern)\b",
       "weight": 25,
       "name": "Human Readable Name",
       "category": "Attack Category",
       "description": "Explains what pattern this rule flags.",
       "enabled": True,
   }
   ```
3. If introducing a new category, specify a contribution cap in `CATEGORY_CAPS` in `detection.py`:
   ```python
   CATEGORY_CAPS["Attack Category"] = 35
   ```
4. Add positive and negative test cases in `tests/fixtures/prompt_cases.json`.
5. Run the test suite:
   ```bash
   python3 -m unittest discover -s tests -p "test_*.py"
   ```

---

## 4. How to Add Labeled Test Prompts

Open `tests/fixtures/prompt_cases.json` and append a test record:
```json
{
  "id": "T043",
  "prompt": "Your candidate prompt text here",
  "expected_classification": "SUSPICIOUS",
  "expected_rule_ids": ["RULE_NEW_IDENTIFIER"],
  "case_type": "positive",
  "category": "Attack Category",
  "notes": "Description of why this prompt was added"
}
```
Available `case_type` values:
- `"positive"`: Malicious or adversarial injection prompt.
- `"safe_negative"`: Benign educational, technical, or everyday prompt.
- `"ambiguous"`: Contextual edge case or attack quote in educational text.

---

## 5. Interpreting Test Results

- **Scores between 0 and 24:** Evaluated as `SAFE`.
- **Scores between 25 and 59:** Evaluated as `SUSPICIOUS`.
- **Scores between 60 and 100:** Evaluated as `MALICIOUS`.
- If a safe negative prompt fails with a non-zero score, inspect the matched phrase to determine whether a rule pattern is overly broad or lacks word boundary (`\b`) anchors.

