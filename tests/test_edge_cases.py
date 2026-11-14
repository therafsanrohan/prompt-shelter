"""Tests for ambiguous edge cases, false-positive evaluation, and limitations."""

import json
import unittest
from pathlib import Path

from detection import analyze_prompt

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "prompt_cases.json"


class TestEdgeCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(FIXTURES_PATH, "r", encoding="utf-8") as f:
            cls.cases = json.load(f)

    def test_ambiguous_edge_cases_and_document_false_positive_behavior(self):
        ambiguous_cases = [c for c in self.cases if c["case_type"] == "ambiguous"]
        for case in ambiguous_cases:
            with self.subTest(case_id=case["id"], notes=case["notes"]):
                score, classification, matched = analyze_prompt(case["prompt"])
                # In regex rule systems, quoted attack phrases in educational or technical text
                # trigger the pattern (inherent limitation of regex vs semantic intent).
                matched_ids = [m["rule_id"] for m in matched]
                for expected_id in case["expected_rule_ids"]:
                    self.assertIn(
                        expected_id,
                        matched_ids,
                        f"Expected regex match for educational quotation in {case['id']}",
                    )

    def test_partial_word_boundaries_do_not_falsely_trigger(self):
        # Words containing 'jailbreak' inside benign words?
        # Note: 'jailbreak' rule pattern in original rules was 'jailbreak'.
        # Word boundary tests for new rules:
        # e.g., 'you are now' vs 'you are nowadays'
        score, classification, matched = analyze_prompt("You are nowadays working on machine learning.")
        self.assertNotIn("ROLE_REASSIGNMENT", [m["rule_id"] for m in matched])

        # 'system override' vs 'system overrider' or unrelated
        score, classification, matched = analyze_prompt("Operating system overrides default sound.")
        self.assertNotIn("FAKE_AUTHORITY", [m["rule_id"] for m in matched])


if __name__ == "__main__":
    unittest.main()

