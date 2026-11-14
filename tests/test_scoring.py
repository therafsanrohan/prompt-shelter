"""Tests for scoring boundaries, category contribution caps, and deduplication."""

import unittest
from detection import (
    CATEGORY_CAPS,
    analyze_prompt,
    calculate_risk_score,
    classify_score,
)


class TestScoring(unittest.TestCase):
    def test_classification_exact_boundaries(self):
        # 0–24: SAFE
        self.assertEqual(classify_score(0), "SAFE")
        self.assertEqual(classify_score(24), "SAFE")

        # 25–59: SUSPICIOUS
        self.assertEqual(classify_score(25), "SUSPICIOUS")
        self.assertEqual(classify_score(59), "SUSPICIOUS")

        # 60–100: MALICIOUS
        self.assertEqual(classify_score(60), "MALICIOUS")
        self.assertEqual(classify_score(100), "MALICIOUS")

    def test_score_never_exceeds_100_or_drops_below_0(self):
        # Massive synthetic match list
        synthetic_matches = [
            {"rule_id": f"R_{i}", "category": f"Cat_{i}", "weight": 40}
            for i in range(20)
        ]
        score = calculate_risk_score(synthetic_matches)
        self.assertEqual(score, 100)

        # Empty match
        self.assertEqual(calculate_risk_score([]), 0)

    def test_duplicate_exact_rule_is_deduplicated(self):
        # Same rule repeated multiple times
        matches = [
            {"rule_id": "RULE_01", "name": "Test", "category": "Instruction override", "weight": 35},
            {"rule_id": "RULE_01", "name": "Test", "category": "Instruction override", "weight": 35},
        ]
        score = calculate_risk_score(matches)
        self.assertEqual(score, 35)

    def test_category_capping_limits_single_attack_vector(self):
        # 3 rules in "Instruction override": weights 35 + 35 + 30 = 100
        # Category cap is 45
        matches = [
            {"rule_id": "RULE_01", "name": "Override 1", "category": "Instruction override", "weight": 35},
            {"rule_id": "RULE_04", "name": "Override 2", "category": "Instruction override", "weight": 35},
            {"rule_id": "RULE_08", "name": "Override 3", "category": "Instruction override", "weight": 30},
        ]
        score = calculate_risk_score(matches)
        self.assertEqual(score, CATEGORY_CAPS["Instruction override"])
        self.assertEqual(score, 45)
        self.assertEqual(classify_score(score), "SUSPICIOUS")

    def test_multi_category_accumulation_reaches_malicious(self):
        # Rule in Instruction override (cap 45, weight 35) + Rule in Jailbreak (cap 40, weight 30) = 65 -> MALICIOUS
        matches = [
            {"rule_id": "RULE_01", "name": "Override", "category": "Instruction override", "weight": 35},
            {"rule_id": "RULE_06", "name": "Jailbreak", "category": "Jailbreak", "weight": 30},
        ]
        score = calculate_risk_score(matches)
        self.assertEqual(score, 65)
        self.assertEqual(classify_score(score), "MALICIOUS")


if __name__ == "__main__":
    unittest.main()

