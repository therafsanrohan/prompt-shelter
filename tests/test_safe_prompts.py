"""Tests for safe educational prompts and benign negative examples."""

import json
import unittest
from pathlib import Path

from detection import analyze_prompt

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "prompt_cases.json"


class TestSafePrompts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(FIXTURES_PATH, "r", encoding="utf-8") as f:
            cls.cases = json.load(f)

    def test_fixture_safe_negative_cases(self):
        safe_cases = [c for c in self.cases if c["case_type"] == "safe_negative"]
        for case in safe_cases:
            with self.subTest(case_id=case["id"], notes=case["notes"]):
                score, classification, matched = analyze_prompt(case["prompt"])
                self.assertEqual(score, 0, f"Safe case {case['id']} received non-zero score {score}.")
                self.assertEqual(classification, "SAFE")
                self.assertEqual(len(matched), 0)

    def test_additional_educational_and_everyday_prompts(self):
        benign_prompts = [
            "How do neural networks perform backpropagation?",
            "Can you explain the difference between symmetric and asymmetric encryption?",
            "What are best practices for securing REST APIs with OAuth2?",
            "Write a short bedtime story about a curious kitten.",
            "Translate 'Good morning, how are you today?' into Japanese.",
            "Provide a summary of the French Revolution for high school students.",
            "How can I optimize an SQL join query on two large tables?",
            "What causes photosynthesis in plant cells?",
            "Give me suggestions for a 3-day itinerary in Rome.",
            "Write a polite email declining a job offer because I accepted another position.",
        ]
        for prompt in benign_prompts:
            with self.subTest(prompt=prompt):
                score, classification, matched = analyze_prompt(prompt)
                self.assertEqual(score, 0)
                self.assertEqual(classification, "SAFE")
                self.assertEqual(len(matched), 0)


if __name__ == "__main__":
    unittest.main()

