"""Tests for text normalization, whitespace handling, and unicode validation."""

import unittest
from detection import MAX_PROMPT_LENGTH, analyze_prompt, normalize_input


class TestNormalization(unittest.TestCase):
    def test_non_string_and_none_inputs(self):
        self.assertEqual(normalize_input(None), "")
        self.assertEqual(normalize_input(12345), "")
        self.assertEqual(normalize_input(["list", "input"]), "")
        self.assertEqual(normalize_input({"key": "val"}), "")

        score, classification, matched = analyze_prompt(None)
        self.assertEqual((score, classification, matched), (0, "SAFE", []))

    def test_empty_and_whitespace_only(self):
        self.assertEqual(normalize_input(""), "")
        self.assertEqual(normalize_input("     "), "")
        self.assertEqual(normalize_input("\n\t\r  \n"), "")

        self.assertEqual(analyze_prompt(""), (0, "SAFE", []))
        self.assertEqual(analyze_prompt("   \n\t  "), (0, "SAFE", []))

    def test_whitespace_and_newline_normalization(self):
        raw = "you\t\tare   \t \t  now   an \t assistant"
        normalized = normalize_input(raw)
        self.assertEqual(normalized, "you are now an assistant")

        # Windows CRLF to LF
        crlf = "line 1\r\nline 2"
        self.assertEqual(normalize_input(crlf), "line 1\nline 2")

    def test_unicode_nfkc_normalization(self):
        # Fullwidth ASCII characters normalized to standard ASCII
        fullwidth = "ｙｏｕ ａｒｅ ｎｏｗ"
        normalized = normalize_input(fullwidth)
        self.assertEqual(normalized, "you are now")
        score, classification, matched = analyze_prompt(fullwidth)
        self.assertTrue(any(m["rule_id"] == "ROLE_REASSIGNMENT" for m in matched))

    def test_length_capping(self):
        long_input = "a" * (MAX_PROMPT_LENGTH + 5000)
        normalized = normalize_input(long_input)
        self.assertEqual(len(normalized), MAX_PROMPT_LENGTH)


if __name__ == "__main__":
    unittest.main()
