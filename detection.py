"""Local rule-based prompt injection detection."""

from __future__ import annotations

import re
import unicodedata
from typing import Any, TypedDict


class DetectionRule(TypedDict, total=False):
    id: str
    pattern: str
    weight: int
    name: str
    category: str
    description: str
    enabled: bool


class MatchedRule(TypedDict, total=False):
    rule_id: str
    name: str
    weight: int
    category: str
    description: str
    pattern: str
    matched_phrase: str
    explanation: str


# Maximum allowed length for input prompts to prevent resource exhaustion / ReDoS
MAX_PROMPT_LENGTH: int = 50000

# Category scoring caps to prevent duplicate score inflation
CATEGORY_CAPS: dict[str, int] = {
    "Instruction override": 45,
    "Prompt extraction": 45,
    "Safety bypass": 40,
    "Jailbreak": 40,
    "Instruction reference": 20,
    "Role manipulation": 40,
    "Authority impersonation": 35,
    "Policy manipulation": 35,
    "Boundary manipulation": 35,
    "Sensitive data extraction": 40,
    "Context extraction": 35,
    "Covert instruction": 30,
    "Indirect injection": 35,
}

# The 10 original baseline detection rules
_ORIGINAL_RULES: list[DetectionRule] = [
    {
        "id": "RULE_01_INSTRUCTION_OVERRIDE_PREV",
        "pattern": r"ignore (all )?(previous|prior) instructions",
        "weight": 35,
        "name": "Instruction Override",
        "category": "Instruction override",
        "description": "Attempts to supersede earlier instructions.",
        "enabled": True,
    },
    {
        "id": "RULE_02_SYSTEM_PROMPT_EXTRACTION",
        "pattern": r"reveal (the )?(system prompt|hidden prompt)",
        "weight": 35,
        "name": "System Prompt Extraction",
        "category": "Prompt extraction",
        "description": "Requests disclosure of a system or hidden prompt.",
        "enabled": True,
    },
    {
        "id": "RULE_03_PROMPT_EXTRACTION",
        "pattern": r"show me (the )?(system prompt|hidden instructions)",
        "weight": 30,
        "name": "Prompt Extraction",
        "category": "Prompt extraction",
        "description": "Requests hidden instructions or system prompt content.",
        "enabled": True,
    },
    {
        "id": "RULE_04_INSTRUCTION_OVERRIDE_DISREGARD",
        "pattern": r"disregard (all )?(previous|prior) instructions",
        "weight": 35,
        "name": "Instruction Override",
        "category": "Instruction override",
        "description": "Attempts to supersede earlier instructions.",
        "enabled": True,
    },
    {
        "id": "RULE_05_SAFETY_BYPASS",
        "pattern": r"bypass (all )?(safety|security|safeguards)",
        "weight": 30,
        "name": "Safety Bypass",
        "category": "Safety bypass",
        "description": "Asks to bypass safety or security safeguards.",
        "enabled": True,
    },
    {
        "id": "RULE_06_JAILBREAK_ATTEMPT",
        "pattern": r"jailbreak",
        "weight": 30,
        "name": "Jailbreak Attempt",
        "category": "Jailbreak",
        "description": "Contains the configured jailbreak indicator.",
        "enabled": True,
    },
    {
        "id": "RULE_07_DEVELOPER_MESSAGE",
        "pattern": r"developer message",
        "weight": 15,
        "name": "Developer Message Reference",
        "category": "Instruction reference",
        "description": "References a developer message.",
        "enabled": True,
    },
    {
        "id": "RULE_08_RULE_OVERRIDE",
        "pattern": r"ignore your rules",
        "weight": 30,
        "name": "Rule Override",
        "category": "Instruction override",
        "description": "Asks the model to disregard its rules.",
        "enabled": True,
    },
    {
        "id": "RULE_09_UNRESTRICTED_ROLE",
        "pattern": r"act as (an? )?(unrestricted|unfiltered)",
        "weight": 30,
        "name": "Unrestricted Role Request",
        "category": "Role manipulation",
        "description": "Requests an unrestricted or unfiltered role.",
        "enabled": True,
    },
    {
        "id": "RULE_10_HIDDEN_INSTRUCTION_EXTRACTION",
        "pattern": r"reveal your hidden instructions",
        "weight": 35,
        "name": "Hidden Instruction Extraction",
        "category": "Prompt extraction",
        "description": "Requests disclosure of hidden instructions.",
        "enabled": True,
    },
]

# The 10 new candidate detection rules (Rules 11-20)
_NEW_RULES: list[DetectionRule] = [
    {
        "id": "ROLE_REASSIGNMENT",
        "pattern": r"\b(?:you are now|from now on you are|your new role is)\b",
        "weight": 20,
        "name": "Role Reassignment",
        "category": "Role manipulation",
        "description": "Detects attempts to assign the assistant a new role or identity that bypasses its original operating constraints.",
        "enabled": True,
    },
    {
        "id": "FAKE_AUTHORITY",
        "pattern": r"\b(?:system override|admin override|root command|priority instruction)\b",
        "weight": 20,
        "name": "Fake Authority Injection",
        "category": "Authority impersonation",
        "description": "Detects language that impersonates privileged system or administrator instructions.",
        "enabled": True,
    },
    {
        "id": "POLICY_REPLACEMENT",
        "pattern": r"\b(?:replace|overwrite|modify|rewrite)\b.{0,40}\b(?:system instructions|system policy|safety policy|original rules)\b",
        "weight": 25,
        "name": "Policy Replacement",
        "category": "Policy manipulation",
        "description": "Detects attempts to replace, rewrite, or overwrite system or safety instructions.",
        "enabled": True,
    },
    {
        "id": "FAKE_SYSTEM_MESSAGE",
        "pattern": r"(?m)^\s*(?:\[?\s*(?:system|developer)\s*\]?)\s*:",
        "weight": 20,
        "name": "Fake System or Developer Message",
        "category": "Authority impersonation",
        "description": "Detects message-like prefixes that imitate trusted instruction roles.",
        "enabled": True,
    },
    {
        "id": "BOUNDARY_MANIPULATION",
        "pattern": r"(?:<\|im_end\|>|<\|fim_suffix\|>|</?(?:system|instructions)>|###\s*(?:system|new instructions))",
        "weight": 25,
        "name": "Instruction Boundary Manipulation",
        "category": "Boundary manipulation",
        "description": "Detects tokens or tags commonly used to imitate or manipulate prompt or message boundaries.",
        "enabled": True,
    },
    {
        "id": "CREDENTIAL_EXTRACTION",
        "pattern": r"\b(?:reveal|expose|print|display|dump|extract)\b.{0,50}\b(?:api keys?|passwords?|access tokens?|secret keys?|credentials)\b",
        "weight": 30,
        "name": "Credential Extraction",
        "category": "Sensitive data extraction",
        "description": "Detects requests to reveal, print, dump, or extract credentials and secrets.",
        "enabled": True,
    },
    {
        "id": "CONTEXT_EXTRACTION",
        "pattern": r"\b(?:dump|export|reveal|extract|print)\b.{0,50}\b(?:conversation history|chat history|hidden context|internal memory|private context)\b",
        "weight": 25,
        "name": "Context and Memory Extraction",
        "category": "Context extraction",
        "description": "Detects attempts to extract hidden context, private conversation history, or internal memory.",
        "enabled": True,
    },
    {
        "id": "REFUSAL_SUPPRESSION",
        "pattern": r"\b(?:do not|never|don't)\s+(?:refuse|decline|reject|say no)\b",
        "weight": 20,
        "name": "Refusal Suppression",
        "category": "Safety bypass",
        "description": "Detects explicit attempts to suppress model refusal behavior.",
        "enabled": True,
    },
    {
        "id": "INSTRUCTION_CONCEALMENT",
        "pattern": r"\b(?:hide|conceal|silently|secretly)\b.{0,50}\b(?:instructions|actions|commands|changes)\b",
        "weight": 20,
        "name": "Instruction Concealment",
        "category": "Covert instruction",
        "description": "Detects instructions to conceal behavior or hidden commands from the user.",
        "enabled": True,
    },
    {
        "id": "INDIRECT_PROMPT_INJECTION",
        "pattern": r"\b(?:when\s+(?:reading|summarizing|processing|analyzing)|while\s+(?:reading|summarizing|processing))\b.{0,100}\b(?:ignore the user|follow these instructions|override the original task)\b",
        "weight": 25,
        "name": "Indirect Prompt Injection",
        "category": "Indirect injection",
        "description": "Detects instructions embedded in content being processed that attempt to override the user's task.",
        "enabled": True,
    },
]

# Combined master rule list: 20 rules
RULES: list[DetectionRule] = _ORIGINAL_RULES + _NEW_RULES

# Precompile regexes for high performance and safety
_COMPILED_RULES: list[tuple[DetectionRule, re.Pattern[str]]] = [
    (rule, re.compile(rule["pattern"], re.IGNORECASE))
    for rule in RULES
    if rule.get("enabled", True)
]


def normalize_input(prompt: Any, max_length: int = MAX_PROMPT_LENGTH) -> str:
    """Safely validate, truncate, and normalize prompt text for matching."""
    if not isinstance(prompt, str):
        return ""
    if not prompt:
        return ""

    # Truncate at maximum length to prevent resource exhaustion / ReDoS
    if len(prompt) > max_length:
        prompt = prompt[:max_length]

    # Normalize unicode forms (NFKC compatibility decomposition followed by canonical composition)
    normalized = unicodedata.normalize("NFKC", prompt)

    # Normalize carriage returns and newlines
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")

    # Normalize horizontal whitespace (tabs, non-breaking spaces) while preserving newlines
    # for multiline patterns like FAKE_SYSTEM_MESSAGE
    normalized = re.sub(r"[^\S\n]+", " ", normalized)

    # Strip surrounding whitespace
    return normalized.strip()


def classify_score(score: int) -> str:
    """Centralized classifier adhering to documented risk thresholds."""
    if score >= 60:
        return "MALICIOUS"
    if score >= 25:
        return "SUSPICIOUS"
    return "SAFE"


def calculate_risk_score(
    matched_rules: list[MatchedRule],
    category_caps: dict[str, int] = CATEGORY_CAPS,
) -> int:
    """Calculate aggregated risk score with category deduplication and capping.
    
    Formula:
      1. Deduplicate multiple matches of the exact same rule ID / pattern.
      2. Group matches by category.
      3. Sum weights within each category and cap at the category cap.
      4. Sum category contributions and cap final score at 100.
    """
    if not matched_rules:
        return 0

    # Deduplicate matches by rule_id or pattern
    unique_matches: dict[str, MatchedRule] = {}
    for match in matched_rules:
        key = match.get("rule_id") or match.get("pattern") or match.get("name", "")
        if key not in unique_matches:
            unique_matches[key] = match

    # Group by category
    category_totals: dict[str, int] = {}
    for match in unique_matches.values():
        category = match.get("category", "General")
        weight = match.get("weight", 0)
        category_totals[category] = category_totals.get(category, 0) + weight

    # Apply category caps
    total_score = 0
    for category, total in category_totals.items():
        cap = category_caps.get(category, 50)
        total_score += min(total, cap)

    return min(100, max(0, total_score))


def analyze_prompt(prompt: str) -> tuple[int, str, list[MatchedRule]]:
    """Return the capped category-aware risk score, classification, and explainable findings.
    
    Backward compatible with all callers expecting (int, str, list[MatchedRule]).
    """
    if not prompt or not isinstance(prompt, str):
        return 0, "SAFE", []

    clean_prompt = normalize_input(prompt)
    if not clean_prompt.strip():
        return 0, "SAFE", []

    matched: list[MatchedRule] = []

    for rule, compiled_regex in _COMPILED_RULES:
        match_obj = compiled_regex.search(clean_prompt)
        if match_obj:
            matched_phrase = match_obj.group(0).strip()
            rule_id = rule.get("id", rule["name"])
            matched.append(
                {
                    "rule_id": rule_id,
                    "name": rule["name"],
                    "weight": rule["weight"],
                    "category": rule["category"],
                    "description": rule["description"],
                    "pattern": rule["pattern"],
                    "matched_phrase": matched_phrase,
                    "explanation": f"Matched pattern for {rule['name']} in category '{rule['category']}': \"{matched_phrase}\"",
                }
            )

    score = calculate_risk_score(matched)
    classification = classify_score(score)

    return score, classification, matched
