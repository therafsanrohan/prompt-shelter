"""Local rule-based prompt injection detection."""

import re
from typing import TypedDict


class DetectionRule(TypedDict):
    pattern: str
    weight: int
    name: str
    category: str
    description: str


RULES: list[DetectionRule] = [
    {
        "pattern": r"ignore (all )?(previous|prior) instructions",
        "weight": 35,
        "name": "Instruction Override",
        "category": "Instruction override",
        "description": "Attempts to supersede earlier instructions.",
    },
    {
        "pattern": r"reveal (the )?(system prompt|hidden prompt)",
        "weight": 35,
        "name": "System Prompt Extraction",
        "category": "Prompt extraction",
        "description": "Requests disclosure of a system or hidden prompt.",
    },
    {
        "pattern": r"show me (the )?(system prompt|hidden instructions)",
        "weight": 30,
        "name": "Prompt Extraction",
        "category": "Prompt extraction",
        "description": "Requests hidden instructions or system prompt content.",
    },
    {
        "pattern": r"disregard (all )?(previous|prior) instructions",
        "weight": 35,
        "name": "Instruction Override",
        "category": "Instruction override",
        "description": "Attempts to supersede earlier instructions.",
    },
    {
        "pattern": r"bypass (all )?(safety|security|safeguards)",
        "weight": 30,
        "name": "Safety Bypass",
        "category": "Safety bypass",
        "description": "Asks to bypass safety or security safeguards.",
    },
    {
        "pattern": r"jailbreak",
        "weight": 30,
        "name": "Jailbreak Attempt",
        "category": "Jailbreak",
        "description": "Contains the configured jailbreak indicator.",
    },
    {
        "pattern": r"developer message",
        "weight": 15,
        "name": "Developer Message Reference",
        "category": "Instruction reference",
        "description": "References a developer message.",
    },
    {
        "pattern": r"ignore your rules",
        "weight": 30,
        "name": "Rule Override",
        "category": "Instruction override",
        "description": "Asks the model to disregard its rules.",
    },
    {
        "pattern": r"act as (an? )?(unrestricted|unfiltered)",
        "weight": 30,
        "name": "Unrestricted Role Request",
        "category": "Role manipulation",
        "description": "Requests an unrestricted or unfiltered role.",
    },
    {
        "pattern": r"reveal your hidden instructions",
        "weight": 35,
        "name": "Hidden Instruction Extraction",
        "category": "Prompt extraction",
        "description": "Requests disclosure of hidden instructions.",
    },
]


class MatchedRule(TypedDict):
    name: str
    weight: int
    category: str
    description: str
    pattern: str


def analyze_prompt(prompt: str) -> tuple[int, str, list[MatchedRule]]:
    """Return the existing capped weighted score, label, and matching rules."""
    matched: list[MatchedRule] = []

    for rule in RULES:
        if re.search(rule["pattern"], prompt, re.IGNORECASE):
            matched.append(
                {
                    "name": rule["name"],
                    "weight": rule["weight"],
                    "category": rule["category"],
                    "description": rule["description"],
                    "pattern": rule["pattern"],
                }
            )

    score = min(100, sum(item["weight"] for item in matched))
    if score >= 60:
        classification = "MALICIOUS"
    elif score >= 25:
        classification = "SUSPICIOUS"
    else:
        classification = "SAFE"

    return score, classification, matched
