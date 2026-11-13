"""Small local SQLite store for privacy-conscious scan history."""

import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict


DB_PATH = Path(__file__).with_name("prompt_shelter.db")
PREVIEW_LIMIT = 120


class ScanRecord(TypedDict):
    id: int
    scanned_at: str
    prompt_preview: str | None
    classification: str
    risk_score: int
    matched_rules: list[str]


def initialize_database(db_path: Path | str = DB_PATH) -> None:
    """Create the local history table if it does not exist."""
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                prompt_preview TEXT,
                classification TEXT NOT NULL
                    CHECK (classification IN ('SAFE', 'SUSPICIOUS', 'MALICIOUS')),
                risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
                matched_rules TEXT NOT NULL
            )
            """
        )


def _redacted_preview(prompt: str) -> str:
    compact = " ".join(prompt.split())
    compact = re.sub(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        "[email]",
        compact,
        flags=re.IGNORECASE,
    )
    compact = re.sub(
        r"\b(?:sk-[A-Za-z0-9_-]{12,}|"
        r"(?:api[_-]?key|token|secret)\s*[:=]\s*\S+)\b",
        "[secret]",
        compact,
        flags=re.IGNORECASE,
    )
    if len(compact) > PREVIEW_LIMIT:
        return compact[: PREVIEW_LIMIT - 1].rstrip() + "…"
    return compact


def save_scan(
    prompt: str,
    risk_score: int,
    classification: str,
    matched_rules: list[str],
    store_preview: bool = False,
    db_path: Path | str = DB_PATH,
) -> None:
    """Persist scan metadata, never the full submitted prompt."""
    initialize_database(db_path)
    preview = _redacted_preview(prompt) if store_preview else None
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO scans
                (scanned_at, prompt_preview, classification, risk_score, matched_rules)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                preview,
                classification,
                risk_score,
                json.dumps(matched_rules),
            ),
        )


def get_scans(db_path: Path | str = DB_PATH) -> list[ScanRecord]:
    """Return scan records newest first."""
    initialize_database(db_path)
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, scanned_at, prompt_preview, classification, risk_score, matched_rules
            FROM scans
            ORDER BY scanned_at DESC, id DESC
            """
        ).fetchall()
    return [
        {
            "id": row[0],
            "scanned_at": row[1],
            "prompt_preview": row[2],
            "classification": row[3],
            "risk_score": row[4],
            "matched_rules": json.loads(row[5]),
        }
        for row in rows
    ]


def clear_scans(db_path: Path | str = DB_PATH) -> None:
    """Remove every scan record from the local history."""
    initialize_database(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute("DELETE FROM scans")
