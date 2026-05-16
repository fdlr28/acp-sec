"""ACP-SEC Continuous Monitoring — watchlist, scheduled scans, drift alerts."""

from __future__ import annotations

import json
import sqlite3
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Default DB location (next to the package, not inside it).
_DEFAULT_DB = Path(__file__).resolve().parent.parent / "acpsec_monitor.db"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class WatchlistEntry:
    url: str
    schedule: str = "daily"   # hourly | daily | weekly
    added_at: float = field(default_factory=time.time)
    last_scan: float | None = None
    last_score: float | None = None
    enabled: bool = True


@dataclass
class ScoreRecord:
    url: str
    score: float
    max_score: float
    band: str
    timestamp: float


@dataclass
class DriftAlert:
    url: str
    old_score: float
    new_score: float
    delta: float
    timestamp: float


# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------

class Monitor:
    """
    Lightweight SQLite-backed monitoring for ACP-SEC agents.

    Stores watchlist, score history, and drift alerts.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_tables()

    def close(self) -> None:
        self.conn.close()

    def _init_tables(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS watchlist (
                url TEXT PRIMARY KEY,
                schedule TEXT NOT NULL DEFAULT 'daily',
                added_at REAL NOT NULL,
                last_scan REAL,
                last_score REAL,
                enabled INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS score_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                score REAL NOT NULL,
                max_score REAL NOT NULL,
                band TEXT NOT NULL,
                timestamp REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS drift_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                old_score REAL NOT NULL,
                new_score REAL NOT NULL,
                delta REAL NOT NULL,
                timestamp REAL NOT NULL
            );
        """)
        self.conn.commit()

    # -- watchlist ----------------------------------------------------------

    def add_agent(self, url: str, schedule: str = "daily") -> WatchlistEntry:
        """Add an agent to the watchlist. Overwrites if already exists."""
        entry = WatchlistEntry(url=url, schedule=schedule)
        self.conn.execute(
            "INSERT OR REPLACE INTO watchlist (url, schedule, added_at, enabled) "
            "VALUES (?, ?, ?, 1)",
            (url, schedule, entry.added_at),
        )
        self.conn.commit()
        return entry

    def remove_agent(self, url: str) -> bool:
        """Remove an agent from the watchlist. Returns True if it existed."""
        cur = self.conn.execute("DELETE FROM watchlist WHERE url = ?", (url,))
        self.conn.commit()
        return cur.rowcount > 0

    def list_agents(self) -> list[WatchlistEntry]:
        """List all agents on the watchlist."""
        rows = self.conn.execute(
            "SELECT url, schedule, added_at, last_scan, last_score, enabled "
            "FROM watchlist ORDER BY added_at"
        ).fetchall()
        return [
            WatchlistEntry(
                url=r["url"],
                schedule=r["schedule"],
                added_at=r["added_at"],
                last_scan=r["last_scan"],
                last_score=r["last_score"],
                enabled=bool(r["enabled"]),
            )
            for r in rows
        ]

    def get_agent(self, url: str) -> WatchlistEntry | None:
        """Get a single watchlist entry by URL."""
        row = self.conn.execute(
            "SELECT url, schedule, added_at, last_scan, last_score, enabled "
            "FROM watchlist WHERE url = ?",
            (url,),
        ).fetchone()
        if not row:
            return None
        return WatchlistEntry(
            url=row["url"],
            schedule=row["schedule"],
            added_at=row["added_at"],
            last_scan=row["last_scan"],
            last_score=row["last_score"],
            enabled=bool(row["enabled"]),
        )

    # -- score history ------------------------------------------------------

    def record_score(self, url: str, score: float, max_score: float, band: str) -> ScoreRecord:
        """Record a score for an agent and check for drift."""
        now = time.time()
        record = ScoreRecord(
            url=url, score=score, max_score=max_score, band=band, timestamp=now
        )
        self.conn.execute(
            "INSERT INTO score_history (url, score, max_score, band, timestamp) "
            "VALUES (?, ?, ?, ?, ?)",
            (url, score, max_score, band, now),
        )
        # Update watchlist last_scan / last_score
        self.conn.execute(
            "UPDATE watchlist SET last_scan = ?, last_score = ? WHERE url = ?",
            (now, score, url),
        )
        self.conn.commit()

        # Check for drift (compare with previous score)
        self._check_drift(url, score, now)

        return record

    def get_history(self, url: str, limit: int = 50) -> list[ScoreRecord]:
        """Get score history for an agent, most recent first."""
        rows = self.conn.execute(
            "SELECT url, score, max_score, band, timestamp "
            "FROM score_history WHERE url = ? ORDER BY timestamp DESC LIMIT ?",
            (url, limit),
        ).fetchall()
        return [
            ScoreRecord(
                url=r["url"],
                score=r["score"],
                max_score=r["max_score"],
                band=r["band"],
                timestamp=r["timestamp"],
            )
            for r in rows
        ]

    def get_trust_index(self, url: str, window: int = 5) -> float | None:
        """
        ACP-SEC Trust Index — rolling average of last `window` scores.
        Returns None if no history exists.
        """
        rows = self.conn.execute(
            "SELECT score FROM score_history WHERE url = ? "
            "ORDER BY timestamp DESC LIMIT ?",
            (url, window),
        ).fetchall()
        if not rows:
            return None
        scores = [r["score"] for r in rows]
        return round(sum(scores) / len(scores), 1)

    # -- drift detection ----------------------------------------------------

    DRIFT_THRESHOLD = 10.0  # alert if score drops by more than this

    def _check_drift(self, url: str, new_score: float, now: float) -> DriftAlert | None:
        """Compare new score with previous; create alert if drift exceeds threshold."""
        rows = self.conn.execute(
            "SELECT score FROM score_history WHERE url = ? "
            "ORDER BY timestamp DESC LIMIT 2",
            (url,),
        ).fetchall()
        if len(rows) < 2:
            return None
        old_score = rows[1]["score"]  # second-most-recent
        delta = old_score - new_score
        if delta > self.DRIFT_THRESHOLD:
            alert = DriftAlert(
                url=url,
                old_score=old_score,
                new_score=new_score,
                delta=delta,
                timestamp=now,
            )
            self.conn.execute(
                "INSERT INTO drift_alerts (url, old_score, new_score, delta, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (url, old_score, new_score, delta, now),
            )
            self.conn.commit()
            return alert
        return None

    def get_alerts(self, url: str | None = None, limit: int = 20) -> list[DriftAlert]:
        """Get drift alerts, optionally filtered by URL."""
        if url:
            rows = self.conn.execute(
                "SELECT url, old_score, new_score, delta, timestamp "
                "FROM drift_alerts WHERE url = ? ORDER BY timestamp DESC LIMIT ?",
                (url, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT url, old_score, new_score, delta, timestamp "
                "FROM drift_alerts ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            DriftAlert(
                url=r["url"],
                old_score=r["old_score"],
                new_score=r["new_score"],
                delta=r["delta"],
                timestamp=r["timestamp"],
            )
            for r in rows
        ]

    # -- scheduled scan check -----------------------------------------------

    def get_due_agents(self) -> list[WatchlistEntry]:
        """Return agents whose next scan is due based on their schedule."""
        now = time.time()
        entries = self.list_agents()
        due = []
        for entry in entries:
            if not entry.enabled:
                continue
            if entry.last_scan is None:
                due.append(entry)
                continue
            interval = _schedule_interval(entry.schedule)
            if now - entry.last_scan >= interval:
                due.append(entry)
        return due

    # -- webhook notifications ----------------------------------------------

    @staticmethod
    def send_webhook(
        webhook_url: str,
        title: str,
        description: str,
        fields: dict[str, str] | None = None,
    ) -> bool:
        """
        Send a notification via webhook (Discord/Slack format).

        Supports Discord webhooks (embeds) and generic JSON POST.
        Returns True if the webhook was sent successfully.
        """
        # Detect Discord webhook
        if "discord.com" in webhook_url or "discordapp.com" in webhook_url:
            payload = {
                "embeds": [{
                    "title": title,
                    "description": description,
                    "color": 0x5865F2,  # Discord blurple
                    "fields": [
                        {"name": k, "value": v, "inline": True}
                        for k, v in (fields or {}).items()
                    ],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }]
            }
        # Detect Telegram
        elif "api.telegram.org" in webhook_url:
            text = f"*{title}*\n{description}"
            if fields:
                text += "\n" + "\n".join(f"• {k}: {v}" for k, v in fields.items())
            payload = {"text": text, "parse_mode": "Markdown"}
        # Generic (Slack-compatible)
        else:
            payload = {
                "text": f"*{title}*\n{description}",
                "attachments": [{
                    "fields": [
                        {"title": k, "value": v, "short": True}
                        for k, v in (fields or {}).items()
                    ]
                }]
            }

        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status in (200, 204)
        except (urllib.error.URLError, OSError):
            return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _schedule_interval(schedule: str) -> float:
    """Convert schedule name to seconds."""
    return {
        "hourly": 3600,
        "daily": 86400,
        "weekly": 604800,
    }.get(schedule, 86400)
