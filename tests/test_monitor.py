"""Tests for the ACP-SEC Monitor module (v0.3.0)."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest

from acpsec.monitor import Monitor, WatchlistEntry, ScoreRecord, DriftAlert


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test_monitor.db"


@pytest.fixture
def monitor(tmp_db: Path) -> Monitor:
    return Monitor(tmp_db)


# ---------------------------------------------------------------------------
# Watchlist management
# ---------------------------------------------------------------------------

class TestWatchlist:
    def test_add_agent(self, monitor: Monitor):
        entry = monitor.add_agent("https://example.com/agent.yaml", "daily")
        assert entry.url == "https://example.com/agent.yaml"
        assert entry.schedule == "daily"
        assert entry.enabled is True

    def test_list_agents_empty(self, monitor: Monitor):
        assert monitor.list_agents() == []

    def test_list_agents_returns_added(self, monitor: Monitor):
        monitor.add_agent("https://a.example.com/agent.yaml")
        monitor.add_agent("https://b.example.com/agent.yaml")
        agents = monitor.list_agents()
        assert len(agents) == 2
        assert agents[0].url == "https://a.example.com/agent.yaml"
        assert agents[1].url == "https://b.example.com/agent.yaml"

    def test_remove_agent(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml")
        assert monitor.remove_agent("https://example.com/agent.yaml") is True
        assert monitor.list_agents() == []

    def test_remove_nonexistent_agent(self, monitor: Monitor):
        assert monitor.remove_agent("https://nonexistent.example.com") is False

    def test_get_agent(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml", "hourly")
        entry = monitor.get_agent("https://example.com/agent.yaml")
        assert entry is not None
        assert entry.url == "https://example.com/agent.yaml"
        assert entry.schedule == "hourly"

    def test_get_nonexistent_agent(self, monitor: Monitor):
        assert monitor.get_agent("https://nonexistent.example.com") is None

    def test_add_overwrites_existing(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml", "daily")
        monitor.add_agent("https://example.com/agent.yaml", "weekly")
        agents = monitor.list_agents()
        assert len(agents) == 1
        assert agents[0].schedule == "weekly"

    def test_schedule_options(self, monitor: Monitor):
        for schedule in ["hourly", "daily", "weekly"]:
            monitor.add_agent(f"https://{schedule}.example.com/agent.yaml", schedule)
        agents = monitor.list_agents()
        assert len(agents) == 3
        schedules = {a.schedule for a in agents}
        assert schedules == {"hourly", "daily", "weekly"}


# ---------------------------------------------------------------------------
# Score history
# ---------------------------------------------------------------------------

class TestScoreHistory:
    def test_record_score(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml")
        record = monitor.record_score("https://example.com/agent.yaml", 85.0, 100.0, "HARDENED")
        assert record.score == 85.0
        assert record.max_score == 100.0
        assert record.band == "HARDENED"

    def test_get_history(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml")
        monitor.record_score("https://example.com/agent.yaml", 80.0, 100.0, "HARDENED")
        monitor.record_score("https://example.com/agent.yaml", 90.0, 100.0, "SECURE")
        history = monitor.get_history("https://example.com/agent.yaml")
        assert len(history) == 2
        # Most recent first
        assert history[0].score == 90.0
        assert history[1].score == 80.0

    def test_get_history_empty(self, monitor: Monitor):
        history = monitor.get_history("https://nonexistent.example.com")
        assert history == []

    def test_get_history_limit(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml")
        for i in range(10):
            monitor.record_score("https://example.com/agent.yaml", float(i), 100.0, "TEST")
        history = monitor.get_history("https://example.com/agent.yaml", limit=3)
        assert len(history) == 3

    def test_record_updates_watchlist(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml")
        monitor.record_score("https://example.com/agent.yaml", 85.0, 100.0, "HARDENED")
        entry = monitor.get_agent("https://example.com/agent.yaml")
        assert entry is not None
        assert entry.last_score == 85.0
        assert entry.last_scan is not None


# ---------------------------------------------------------------------------
# Trust Index
# ---------------------------------------------------------------------------

class TestTrustIndex:
    def test_trust_index_empty(self, monitor: Monitor):
        assert monitor.get_trust_index("https://example.com/agent.yaml") is None

    def test_trust_index_single(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml")
        monitor.record_score("https://example.com/agent.yaml", 80.0, 100.0, "HARDENED")
        assert monitor.get_trust_index("https://example.com/agent.yaml") == 80.0

    def test_trust_index_rolling_average(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml")
        scores = [70.0, 80.0, 90.0, 85.0, 75.0]
        for s in scores:
            monitor.record_score("https://example.com/agent.yaml", s, 100.0, "TEST")
        expected = round(sum(scores) / len(scores), 1)
        assert monitor.get_trust_index("https://example.com/agent.yaml") == expected

    def test_trust_index_window(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml")
        # Add 10 scores; trust index should only use last 5
        for i in range(10):
            monitor.record_score("https://example.com/agent.yaml", float(i * 10), 100.0, "TEST")
        # Last 5: 50, 60, 70, 80, 90 → avg = 70
        assert monitor.get_trust_index("https://example.com/agent.yaml", window=5) == 70.0


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------

class TestDriftDetection:
    def test_no_drift_on_first_scan(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml")
        monitor.record_score("https://example.com/agent.yaml", 80.0, 100.0, "HARDENED")
        alerts = monitor.get_alerts("https://example.com/agent.yaml")
        assert alerts == []

    def test_no_drift_within_threshold(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml")
        monitor.record_score("https://example.com/agent.yaml", 80.0, 100.0, "HARDENED")
        monitor.record_score("https://example.com/agent.yaml", 75.0, 100.0, "HARDENED")
        alerts = monitor.get_alerts("https://example.com/agent.yaml")
        assert alerts == []

    def test_drift_detected_above_threshold(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml")
        monitor.record_score("https://example.com/agent.yaml", 80.0, 100.0, "HARDENED")
        monitor.record_score("https://example.com/agent.yaml", 65.0, 100.0, "VULNERABLE")
        alerts = monitor.get_alerts("https://example.com/agent.yaml")
        assert len(alerts) == 1
        assert alerts[0].old_score == 80.0
        assert alerts[0].new_score == 65.0
        assert alerts[0].delta == 15.0

    def test_drift_threshold_exact(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml")
        monitor.record_score("https://example.com/agent.yaml", 80.0, 100.0, "HARDENED")
        # Exactly 10 pts drop — should NOT alert (threshold is >10)
        monitor.record_score("https://example.com/agent.yaml", 70.0, 100.0, "HARDENED")
        alerts = monitor.get_alerts("https://example.com/agent.yaml")
        assert alerts == []

    def test_get_all_alerts(self, monitor: Monitor):
        monitor.add_agent("https://a.example.com/agent.yaml")
        monitor.add_agent("https://b.example.com/agent.yaml")
        monitor.record_score("https://a.example.com/agent.yaml", 80.0, 100.0, "HARDENED")
        monitor.record_score("https://a.example.com/agent.yaml", 60.0, 100.0, "VULNERABLE")
        monitor.record_score("https://b.example.com/agent.yaml", 90.0, 100.0, "SECURE")
        monitor.record_score("https://b.example.com/agent.yaml", 70.0, 100.0, "HARDENED")
        all_alerts = monitor.get_alerts()
        assert len(all_alerts) == 2


# ---------------------------------------------------------------------------
# Scheduled scans
# ---------------------------------------------------------------------------

class TestScheduledScans:
    def test_due_agents_new(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml", "daily")
        due = monitor.get_due_agents()
        assert len(due) == 1

    def test_due_agents_not_due(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml", "daily")
        # Record a score to set last_scan
        monitor.record_score("https://example.com/agent.yaml", 80.0, 100.0, "HARDENED")
        due = monitor.get_due_agents()
        assert len(due) == 0

    def test_due_agents_respects_schedule(self, monitor: Monitor):
        monitor.add_agent("https://hourly.example.com/agent.yaml", "hourly")
        monitor.add_agent("https://daily.example.com/agent.yaml", "daily")
        monitor.add_agent("https://weekly.example.com/agent.yaml", "weekly")
        due = monitor.get_due_agents()
        assert len(due) == 3

    def test_disabled_agents_not_due(self, monitor: Monitor):
        monitor.add_agent("https://example.com/agent.yaml", "daily")
        # Disable via direct DB manipulation
        monitor.conn.execute("UPDATE watchlist SET enabled = 0 WHERE url = ?", ("https://example.com/agent.yaml",))
        monitor.conn.commit()
        due = monitor.get_due_agents()
        assert len(due) == 0


# ---------------------------------------------------------------------------
# Webhook notifications
# ---------------------------------------------------------------------------

class TestWebhook:
    def test_send_webhook_invalid_url(self):
        result = Monitor.send_webhook(
            "https://invalid.example.com/webhook",
            "Test", "Description"
        )
        assert result is False

    def test_send_webhook_discord_format(self):
        # Just verify it doesn't crash with a bad URL
        result = Monitor.send_webhook(
            "https://discord.com/api/webhooks/test",
            "Test", "Description",
            {"Field": "Value"}
        )
        assert isinstance(result, bool)

    def test_send_webhook_telegram_format(self):
        result = Monitor.send_webhook(
            "https://api.telegram.org/bot123/sendMessage",
            "Test", "Description"
        )
        assert isinstance(result, bool)
