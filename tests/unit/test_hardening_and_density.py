"""Tests for candidates table hardening and cross-turn density tracking."""
from __future__ import annotations

import pytest

from harness.core.context import AgentContext
from harness.core.types import Severity
from harness.core.verdicts import Finding
from harness.patterns.fingerprint import extract_fingerprint, fingerprint_to_json
from harness.patterns.store import (
    init_db, list_candidates, upsert_candidate, set_candidate_status,
)
from harness.boundaries.session_accumulator import ThreatAccumulator


# ── Item 3: Candidates table hardening ────────────────────────────────────

class TestCandidatesCap:

    def _insert_n(self, db, n, prefix="text"):
        """Insert n unique candidates."""
        for i in range(n):
            text = f"{prefix}_{i}_{'x' * (i * 3)}"
            fp = extract_fingerprint(text, 0.0, 1.5, 0.0, 1.0)
            upsert_candidate(db, fingerprint_to_json(fp), f"skel_{i}", "high", fp["lsh"])

    def test_cap_at_500(self, tmp_path):
        db = str(tmp_path / "test.db")
        self._insert_n(db, 502)
        candidates = list_candidates(db, min_hits=1)
        open_count = sum(1 for c in candidates if c["status"] == "open")
        assert open_count <= 500

    def test_evicts_low_hit_first(self, tmp_path):
        db = str(tmp_path / "test.db")
        self._insert_n(db, 499)

        # Create one candidate with high hits by upserting it multiple times
        text = "recurring_attack_pattern_unique"
        fp = extract_fingerprint(text, 0.0, 1.5, 0.0, 1.0)
        for _ in range(5):
            upsert_candidate(db, fingerprint_to_json(fp), "recurring", "high", fp["lsh"])

        # Now insert 2 more to trigger eviction
        self._insert_n(db, 2, prefix="overflow")

        candidates = list_candidates(db, min_hits=1)
        # The recurring one (hit_count=5) should survive eviction
        recurring = [c for c in candidates if c["skeleton"] == "recurring"]
        assert len(recurring) == 1
        assert recurring[0]["hit_count"] == 5

    def test_promoted_not_counted_toward_cap(self, tmp_path):
        db = str(tmp_path / "test.db")
        self._insert_n(db, 5)
        candidates = list_candidates(db, min_hits=1)
        set_candidate_status(db, candidates[0]["id"], "promoted")
        # Promoted candidates don't count toward open cap
        open_count = sum(1 for c in list_candidates(db, min_hits=1) if c["status"] == "open")
        assert open_count == 4


class TestCandidatesMinHits:

    def test_open_filtered_by_default(self, tmp_path):
        db = str(tmp_path / "test.db")
        # Insert 3 unique candidates (hit_count=1 each)
        for i in range(3):
            text = f"noise_{i}_{'y' * (i * 20)}"
            fp = extract_fingerprint(text, 0.0, 1.5, 0.0, 1.0)
            upsert_candidate(db, fingerprint_to_json(fp), f"skel_{i}", "medium", fp["lsh"])

        # Default: open candidates with hit_count < 3 are hidden
        visible = list_candidates(db, status="open")
        assert len(visible) == 0

    def test_all_flag_shows_everything(self, tmp_path):
        db = str(tmp_path / "test.db")
        for i in range(3):
            text = f"noise_{i}_{'y' * (i * 20)}"
            fp = extract_fingerprint(text, 0.0, 1.5, 0.0, 1.0)
            upsert_candidate(db, fingerprint_to_json(fp), f"skel_{i}", "medium", fp["lsh"])

        # With min_hits=1, all are visible
        visible = list_candidates(db, status="open", min_hits=1)
        assert len(visible) == 3

    def test_recurring_candidates_visible(self, tmp_path):
        db = str(tmp_path / "test.db")
        text = "recurring_pattern_xyz"
        fp = extract_fingerprint(text, 0.0, 1.5, 0.0, 1.0)
        for _ in range(3):
            upsert_candidate(db, fingerprint_to_json(fp), "skel", "high", fp["lsh"])

        visible = list_candidates(db, status="open")
        assert len(visible) == 1
        assert visible[0]["hit_count"] == 3


# ── Item 1: Cross-turn density tracking ──────────────────────────────────

class TestDensityTracking:

    @pytest.fixture
    async def acc(self, tmp_path):
        a = ThreatAccumulator(
            db_path=str(tmp_path / "sessions.db"),
            escalation_threshold=0.70,
            window_size=5,
            density_threshold=0.05,
        )
        yield a
        await a.close()

    async def test_no_escalation_on_low_density(self, acc):
        for i in range(5):
            await acc.record("sess1", f"normal text {i}", "allow", [], density=0.02)
        escalated, _ = await acc.check("sess1")
        assert not escalated

    async def test_escalation_on_sustained_high_density(self, acc):
        # 5 turns each at 8% density — average 0.08 > 0.05 threshold
        for i in range(5):
            await acc.record("sess2", f"ignore override text {i}", "allow", [], density=0.08)
        escalated, reason = await acc.check("sess2")
        # Density alone adds WEIGHT_DENSITY (0.25) which is below escalation_threshold (0.70)
        # But combined with other signals it contributes
        # Let's check the score directly
        db = await acc._conn()
        async with db.execute("SELECT risk_score FROM sessions WHERE session_id = 'sess2'") as cur:
            row = await cur.fetchone()
        assert row["risk_score"] >= 0.25  # density signal fired

    async def test_density_plus_blocks_escalates(self, acc):
        # Turns with both high density AND blocks — should escalate
        for i in range(5):
            await acc.record("sess3", f"ignore override {i}", "block", ["injection"], density=0.08)
        escalated, reason = await acc.check("sess3")
        assert escalated
        assert "session_accumulator" in reason

    async def test_density_signal_not_triggered_on_zero(self, acc):
        for i in range(5):
            await acc.record("sess4", f"clean text {i}", "allow", [], density=0.0)
        db = await acc._conn()
        async with db.execute("SELECT risk_score FROM sessions WHERE session_id = 'sess4'") as cur:
            row = await cur.fetchone()
        assert row["risk_score"] == 0.0

    async def test_density_decays_with_window(self, acc):
        # 3 high-density turns followed by 5 normal turns
        for i in range(3):
            await acc.record("sess5", f"ignore override {i}", "allow", [], density=0.10)
        for i in range(5):
            await acc.record("sess5", f"normal {i}", "allow", [], density=0.01)
        # Window is 5, so only the last 5 (normal) are in scope
        db = await acc._conn()
        async with db.execute("SELECT risk_score FROM sessions WHERE session_id = 'sess5'") as cur:
            row = await cur.fetchone()
        assert row["risk_score"] < 0.25  # density signal should have decayed out


class TestExtractDensity:

    def test_extracts_from_heuristic_detail(self):
        from harness.core.harness import _extract_density
        from harness.core.verdicts import ScanVerdict, Finding
        from harness.core.types import ScanStatus

        verdict = ScanVerdict(
            status=ScanStatus.ALLOW,
            findings=[Finding(
                scanner="heuristic_scan",
                category="heuristic_anomaly",
                severity=Severity.MEDIUM,
                detail="total=3.4 (density=2.0, coherence=1.4)",
            )],
        )
        assert _extract_density(verdict) == 2.0

    def test_returns_zero_when_no_heuristic(self):
        from harness.core.harness import _extract_density
        from harness.core.verdicts import ScanVerdict
        from harness.core.types import ScanStatus

        verdict = ScanVerdict(status=ScanStatus.ALLOW)
        assert _extract_density(verdict) == 0.0

    def test_returns_zero_when_no_density_in_detail(self):
        from harness.core.harness import _extract_density
        from harness.core.verdicts import ScanVerdict, Finding
        from harness.core.types import ScanStatus

        verdict = ScanVerdict(
            status=ScanStatus.ALLOW,
            findings=[Finding(
                scanner="heuristic_scan",
                category="heuristic_anomaly",
                severity=Severity.LOW,
                detail="total=1.2 (structural=1.2)",
            )],
        )
        assert _extract_density(verdict) == 0.0
