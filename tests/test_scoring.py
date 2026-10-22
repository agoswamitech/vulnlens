from datetime import date
from pathlib import Path

import pandas as pd
import pytest

from vulnlens.analysis import analyze
from vulnlens.generate_data import generate
from vulnlens.scoring import asset_score, risk_score, threat_score, tier


def test_known_exploited_is_max_threat():
    assert threat_score(0.01, known_exploited=True, exploit_available=False) == 1.0


def test_public_exploit_raises_threat_floor():
    assert threat_score(0.02, known_exploited=False, exploit_available=True) == 0.5
    assert threat_score(0.02, known_exploited=False, exploit_available=False) == 0.02


def test_asset_score_bounds():
    assert asset_score("Restricted", True, "Production") == pytest.approx(1.0)
    assert asset_score("Public", False, "Development") == pytest.approx(0.05 + 0.06)


def test_risk_score_range():
    assert risk_score(10.0, 1.0, 1.0) == 100.0
    assert risk_score(0.0, 0.0, 0.0) == 0.0


def test_exploited_internet_facing_always_p1():
    assert tier(10.0, known_exploited=True, internet_facing=True) == "P1"


def test_medium_cvss_can_escalate():
    # Medium CVSS, actively exploited, on a restricted internet-facing prod host
    score = risk_score(6.5, threat_score(0.9, True, True), asset_score("Restricted", True, "Production"))
    assert tier(score, True, True) == "P1"


def test_critical_cvss_can_downgrade():
    # Critical CVSS, no known exploit, on a public dev box
    score = risk_score(9.8, threat_score(0.01, False, False), asset_score("Public", False, "Development"))
    assert tier(score, False, False) in ("P3", "P4")


def test_pipeline_end_to_end(tmp_path: Path):
    generate(tmp_path, n_assets=60, seed=7)
    r = analyze(tmp_path, date(2026, 10, 1))
    assert r.kpis["Open findings"] == len(r.open) > 0
    assert set(r.open["priority"]) <= {"P1", "P2", "P3", "P4"}
    assert r.open["risk_score"].between(0, 100).all()
    # Overdue findings are open and past due
    assert (r.overdue["status"] == "Open").all()
    assert (r.overdue["due_date"] < pd.Timestamp("2026-10-01")).all()
