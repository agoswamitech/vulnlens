"""Risk-based prioritization: severity alone is not risk.

CVSS describes how bad a flaw *could* be. Real risk also depends on whether attackers
are actually exploiting it (threat) and what the affected system holds (asset context).
This module combines all three into a transparent 0-100 score and a P1-P4 tier with
a remediation SLA, so every number in the report can be explained to an auditor.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

# Weights for the three components (must sum to 1.0)
W_SEVERITY = 0.40
W_THREAT = 0.30
W_ASSET = 0.30

DATA_CLASS_WEIGHT = {"Restricted": 1.0, "Confidential": 0.7, "Internal": 0.4, "Public": 0.1}
ENVIRONMENT_WEIGHT = {"Production": 1.0, "Test": 0.4, "Development": 0.3}

# Remediation SLA in days, by tier
SLA_DAYS = {"P1": 15, "P2": 30, "P3": 60, "P4": 90}


@dataclass(frozen=True)
class TierThresholds:
    p1: float = 70.0
    p2: float = 55.0
    p3: float = 35.0


def threat_score(epss: float, known_exploited: bool, exploit_available: bool) -> float:
    """0-1: likelihood the flaw is (or soon will be) exploited."""
    if known_exploited:
        return 1.0
    score = epss
    if exploit_available:
        score = max(score, 0.5)
    return min(1.0, score)


def asset_score(data_classification: str, internet_facing: bool, environment: str) -> float:
    """0-1: business impact if this asset is compromised."""
    return (
        0.50 * DATA_CLASS_WEIGHT.get(data_classification, 0.4)
        + 0.30 * (1.0 if internet_facing else 0.0)
        + 0.20 * ENVIRONMENT_WEIGHT.get(environment, 0.5)
    )


def risk_score(cvss: float, threat: float, asset: float) -> float:
    return round(100 * (W_SEVERITY * cvss / 10 + W_THREAT * threat + W_ASSET * asset), 1)


def tier(score: float, known_exploited: bool, internet_facing: bool, t: TierThresholds = TierThresholds()) -> str:
    # Override: an actively exploited flaw on an internet-facing host is always P1
    if known_exploited and internet_facing:
        return "P1"
    if score >= t.p1:
        return "P1"
    if score >= t.p2:
        return "P2"
    if score >= t.p3:
        return "P3"
    return "P4"


def score_findings(df: pd.DataFrame, thresholds: TierThresholds = TierThresholds()) -> pd.DataFrame:
    """Add threat_score, asset_score, risk_score, priority and sla_days columns.

    Expects one row per finding, already joined with asset and vulnerability fields.
    """
    out = df.copy()
    out["threat_score"] = [
        threat_score(e, k, x) for e, k, x in zip(out["epss"], out["known_exploited"], out["exploit_available"])
    ]
    out["asset_score"] = [
        asset_score(d, i, e) for d, i, e in zip(out["data_classification"], out["internet_facing"], out["environment"])
    ]
    out["risk_score"] = [risk_score(c, t, a) for c, t, a in zip(out["cvss_base"], out["threat_score"], out["asset_score"])]
    out["priority"] = [
        tier(s, k, i, thresholds) for s, k, i in zip(out["risk_score"], out["known_exploited"], out["internet_facing"])
    ]
    out["sla_days"] = out["priority"].map(SLA_DAYS)
    return out
