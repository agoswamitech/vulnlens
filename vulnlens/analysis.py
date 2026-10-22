"""Load scanner data, score it, and compute the metrics a security team reports on."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import pandas as pd

from .scoring import score_findings

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
PRIORITY_ORDER = ["P1", "P2", "P3", "P4"]
AGE_BUCKETS = [(-1, 30, "0-30 days"), (30, 60, "31-60 days"), (60, 90, "61-90 days"), (90, 10**6, "90+ days")]


def load(data_dir: Path) -> pd.DataFrame:
    findings = pd.read_csv(data_dir / "findings.csv", parse_dates=["first_seen", "last_seen", "fixed_date"])
    assets = pd.read_csv(data_dir / "assets.csv")
    catalog = pd.read_csv(data_dir / "vuln_catalog.csv")
    df = findings.merge(assets, on="asset_id", how="left").merge(catalog, on="vuln_id", how="left")
    missing = df["hostname"].isna().sum() + df["title"].isna().sum()
    if missing:
        raise ValueError(f"{missing} findings reference unknown assets or vulnerabilities")
    return df


def enrich(df: pd.DataFrame, as_of: date) -> pd.DataFrame:
    df = score_findings(df)
    as_of_ts = pd.Timestamp(as_of)
    end = df["fixed_date"].where(df["status"] == "Fixed", as_of_ts)
    df["age_days"] = (end - df["first_seen"]).dt.days
    df["due_date"] = df["first_seen"] + pd.to_timedelta(df["sla_days"], unit="D")
    df["days_past_due"] = (as_of_ts - df["due_date"]).dt.days.clip(lower=0).where(df["status"] == "Open", 0)
    df["overdue"] = (df["status"] == "Open") & (df["days_past_due"] > 0)
    # Fixed late = closed, but after its SLA due date
    df["met_sla"] = df["age_days"] <= df["sla_days"]
    df["age_bucket"] = pd.cut(
        df["age_days"], bins=[b[0] for b in AGE_BUCKETS] + [AGE_BUCKETS[-1][1]], labels=[b[2] for b in AGE_BUCKETS]
    )
    return df


@dataclass
class Report:
    as_of: date
    findings: pd.DataFrame
    open: pd.DataFrame
    kpis: dict = field(default_factory=dict)
    by_severity: pd.DataFrame = None
    by_priority: pd.DataFrame = None
    reprioritization: pd.DataFrame = None
    by_business_unit: pd.DataFrame = None
    top_assets: pd.DataFrame = None
    quick_wins: pd.DataFrame = None
    aging: pd.DataFrame = None
    trend: pd.DataFrame = None
    mttr: pd.DataFrame = None
    overdue: pd.DataFrame = None


def analyze(data_dir: Path, as_of: date) -> Report:
    df = enrich(load(data_dir), as_of)
    open_ = df[df["status"] == "Open"].copy()
    fixed = df[df["status"] == "Fixed"]
    r = Report(as_of=as_of, findings=df, open=open_)

    r.kpis = {
        "Open findings": len(open_),
        "Assets with open findings": open_["asset_id"].nunique(),
        "Open P1 (fix within 15 days)": int((open_["priority"] == "P1").sum()),
        "Open known-exploited findings": int(open_["known_exploited"].sum()),
        "Internet-facing Critical/High open": int(
            (open_["internet_facing"] & open_["severity"].isin(["Critical", "High"])).sum()
        ),
        "Overdue (past SLA)": int(open_["overdue"].sum()),
        "SLA compliance (fixed on time)": round(100 * fixed["met_sla"].mean(), 1) if len(fixed) else 0.0,
        "Mean age of open findings (days)": round(open_["age_days"].mean(), 1),
        "Risk accepted (exceptions)": int((df["status"] == "Risk Accepted").sum()),
    }
    r.kpis["Remediated in period"] = len(fixed)

    r.by_severity = (
        open_["severity"].value_counts().reindex(SEVERITY_ORDER, fill_value=0).rename_axis("Severity").reset_index(name="Open")
    )
    r.by_priority = (
        open_.groupby("priority")
        .agg(Open=("finding_id", "count"), Overdue=("overdue", "sum"), Avg_Risk=("risk_score", "mean"))
        .reindex(PRIORITY_ORDER, fill_value=0)
        .rename_axis("Priority")
        .reset_index()
    )
    r.by_priority["Avg_Risk"] = r.by_priority["Avg_Risk"].round(1)

    # The key insight: how risk-based priority differs from raw CVSS severity
    r.reprioritization = (
        pd.crosstab(open_["severity"], open_["priority"]).reindex(index=SEVERITY_ORDER, columns=PRIORITY_ORDER, fill_value=0)
    )
    r.reprioritization.index.name = "CVSS Severity"
    r.kpis["CVSS Critical/High downgraded to P3/P4"] = int(
        r.reprioritization.loc[["Critical", "High"], ["P3", "P4"]].to_numpy().sum()
    )
    r.kpis["CVSS Medium/Low escalated to P1/P2"] = int(
        r.reprioritization.loc[["Medium", "Low"], ["P1", "P2"]].to_numpy().sum()
    )

    r.by_business_unit = (
        open_.groupby("business_unit")
        .agg(
            P1=("priority", lambda s: (s == "P1").sum()),
            P2=("priority", lambda s: (s == "P2").sum()),
            Open=("finding_id", "count"),
            Overdue=("overdue", "sum"),
            Known_Exploited=("known_exploited", "sum"),
            Total_Risk=("risk_score", "sum"),
            Assets=("asset_id", "nunique"),
        )
        .assign(P1_P2=lambda d: d["P1"] + d["P2"])
        .sort_values(["P1", "P1_P2"], ascending=False)
        .rename_axis("Business Unit")
        .reset_index()
    )
    bu_fixed = fixed.groupby("business_unit")["met_sla"].mean().mul(100).round(1)
    r.by_business_unit["SLA_Compliance_%"] = r.by_business_unit["Business Unit"].map(bu_fixed)
    r.by_business_unit["Total_Risk"] = r.by_business_unit["Total_Risk"].round(0)

    r.top_assets = (
        open_.groupby(["asset_id", "hostname", "business_unit", "asset_type", "internet_facing", "data_classification", "owner"])
        .agg(
            Open=("finding_id", "count"),
            P1=("priority", lambda s: (s == "P1").sum()),
            Max_Risk=("risk_score", "max"),
            Total_Risk=("risk_score", "sum"),
        )
        .sort_values(["P1", "Max_Risk", "Total_Risk"], ascending=False)
        .head(15)
        .reset_index()
    )
    r.top_assets["Total_Risk"] = r.top_assets["Total_Risk"].round(0)

    # One fix (patch/config change) that closes many urgent findings at once.
    # Ranked by P1/P2 risk only, so widespread low-risk hygiene items don't crowd the list.
    urgent = open_[open_["priority"].isin(["P1", "P2"])]
    r.quick_wins = (
        urgent.groupby(["vuln_id", "title", "severity", "known_exploited"])
        .agg(Assets=("asset_id", "nunique"), P1=("priority", lambda s: (s == "P1").sum()), Risk_Removed=("risk_score", "sum"))
        .sort_values("Risk_Removed", ascending=False)
        .head(10)
        .reset_index()
    )
    urgent_risk = urgent["risk_score"].sum()
    r.quick_wins["Share_of_P1_P2_Risk_%"] = (100 * r.quick_wins["Risk_Removed"] / urgent_risk).round(1)
    r.quick_wins["Risk_Removed"] = r.quick_wins["Risk_Removed"].round(0)
    r.kpis["P1/P2 risk removed by top 5 fixes (%)"] = round(r.quick_wins["Share_of_P1_P2_Risk_%"].head(5).sum(), 1)

    r.aging = (
        pd.crosstab(open_["age_bucket"], open_["priority"])
        .reindex(columns=PRIORITY_ORDER, fill_value=0)
        .rename_axis("Age")
        .reset_index()
    )

    # Last six complete months
    last_month = pd.Period(pd.Timestamp(as_of) - pd.Timedelta(days=1), "M")
    months = pd.period_range(end=last_month, periods=6, freq="M")
    opened = df["first_seen"].dt.to_period("M").value_counts()
    closed = fixed["fixed_date"].dt.to_period("M").value_counts()
    trend = pd.DataFrame({"Month": months.astype(str), "Opened": [opened.get(m, 0) for m in months], "Closed": [closed.get(m, 0) for m in months]})
    # Backlog at end of each month = opened so far minus closed so far (open + accepted)
    trend["Backlog"] = [
        int(((df["first_seen"].dt.to_period("M") <= m) & ~((df["status"] == "Fixed") & (df["fixed_date"].dt.to_period("M") <= m))).sum())
        for m in months
    ]
    r.trend = trend

    r.mttr = (
        fixed.groupby("severity")["age_days"].agg(["mean", "median", "count"]).reindex(SEVERITY_ORDER).round(1)
        .rename(columns={"mean": "MTTR_Mean_Days", "median": "MTTR_Median_Days", "count": "Fixed"})
        .rename_axis("Severity").reset_index()
    )

    # Cast numpy scalars to plain Python numbers for clean output
    r.kpis = {k: (float(v) if isinstance(v, float) else int(v)) for k, v in r.kpis.items()}

    r.overdue = open_[open_["overdue"]].sort_values(["priority", "days_past_due"], ascending=[True, False])
    return r
