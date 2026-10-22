"""Generate a synthetic vulnerability-scanner export for a fictional insurance company.

Everything produced here is fake: hostnames, owners, vulnerability IDs and scores.
Vulnerability IDs use the "SYN-" prefix so they can never be confused with real CVEs.
The output mirrors the shape of a typical Nessus/Qualys/Rapid7 CSV export so the
rest of the pipeline works the same way on real (sanitized) data.
"""

from __future__ import annotations

import argparse
import random
from datetime import date, timedelta
from pathlib import Path

import pandas as pd

BUSINESS_UNITS = ["Underwriting", "Claims", "Finance", "Human Resources", "Agency Portal", "IT Operations"]

# (asset_type, operating systems, share of fleet)
ASSET_PROFILES = [
    ("Workstation", ["Windows 11", "Windows 10", "macOS 14"], 0.50),
    ("Server", ["Windows Server 2019", "Windows Server 2022", "RHEL 8", "Ubuntu 22.04"], 0.28),
    ("Network Device", ["Cisco IOS XE", "Palo Alto PAN-OS", "FortiOS"], 0.08),
    ("Cloud Workload", ["Amazon Linux 2023", "Ubuntu 22.04", "Windows Server 2022"], 0.14),
]

# Data each business unit typically handles. Insurance carriers hold a lot of PII
# (policyholder SSNs, driver records, medical info on claims), so this drives risk.
BU_DATA_CLASS = {
    "Underwriting": ["Restricted", "Confidential"],
    "Claims": ["Restricted", "Restricted", "Confidential"],
    "Finance": ["Restricted", "Confidential"],
    "Human Resources": ["Restricted", "Confidential"],
    "Agency Portal": ["Confidential", "Internal"],
    "IT Operations": ["Internal", "Confidential", "Public"],
}

# Synthetic vulnerability catalog: (title, family, cvss, base exploit likelihood)
VULN_TEMPLATES = [
    ("Remote code execution in Java logging library", "Application", 10.0, 0.95),
    ("SMBv1 remote code execution", "Windows", 8.1, 0.90),
    ("Remote Desktop pre-auth RCE", "Windows", 9.8, 0.85),
    ("Managed file transfer SQL injection", "Web Application", 9.8, 0.92),
    ("Print spooler privilege escalation", "Windows", 8.8, 0.80),
    ("VPN appliance path traversal", "Network", 9.8, 0.88),
    ("Firewall management interface auth bypass", "Network", 9.8, 0.70),
    ("OpenSSL buffer over-read", "Linux", 7.5, 0.40),
    ("Outdated TLS 1.0/1.1 enabled", "General", 5.3, 0.02),
    ("Weak SSH ciphers supported", "General", 5.3, 0.01),
    ("Self-signed TLS certificate", "General", 6.5, 0.01),
    ("Browser use-after-free", "Workstation", 8.8, 0.30),
    ("Office document macro RCE", "Workstation", 7.8, 0.45),
    ("PDF reader heap overflow", "Workstation", 7.8, 0.15),
    ("Linux kernel local privilege escalation", "Linux", 7.8, 0.35),
    ("sudo heap overflow", "Linux", 7.8, 0.50),
    ("Apache HTTP Server request smuggling", "Web Application", 9.1, 0.12),
    ("Spring framework RCE", "Application", 9.8, 0.75),
    ("Missing HTTP security headers", "Web Application", 4.3, 0.01),
    ("Directory listing enabled", "Web Application", 5.3, 0.03),
    ("SNMP default community string", "Network", 7.5, 0.20),
    ("Unsupported OS version", "General", 10.0, 0.10),
    ("Windows cumulative security update missing", "Windows", 8.8, 0.25),
    ("Exchange server SSRF", "Windows", 9.8, 0.85),
    ("DNS server cache poisoning", "Network", 6.8, 0.05),
    ("Java runtime outdated", "Application", 6.5, 0.08),
    ("PHP remote code execution", "Web Application", 9.8, 0.40),
    ("Cloud storage bucket publicly listable", "Cloud", 7.5, 0.30),
    ("Instance metadata service v1 enabled", "Cloud", 6.5, 0.20),
    ("Container image with critical library flaw", "Cloud", 9.8, 0.15),
    ("Database default credentials", "Application", 9.8, 0.60),
    ("NTLM relay possible (SMB signing disabled)", "Windows", 6.5, 0.35),
    ("jQuery cross-site scripting", "Web Application", 6.1, 0.05),
    ("Zip library path traversal", "Application", 5.5, 0.04),
    ("Hypervisor tools privilege escalation", "Server", 7.8, 0.10),
    ("ICMP timestamp request disclosure", "General", 2.1, 0.0),
    ("Cleartext HTTP login form", "Web Application", 3.7, 0.02),
]

FAMILY_FIT = {
    "Workstation": {"Workstation", "Windows", "General", "Application"},
    "Server": {"Windows", "Linux", "General", "Application", "Web Application", "Server"},
    "Network Device": {"Network", "General"},
    "Cloud Workload": {"Cloud", "Linux", "Application", "Web Application", "General"},
}

FIRST_NAMES = ["A.", "B.", "C.", "D.", "E.", "F.", "G.", "H.", "J.", "K.", "L.", "M."]
LAST_NAMES = ["Rivera", "Chen", "Patel", "Okafor", "Nguyen", "Smith", "Garcia", "Kim", "Johnson", "Adams"]


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def build_catalog(rng: random.Random) -> pd.DataFrame:
    rows = []
    for i, (title, family, cvss, exploit_base) in enumerate(VULN_TEMPLATES, start=1):
        # EPSS-style probability (0-1): jitter around the template's base likelihood
        epss = min(0.97, max(0.0005, rng.gauss(exploit_base, 0.08) if exploit_base > 0.1 else exploit_base * rng.uniform(0.3, 1.5)))
        rows.append(
            {
                "vuln_id": f"SYN-2026-{1000 + i}",
                "title": title,
                "plugin_family": family,
                "cvss_base": cvss,
                "severity": severity_from_cvss(cvss),
                "epss": round(epss, 4),
                # "Known exploited" flag, analogous to CISA's KEV catalog
                "known_exploited": exploit_base >= 0.85,
                "exploit_available": exploit_base >= 0.30,
            }
        )
    return pd.DataFrame(rows)


def build_assets(rng: random.Random, n_assets: int) -> pd.DataFrame:
    rows = []
    weights = [p[2] for p in ASSET_PROFILES]
    for i in range(1, n_assets + 1):
        asset_type, oses, _ = rng.choices(ASSET_PROFILES, weights=weights)[0]
        bu = rng.choice(BUSINESS_UNITS)
        prefix = {"Workstation": "WS", "Server": "SRV", "Network Device": "NET", "Cloud Workload": "CLD"}[asset_type]
        internet_facing = (
            (asset_type in ("Server", "Cloud Workload") and rng.random() < (0.35 if bu == "Agency Portal" else 0.10))
            or (asset_type == "Network Device" and rng.random() < 0.40)
        )
        environment = "Production" if asset_type == "Workstation" or rng.random() < 0.7 else rng.choice(["Development", "Test"])
        rows.append(
            {
                "asset_id": f"A{i:04d}",
                "hostname": f"{prefix}-{bu[:3].upper()}-{i:04d}.corp.example",
                "asset_type": asset_type,
                "os": rng.choice(oses),
                "business_unit": bu,
                "environment": environment,
                "internet_facing": internet_facing,
                "data_classification": rng.choice(BU_DATA_CLASS[bu]),
                "owner": f"{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}",
            }
        )
    return pd.DataFrame(rows)


def build_findings(rng: random.Random, assets: pd.DataFrame, catalog: pd.DataFrame, as_of: date, days_back: int) -> pd.DataFrame:
    rows = []
    fid = 1
    for asset in assets.itertuples():
        fits = catalog[catalog["plugin_family"].isin(FAMILY_FIT[asset.asset_type])]
        n = max(1, int(rng.gauss(6 if asset.asset_type == "Server" else 4, 2)))
        for vuln in fits.sample(n=min(n, len(fits)), random_state=rng.randint(0, 10**6)).itertuples():
            first_seen = as_of - timedelta(days=rng.randint(0, days_back))
            age = (as_of - first_seen).days
            # Each finding gets a time-to-fix drawn from an exponential distribution;
            # criticals are patched faster on average. If that time has not elapsed yet,
            # the finding is still open as of the report date.
            mean_fix = {"Critical": 22, "High": 35, "Medium": 70, "Low": 120}[vuln.severity]
            time_to_fix = max(1, int(rng.expovariate(1 / mean_fix)))
            if rng.random() < 0.04:
                status, fixed_date = "Risk Accepted", None
                last_seen = as_of - timedelta(days=rng.randint(0, 3))
            elif time_to_fix < age:
                status = "Fixed"
                fixed_date = first_seen + timedelta(days=time_to_fix)
                last_seen = fixed_date - timedelta(days=1)
            else:
                status, fixed_date = "Open", None
                last_seen = as_of - timedelta(days=rng.randint(0, 3))
            rows.append(
                {
                    "finding_id": f"F{fid:06d}",
                    "asset_id": asset.asset_id,
                    "vuln_id": vuln.vuln_id,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "status": status,
                    "fixed_date": fixed_date,
                    "port": rng.choice([22, 80, 443, 445, 3389, 8080, 0]),
                }
            )
            fid += 1
    return pd.DataFrame(rows)


def generate(out_dir: Path, n_assets: int = 400, seed: int = 42, as_of: date = date(2026, 10, 1), days_back: int = 180) -> None:
    rng = random.Random(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    catalog = build_catalog(rng)
    assets = build_assets(rng, n_assets)
    findings = build_findings(rng, assets, catalog, as_of, days_back)
    catalog.to_csv(out_dir / "vuln_catalog.csv", index=False)
    assets.to_csv(out_dir / "assets.csv", index=False)
    findings.to_csv(out_dir / "findings.csv", index=False)
    print(f"Wrote {len(assets)} assets, {len(catalog)} vulnerabilities, {len(findings)} findings to {out_dir}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=Path("data"))
    ap.add_argument("--assets", type=int, default=400)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--as-of", type=date.fromisoformat, default=date(2026, 10, 1))
    args = ap.parse_args()
    generate(args.out, args.assets, args.seed, args.as_of)


if __name__ == "__main__":
    main()
