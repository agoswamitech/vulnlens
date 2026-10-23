# VulnLens: Risk-Based Vulnerability Prioritization & Reporting

[![tests](https://github.com/agoswamitech/vulnlens/actions/workflows/tests.yml/badge.svg)](https://github.com/agoswamitech/vulnlens/actions/workflows/tests.yml)

VulnLens turns a raw vulnerability-scanner export into a **prioritized remediation plan**, an **Excel workbook** for analysts, and a **PowerPoint briefing** for leadership.

The core idea: **CVSS severity is not risk.** A "Critical" flaw on an isolated dev box can matter less than a "Medium" flaw that attackers are actively exploiting on an internet-facing server full of policyholder PII. VulnLens scores every finding on three inputs (severity, threat, and asset context), assigns a P1–P4 priority with a remediation SLA, and reports on how well the organization is keeping up.

> All data in this repo is **synthetic**. Hostnames, owners and vulnerability IDs (`SYN-2026-xxxx`) are generated and do not represent any real company or real CVE.

---

## What it produces

| Output | Audience | What's in it |
|---|---|---|
| `vulnerability_risk_report.xlsx` | Security analysts, IT owners | Executive summary with native Excel charts; every open finding ranked by risk with filters and color-coded priority; overdue list; CVSS-vs-priority matrix; business unit breakdown; top risky assets; quick wins; aging; MTTR; methodology |
| `vulnerability_risk_briefing.pptx` | IT / security leadership | 8 slides: KPIs, "severity is not risk," remediation trend, where risk lives, quick wins, recommendations, methodology |
| `prioritized_open_findings.csv` | Ticketing / automation | Every open finding with its risk score, priority and SLA due date |

Sample outputs from the included synthetic dataset are in [`sample_output/`](sample_output/).

### Sample results (synthetic data, 400 assets, 1,665 findings over 6 months)

- **385** open findings across **244** assets; **53** are P1 (15-day SLA) and **33** are known-exploited.
- Risk scoring moved **18** scanner Critical/High findings down to P3/P4 and escalated **22** Medium/Low findings to P1/P2.
- **142** open findings are past SLA; **67%** of fixes in the period closed on time.
- **Five fixes** (one patch or config change each) would remove **44%** of all urgent (P1/P2) risk.
- The backlog grew every month for six months, because fixes are not keeping pace with new findings.

---

## How the scoring works

```
Risk score (0–100) = 100 × (0.40 × CVSS/10  +  0.30 × Threat  +  0.30 × Asset)

Threat (0–1) = 1.0 if known exploited in the wild (like CISA KEV)
               else max(EPSS probability, 0.5 if a public exploit exists)

Asset (0–1)  = 0.5 × data classification  (Restricted 1.0, Confidential 0.7, Internal 0.4, Public 0.1)
             + 0.3 × internet facing
             + 0.2 × environment          (Production 1.0, Test 0.4, Development 0.3)
```

| Priority | Rule | Remediation SLA |
|---|---|---|
| **P1** | score ≥ 70, **or** known-exploited on an internet-facing asset | 15 days |
| **P2** | score ≥ 55 | 30 days |
| **P3** | score ≥ 35 | 60 days |
| **P4** | everything else | 90 days |

Weights, thresholds and SLAs live in [`vulnlens/scoring.py`](vulnlens/scoring.py) so they can be tuned to an organization's risk appetite. The formula is intentionally simple and explainable: every score can be justified to an auditor or a system owner line by line.

**Why these inputs:**
- **Severity (CVSS)** measures how bad a flaw could be in theory.
- **Threat** measures how likely it is to be used. EPSS (Exploit Prediction Scoring System) gives a probability of exploitation in the next 30 days; CISA's Known Exploited Vulnerabilities catalog lists flaws seen in real attacks.
- **Asset context** measures business impact. An insurance carrier holds SSNs, driver records, claims medical data and payment data, so data classification is weighted heavily.

---

## Metrics reported

- Open findings by severity and by priority, overdue counts
- **SLA compliance**: share of remediated findings closed within their SLA
- **MTTR** (mean/median time to remediate) by severity
- **Aging** buckets (0–30, 31–60, 61–90, 90+ days) by priority
- **Monthly trend**: opened vs closed, and backlog at month end
- **Business unit** breakdown with P1/P2 counts, overdue, known-exploited, SLA compliance
- **Top risky assets** to bring to their owners
- **Quick wins**: the single fixes that remove the most P1/P2 risk across the fleet
- Risk-accepted exceptions

---

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m vulnlens demo --out reports                 # generate synthetic data + build all reports
```

Or step by step:

```bash
python -m vulnlens generate --out data --assets 400 --seed 42
python -m vulnlens report   --data data --out reports --as-of 2026-10-01
python -m pytest -q                                   # run the tests
```

### Using your own (sanitized) data

`report` reads three CSVs from the `--data` folder. Column names match what most scanners (Nessus, Qualys, Rapid7) can export after light renaming:

| File | Columns |
|---|---|
| `assets.csv` | `asset_id, hostname, asset_type, os, business_unit, environment, internet_facing, data_classification, owner` |
| `vuln_catalog.csv` | `vuln_id, title, plugin_family, cvss_base, severity, epss, known_exploited, exploit_available` |
| `findings.csv` | `finding_id, asset_id, vuln_id, first_seen, last_seen, status (Open/Fixed/Risk Accepted), fixed_date, port` |

`epss` and `known_exploited` can be filled from the public [FIRST EPSS](https://www.first.org/epss/) and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) feeds.

---

## Project layout

```
vulnlens/
├── vulnlens/
│   ├── generate_data.py   # synthetic scanner export (assets, catalog, findings)
│   ├── scoring.py         # risk score, priority tiers, SLAs
│   ├── analysis.py        # joins data, computes every metric
│   ├── report_excel.py    # formatted workbook with native Excel charts
│   ├── report_pptx.py     # executive PowerPoint briefing
│   └── cli.py             # `python -m vulnlens ...`
├── tests/                 # unit + end-to-end tests (pytest)
├── docs/
│   └── tabletop_exercise.md   # incident tabletop built on the report's findings
├── data/                  # synthetic input data
└── sample_output/         # generated Excel, PowerPoint and CSV
```

---

## Tabletop exercise

[`docs/tabletop_exercise.md`](docs/tabletop_exercise.md) is a 60-minute tabletop scenario built from this dataset: an actively exploited RDP flaw on an internet-facing Agency Portal server leads to suspected exposure of policyholder data. It includes injects, discussion questions for IT, security, legal/privacy and communications, and an after-action template. It connects vulnerability management to incident response and privacy notification obligations.

---

## Skills demonstrated

- **Vulnerability management**: CVSS, EPSS, known-exploited intelligence, risk-based SLAs, exception handling
- **Data analysis**: Python, pandas, KPI design, trend and aging analysis
- **Reporting & communication**: Excel workbooks with native charts and conditional formatting; PowerPoint for executives
- **Privacy & data protection**: data classification drives risk; tabletop covers breach-notification decisions
- **Incident preparedness**: tabletop / war-gaming exercise design
- **Engineering**: tested, modular, CLI-driven Python

## Possible extensions

- Pull live EPSS and CISA KEV feeds to enrich real scanner exports
- Map findings to MITRE ATT&CK techniques
- Add an identity & access review module (stale accounts, excessive privilege) using the same reporting pipeline
- Track remediation week over week and alert owners when P1s approach their SLA

## License

MIT
