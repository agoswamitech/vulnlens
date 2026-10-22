"""Command-line entry point.

    python -m vulnlens generate --out data            # create synthetic scanner data
    python -m vulnlens report --data data --out reports  # score, analyze, write Excel + PowerPoint
    python -m vulnlens demo                           # both, in one step
"""

from __future__ import annotations

import argparse
from datetime import date
from pathlib import Path

from .analysis import analyze
from .generate_data import generate
from .report_excel import write_workbook
from .report_pptx import write_deck


def report(data: Path, out: Path, as_of: date) -> None:
    r = analyze(data, as_of)
    out.mkdir(parents=True, exist_ok=True)
    xlsx = write_workbook(r, out / "vulnerability_risk_report.xlsx")
    pptx = write_deck(r, out / "vulnerability_risk_briefing.pptx")
    r.open.sort_values("risk_score", ascending=False).to_csv(out / "prioritized_open_findings.csv", index=False)
    width = max(len(k) for k in r.kpis)
    print(f"\nVulnerability risk summary as of {as_of}\n" + "-" * (width + 10))
    for k, v in r.kpis.items():
        print(f"{k:<{width}}  {v}")
    print(f"\nWrote {xlsx}\nWrote {pptx}\nWrote {out / 'prioritized_open_findings.csv'}")


def main() -> None:
    ap = argparse.ArgumentParser(prog="vulnlens", description="Risk-based vulnerability prioritization and reporting")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="create synthetic scanner data")
    g.add_argument("--out", type=Path, default=Path("data"))
    g.add_argument("--assets", type=int, default=400)
    g.add_argument("--seed", type=int, default=42)
    for p in (g, rp := sub.add_parser("report", help="analyze data and write reports"), d := sub.add_parser("demo", help="generate + report")):
        p.add_argument("--as-of", type=date.fromisoformat, default=date(2026, 10, 1))
    rp.add_argument("--data", type=Path, default=Path("data"))
    rp.add_argument("--out", type=Path, default=Path("reports"))
    d.add_argument("--out", type=Path, default=Path("reports"))
    args = ap.parse_args()

    if args.cmd == "generate":
        generate(args.out, args.assets, args.seed, args.as_of)
    elif args.cmd == "report":
        report(args.data, args.out, args.as_of)
    else:
        generate(Path("data"), as_of=args.as_of)
        report(Path("data"), args.out, args.as_of)


if __name__ == "__main__":
    main()
