# Resume Bullets & Interview Notes

## Resume entry

**VulnLens: Risk-Based Vulnerability Prioritization Tool** · Python, pandas, Excel, PowerPoint
- Built a Python tool that scores vulnerability-scanner findings on CVSS severity, exploit likelihood (EPSS, known-exploited status) and asset context (data classification, internet exposure), assigning P1–P4 priorities with remediation SLAs.
- Analyzed 1,600+ synthetic findings across 400 assets; risk-based scoring re-prioritized 40 findings versus CVSS alone and identified 5 fixes that remove 44% of urgent risk.
- Automated an Excel workbook (native charts, conditional formatting, SLA/MTTR/aging metrics) and an 8-slide executive PowerPoint briefing from the same pipeline.
- Designed a 60-minute incident tabletop exercise covering escalation, containment and breach-notification decisions for policyholder PII.

## 30-second pitch

"Scanners rank everything by CVSS, so teams chase thousands of 'criticals.' I built a tool that adds two questions: is anyone actually exploiting this, and what does the affected system hold? For an insurer, a medium-severity bug on an internet-facing server with policyholder SSNs can matter more than a critical on a dev box. The tool turns a scan export into a ranked fix list, an Excel workbook for analysts, and a slide deck for leadership, and I wrote a tabletop exercise that shows what happens when a P1 slips past its SLA."

## Questions to be ready for

- **Why these weights (40/30/30)?** They are a transparent starting point; in practice they are tuned with the security team to match risk appetite. They live in one file so they are easy to change and explain.
- **What is EPSS vs CVSS vs KEV?** CVSS = how severe a flaw could be. EPSS = probability it is exploited in the next 30 days. CISA KEV = flaws confirmed exploited in the wild.
- **What would you do with real data?** Map the scanner export columns to the three CSVs, fill EPSS and KEV from the public feeds, and validate asset classification with system owners.
- **What is the biggest limitation?** Asset context is only as good as the CMDB. Missing or wrong data classification skews scores, so the report should highlight unclassified assets.
- **How does this connect to privacy?** Data classification drives the asset score, and the tabletop walks through breach-notification decisions.
