# Tabletop Exercise: "Unpatched Door"

**Format:** 60-minute discussion-based tabletop · **Organization:** a fictional mid-size property & casualty insurer
**Built from:** the VulnLens synthetic dataset (Agency Portal business unit, Remote Desktop pre-auth RCE finding)

## Objectives

1. Test how a known-exploited vulnerability moves from a scan report to a fix, and where it stalls.
2. Practice the hand-off from vulnerability management to incident response.
3. Walk through privacy and breach-notification decision points for policyholder PII.
4. Identify process gaps and assign owners for follow-up.

## Participants

| Role | Responsibility in the exercise |
|---|---|
| Facilitator | Runs the clock, delivers injects, keeps discussion on track |
| Security Operations | Detection, triage, containment |
| Vulnerability Management | Scan data, risk prioritization, SLA tracking |
| IT Infrastructure / Server Owner | Patching, system changes, restoring service |
| Agency Portal Business Owner | Business impact, customer-facing decisions |
| Privacy / Legal | Data classification, notification obligations |
| Communications | Internal and external messaging |
| Scribe | Captures decisions, gaps and action items |

## Ground rules

No-fault discussion. Decisions are made with the information available at each inject. "We don't know" is a valid and useful answer: it becomes an action item.

## Scenario background

The monthly VulnLens report flagged a **Remote Desktop pre-auth remote code execution** finding as **P1** on `SRV-AGE-0140`, an internet-facing Agency Portal server that stores agent and policyholder data (classified **Restricted**). The flaw is on the known-exploited list. The 15-day SLA expired 9 days ago. The patch ticket was deferred because the server supports quarter-end policy renewals.

## Injects

**Inject 1 (T+0 min): The report**
The VulnLens briefing lists this server among the top risky assets and the fix among the top five quick wins.
- Who owns this finding and who knew it was overdue?
- What is the escalation path when a P1 passes SLA? Was a risk acceptance filed?
- What would have had to be true for the patch to go in on time?

**Inject 2 (T+10): The alert**
The SOC sees repeated failed and then one successful RDP session to the server from an unfamiliar foreign IP at 02:14, followed by a new local admin account.
- Is this an incident? Who declares it, and on what criteria?
- What are the first three containment actions? What is the business impact of isolating the server during renewals?
- What logs and evidence must be preserved before anything is changed?

**Inject 3 (T+25): Lateral movement**
EDR shows the new account ran a credential-dumping tool and attempted SMB connections to Claims file servers, several of which have **SMB signing disabled** (another quick win on the report).
- How do you scope which systems are affected?
- Which accounts need password resets? Do service accounts break if reset?
- Do you bring in an outside incident response firm or notify the cyber insurance carrier?

**Inject 4 (T+40): Data question**
An outbound transfer of about 2 GB from the portal server to a cloud storage provider is found. The server's database holds policyholder names, addresses, driver's license numbers and some SSNs.
- What determines whether this is a reportable breach? Who makes that call?
- Which notification requirements could apply (state breach-notification laws, insurance-regulator cybersecurity rules such as those modeled on the NAIC Insurance Data Security Model Law, contractual obligations to agents)? What are the clocks?
- What do you tell agents and policyholders now, before the investigation is done?

**Inject 5 (T+50): Recovery**
The server is rebuilt and patched. Leadership asks, "How do we make sure this does not happen again?"
- What changes to SLA enforcement, risk acceptance or patch windows are needed?
- Which other P1 findings carry the same pattern (internet-facing, known-exploited, overdue)?
- What metric should leadership watch every month?

## After-action template

| # | Gap observed | Impact | Recommended action | Owner | Due |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |

**What went well:**
**What to improve:**
**Decisions that need leadership input:**

## Facilitator notes

- Common gap: overdue P1s with no formal risk acceptance. Tie back to the "Overdue" sheet in the workbook.
- Common gap: unclear authority to take a revenue-critical system offline. Capture who has that authority.
- Common gap: notification timelines start at "discovery," and teams disagree on when discovery happened. Make the team agree on a definition.
- Close by having each role name one action item they own.
