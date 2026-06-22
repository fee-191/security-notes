# Chapter 16 — Compliance & Governance (GRC)

## Overview

**GRC (Governance, Risk, Compliance)** is the framework an organization uses to govern its own information security operations: defining who is accountable, which risks to prioritize, and what evidence demonstrates compliance to regulators, customers, and partners. Security is not purely a technical matter (firewalls, encryption) but also a matter of **accountability and evidence**: when an incident occurs and there is no documentation proving that proper procedures were followed, the organization may face penalties, lose certifications, or incur legal liability. Engineering builds a robust system; GRC ensures that system has a legal basis, operational records, and clear assignment of responsibility.

This chapter covers the following knowledge blocks:

- **GRC** — three nested layers. **Governance** is the outer layer: leadership sets the rules of the game, defines risk appetite, and establishes decision-making authority. **Risk** is the middle layer: assessing what could go wrong and the magnitude of damage. **Compliance** is the inner layer: proving adherence to standards and laws. Without centralized governance, each team does things its own way, residual risk goes untracked, and there are no records when an audit comes.
- **Risk Management** — risk is formed from the chain **asset → threat → vulnerability → impact × likelihood**. It is measured in two ways: **quantitative** (assigning monetary values: SLE, ARO, ALE) to compare the cost of controls, and **qualitative** (scoring on a 1–5 likelihood × impact scale) when financial data is lacking. Risk treatment has 4 options: **mitigate, transfer, avoid, accept** — every residual risk must be formally signed off and accepted by a risk owner. The **Risk Register** is the central repository tracking every risk along with its owner and remediation deadline.
- **NIST Cybersecurity Framework (CSF)** — a voluntary framework providing a common language to describe security posture, divided into 6 Functions (CSF 2.0): **Govern, Identify, Protect, Detect, Respond, Recover**. CSF defines *what to do* rather than prescribing *specific technologies*.
- **NIST Special Publications** — **SP 800-53** is a detailed control catalog (answering the specific questions CSF leaves open). **SP 800-61** is the incident response process: preparation → detection and analysis → containment/eradication/recovery → lessons learned. **SP 800-207 (Zero Trust)** eliminates default trust based on network location; every access request must be authenticated and have its risk re-evaluated.
- **ISO/IEC 27001 & 27002** — **27001** is the international standard for an Information Security Management System (ISMS), which is **certifiable** by a third party. **27002** is a code of practice providing guidance on implementing each control. The central document is the **SoA (Statement of Applicability)** — listing every control with the rationale for applying or excluding it, which is the auditor's starting point.
- **PCI DSS** — a contractually mandated standard (not a law) for any organization that stores, processes, or transmits payment card data; it comprises 12 requirements. The core rule: Sensitive Authentication Data (CVV, magnetic stripe data, PIN) **must never be stored** after authorization. **Tokenization** replaces real card numbers with meaningless tokens to reduce compliance scope.
- **Vietnamese law** — four main instruments: the **Law on Cyber Information Security 2015** (foundational technical framework), the **Cybersecurity Law 2018** (national security, data localization requirements), **Decree 85/2016** (classifying systems into 5 levels), and **Decree 13/2023** (personal data protection, similar to GDPR). These are mandatory legal regulations; determining a system's classification level and obtaining consent when collecting personal data drives system design and data storage location.

The sections below present the technical detail for each block.

> This chapter is intended for security engineers (Blue Team / AppSec / DevSecOps) who need to look things up and operate in practice. Each concept follows the sequence: **WHAT IT IS → INTERNAL MECHANISM (down to fields/steps/parameters) → REAL, RUNNABLE EXAMPLE → SECURITY NOTES**. Vietnamese legal provisions are presented at the level of **operational meaning**; wherever document numbers/articles need verification, this is explicitly marked `[NEEDS VERIFICATION]` rather than fabricated.

---

## 16.0. Chapter map and the overall GRC model

GRC = **Governance, Risk, Compliance**. These are not three separate things but three nested layers:

```
+------------------------------------------------------------------+
|  GOVERNANCE                                                       |
|  - Who is accountable? Risk appetite?                            |
|  - Policy, standard, procedure                                   |
|   +-----------------------------------------------------------+   |
|   |  RISK MANAGEMENT                                          |  |
|   |  asset -> threat -> vuln -> likelihood x impact -> risk    |  |
|   |  -> treat (accept/mitigate/transfer/avoid) -> register     |  |
|   |   +----------------------------------------------------+   |  |
|   |   |  COMPLIANCE                                        |  |  |
|   |   |  Map control -> framework -> evidence -> audit     |  |  |
|   |   |  NIST CSF/800-53/800-61/800-207, ISO 27001/27002,  |  |  |
|   |   |  PCI DSS, Cyber Info Sec/Cybersecurity Laws,       |  |  |
|   |   |  Decree 85/2016, Decree 13/2023                    |  |  |
|   |   +----------------------------------------------------+   |  |
|   +-----------------------------------------------------------+   |
+------------------------------------------------------------------+
```

**Distinguishing the 4 tiers of governance documents** (very commonly confused — the table below is the standard used in an ISMS):

| Tier | English name | Nature | Example |
|------|---------------|-----------|-------|
| 1 | Policy | "What must be done" — mandatory, approved by leadership | "All personal data must be encrypted at rest" |
| 2 | Standard | "By what technology/specification" — mandatory | "At-rest encryption uses AES-256-GCM" |
| 3 | Procedure | "Which steps to follow" — mandatory | "KMS key rotation procedure every 90 days: step 1..n" |
| 4 | Guideline | "Should do" — recommended | "Prefer envelope encryption" |

**WHY separate into 4 tiers?** So that the policy remains stable over the long term (changes rarely → less re-approval at the leadership level), while standards/procedures change with technology. If you embed "AES-256" into the policy, then every time the algorithm changes you would have to get the entire Board to re-sign — which is not practical.

---

## 16.1. Risk Management

Risk management is an iterative cycle, not a one-off activity. The diagram below summarizes the process from establishing context to continuous monitoring (mapped to ISO 31000 and the NIST RMF):

```
   ┌──────────────────────────────────────────────────────────────┐
   │            ESTABLISH CONTEXT (scope, risk appetite)           │
   └───────────────────────────────┬──────────────────────────────┘
                                    ▼
        ┌───────────────────────────────────────────────────┐
        │  RISK IDENTIFICATION                              │
        │  asset → threat → vulnerability                   │
        └───────────────────────────┬───────────────────────┘
                                    ▼
        ┌───────────────────────────────────────────────────┐
        │  ANALYSIS & EVALUATION                            │
        │  Inherent risk = Likelihood × Impact              │
        │  (quantitative SLE/ALE  or  qualitative 5×5)      │
        └───────────────────────────┬───────────────────────┘
                                    ▼
        ┌───────────────────────────────────────────────────┐
        │  RISK TREATMENT (4 options)                       │
        │  mitigate | transfer | avoid | accept             │
        │  → Residual risk remains                          │
        └───────────────────────────┬───────────────────────┘
                                    ▼
        ┌───────────────────────────────────────────────────┐
        │  RECORD in RISK REGISTER + risk owner signs       │
        └───────────────────────────┬───────────────────────┘
                                    ▼
        ┌───────────────────────────────────────────────────┐
        │  MONITOR & REVIEW PERIODICALLY ──┐                 │
        └────────────────────────────────┘                   │
                  └──────────────────────────────────────────┘
              (loop: residual risk is periodically reassessed)
```

Note: risk is progressively reduced over each cycle (inherent → residual), but never reaches zero — the residual portion must be formally accepted by someone with the authority to do so. The monitoring loop closes the cycle: an outdated register creates a false sense of security, so it must be reviewed periodically.

### 16.1.1. The causal chain: asset → threat → vulnerability → risk

**WHAT IT IS.** Risk does not arise on its own. It is the result of a chain: there is a valuable **asset** → a **threat** exists that wants/is able to cause harm → the asset has a **vulnerability** for the threat to exploit → when successfully exploited it causes an **impact** with a certain **likelihood**. Risk = a function of likelihood and impact.

**MECHANISM — precise definition of each component:**

| Component | Operational definition | Example on an exchange system (CEX) |
|------------|---------------------|------------------------------------------|
| Asset | Something of value that needs protecting (data, system, reputation) | DB holding the hot wallet private key |
| Threat | An actor + action that could cause harm | An APT group targeting the hot wallet to drain funds |
| Threat actor | The agent (human/automation) | APT38 (Lazarus) |
| Vulnerability | A weakness that allows the threat to succeed | RPC node exposed to the Internet, not filtering `eth_sendRawTransaction` |
| Exploit | The means of realizing exploitation of the vuln | Sending a pre-signed tx through the exposed RPC |
| Impact | The consequence if it occurs (financial/reputational/legal) | Loss of USD 50 million in coins |
| Likelihood | Probability/frequency of occurrence | "Medium–high" or ARO=0.3/year |
| Control | A measure to reduce likelihood or impact | HSM transaction signing, RPC allowlist, MPC |

**Conceptual formula:**

```
Inherent Risk  = Likelihood(no control) x Impact(no control)
Residual Risk  = Likelihood(after control) x Impact(after control)
Risk Treatment works on the gap: Inherent - Residual
```

**SECURITY NOTES.** A common mistake: assessing risk based only on the *vulnerability* (scan results) while ignoring asset value. A CVE 9.8 on an internal printer with no sensitive data has a lower residual risk than a CVE 6.5 on a payment gateway. Always multiply by the *impact on the asset*, do not rank purely by CVSS.

### 16.1.2. Quantitative: SLE, ARO, ALE

**WHAT IT IS.** A method that assigns a **monetary value** to risk for objective comparison and to justify the cost of controls (cost-benefit). The standard trio of terms (NIST/(ISC)² CISSP):

| Symbol | Full name | Unit | Formula |
|---------|-----------|--------|-----------|
| AV | Asset Value | money | entered directly |
| EF | Exposure Factor | % (0–1) | proportion of the asset lost in one event |
| SLE | Single Loss Expectancy | money | `SLE = AV × EF` |
| ARO | Annualized Rate of Occurrence | times/year | event frequency per year |
| ALE | Annualized Loss Expectancy | money/year | `ALE = SLE × ARO` |

**A worked example by hand.** Asset = an e-commerce web cluster, AV = USD 2,000,000. A ransomware incident disrupts 30% of revenue per event → EF = 0.30.

```
SLE = AV × EF = 2,000,000 × 0.30 = 600,000 USD / event
Assume ARO = 0.5  (once every 2 years)
ALE = SLE × ARO = 600,000 × 0.5 = 300,000 USD / year
```

**Control investment decision (cost-benefit):** If purchasing an EDR + backup solution costs USD 80,000/year and reduces ARO to 0.1:

```
ALE_new   = 600,000 × 0.1 = 60,000 USD/year
ALE_reduced = 300,000 - 60,000 = 240,000 USD/year  (risk savings)
ROSI (Return On Security Investment) = (240,000 - 80,000) / 80,000 = 200%
```

**Quick-calculation script (runnable, Python 3):**

```python
#!/usr/bin/env python3
# ale_calc.py — calculate SLE/ALE and ROSI for control cost-benefit
def ale(av, ef, aro):
    sle = av * ef
    return sle, sle * aro

def rosi(ale_before, ale_after, control_cost):
    benefit = ale_before - ale_after
    return (benefit - control_cost) / control_cost

av, ef, aro = 2_000_000, 0.30, 0.5
sle, ale_b = ale(av, ef, aro)
_, ale_a   = ale(av, ef, 0.1)
print(f"SLE      = {sle:,.0f} USD/event")
print(f"ALE base = {ale_b:,.0f} USD/yr")
print(f"ALE post = {ale_a:,.0f} USD/yr")
print(f"ROSI     = {rosi(ale_b, ale_a, 80_000):.0%}")
```

Sample output:

```
SLE      = 600,000 USD/event
ALE base = 300,000 USD/yr
ALE post = 60,000 USD/yr
ROSI     = 200%
```

**SECURITY NOTES.** Quantitative analysis sounds scientific, but **EF and ARO are usually guesses**. Use it for *relative comparison* of options, not to report "the risk is exactly USD 300,000" — that is pseudoscience. For long-tail risks such as the loss of the entire cold wallet key, ALE underestimates because it is an extremely small ARO × an extremely large impact → it is better to use a separate scenario analysis.

### 16.1.3. Qualitative: the likelihood × impact matrix

**WHAT IT IS.** When there is no reliable monetary data, use a qualitative scale (usually 5×5). Each axis is 1–5, the risk score = the product, mapped to a color band.

```
IMPACT →        1-Insig  2-Minor  3-Mod   4-Major  5-Severe
LIKELIHOOD ↓
5-Almost Certain   5       10       15      20       25
4-Likely           4        8       12      16       20
3-Possible         3        6        9      12       15
2-Unlikely         2        4        6       8       10
1-Rare             1        2        3       4        5

Band:  1-4 = Low (green)  |  5-9 = Medium (yellow)
       10-15 = High (orange) | 16-25 = Critical (red)
```

**Scale definition table (must be written out concretely, otherwise everyone scores differently):**

| Level | Likelihood (definition) | Impact (financial/operational definition) |
|-----|--------------------------|-----------------------------------------|
| 5 | Occurs >1 time/year | Loss of >1% of annual revenue OR a legal violation incurring a fine |
| 4 | Once per 1–2 years | Disruption of a core service for >4h |
| 3 | Once per 2–5 years | Internal disruption, recovered within the day |
| 2 | Once per 5–10 years | Minor impact, 1 team |
| 1 | Almost never | Negligible |

### 16.1.4. Risk Treatment: the 4 options

| Strategy | Meaning | When to use | Example |
|-----------|---------|--------------|-------|
| **Mitigate** | Add controls to reduce L or I | Risk above threshold, a feasible control exists | WAF, MFA, encryption |
| **Transfer** | Shift the financial consequence to another party | Large impact, hard to reduce on your own | Buy cyber insurance; use a SaaS with an SLA |
| **Avoid** | Drop the activity that generates the risk | Risk exceeds appetite and is not offset by the benefit | Stop storing credit card numbers |
| **Accept** | Keep as-is, formally documented | Residual ≤ risk appetite | Accept a low risk with the risk owner's signature |

**WHY must there be a formal "Accept"?** Every residual risk must have a **risk owner** sign off on its acceptance. This is the key legal/governance point: if an incident occurs, the documentation proves the risk was recognized and someone with authority decided to accept it — rather than "no one knew."

### 16.1.5. Risk Register — the record structure down to each field

**WHAT IT IS.** A risk register — the central repository tracking every risk. Each row = one risk. Below is the standard schema (CSV) down to each field:

| Field | Type/Size | Meaning | Example |
|--------|-----------------|---------|-------|
| `risk_id` | string, e.g. RISK-0001 | Unique identifier | RISK-0042 |
| `asset` | text | Related asset | Hot wallet signing service |
| `threat` | text | Threat | Key exfiltration by an attacker |
| `vulnerability` | text | Weakness | RPC without an allowlist |
| `likelihood_inherent` | int 1–5 | L before control | 4 |
| `impact_inherent` | int 1–5 | I before control | 5 |
| `inherent_score` | int (L×I) | Original risk score | 20 |
| `existing_controls` | text | Existing controls | HSM, network ACL |
| `likelihood_residual` | int 1–5 | L after control | 2 |
| `impact_residual` | int 1–5 | I after control | 5 |
| `residual_score` | int | Residual score | 10 |
| `treatment` | enum | mitigate/transfer/avoid/accept | mitigate |
| `risk_owner` | string | Person accountable | CISO |
| `target_date` | date ISO-8601 | Remediation deadline | 2026-09-30 |
| `status` | enum | open/in_progress/closed/accepted | in_progress |
| `last_review` | date | Most recent review | 2026-06-01 |

**A real example — file `risk_register.csv`:**

```csv
risk_id,asset,threat,vulnerability,L_inh,I_inh,inh_score,controls,L_res,I_res,res_score,treatment,owner,target_date,status
RISK-0042,Hot wallet signer,Key exfiltration,RPC no allowlist,4,5,20,"HSM; net ACL",2,5,10,mitigate,CISO,2026-09-30,in_progress
RISK-0043,KYC PII DB,Data breach,Unencrypted backup,3,5,15,"TDE; KMS",1,5,5,mitigate,DPO,2026-08-15,open
RISK-0044,Old TLS endpoint,MITM,TLS 1.0 enabled,3,3,9,"none",3,3,9,avoid,Infra Lead,2026-07-01,open
```

**Operational query (runnable, using `q`/`csvkit` or awk):**

```bash
# List risks with residual >= 10 (High/Critical) still open, using awk
awk -F',' 'NR>1 && $11>=10 && $15!="closed" {print $1": "$2" (res="$11", owner="$13")"}' risk_register.csv
```

Output:

```
RISK-0042: Hot wallet signer (res=10, owner=CISO)
```

**SECURITY NOTES.** The risk register is a sensitive document — it draws a map of weaknesses for an attacker. Access must be controlled (need-to-know), not left in an open wiki. At the same time it must stay *alive*: review it periodically (e.g. quarterly) — an outdated register is more dangerous than none because it creates a false sense of security.

---

## 16.2. NIST Cybersecurity Framework (CSF)

### 16.2.1. Structure & the 6 Functions (CSF 2.0)

**WHAT IT IS.** The NIST CSF is a voluntary framework, not a control checklist but a **common language** for describing security posture. CSF 1.1 has 5 Functions; **CSF 2.0 (released 2024) adds GOVERN** for a total of 6:

```
            +-------------------+
            |   GV - GOVERN     |  (new in 2.0, spans the other functions)
            +---------+---------+
                      |
 +----------+ +-------+------+ +---------+ +----------+ +----------+
 | ID       | | PR           | | DE      | | RS       | | RC       |
 | IDENTIFY | | PROTECT      | | DETECT  | | RESPOND  | | RECOVER  |
 +----------+ +--------------+ +---------+ +----------+ +----------+
```

**The 3-level hierarchical structure (very important for mapping controls):**

```
Function  (e.g. PR - Protect)
  └─ Category   (e.g. PR.AC - Identity Management & Access Control)
       └─ Subcategory  (e.g. PR.AC-01 - Identities & credentials managed)
            └─ Informative References (map to 800-53, ISO 27001, CIS...)
```

| Code | Function | Objective | Representative categories |
|----|----------|----------|---------------------|
| GV | Govern | Establish & oversee the security strategy, roles, policy, and supply chain risk management | GV.OC, GV.RM, GV.RR, GV.PO, GV.OV, GV.SC |
| ID | Identify | Understand assets, risks, environment | ID.AM (Asset Mgmt), ID.RA (Risk Assessment) |
| PR | Protect | Protective measures | PR.AC/PR.AA, PR.DS (Data Security), PR.PT |
| DE | Detect | Detect events | DE.CM (Continuous Monitoring), DE.AE |
| RS | Respond | Respond | RS.RP, RS.CO, RS.AN, RS.MI |
| RC | Recover | Recover | RC.RP, RC.IM, RC.CO |

> `[NEEDS VERIFICATION]` Specific category codes changed between CSF 1.1 and 2.0 (e.g. PR.AC → PR.AA in 2.0). When writing official documentation, cross-check against the latest CSF 2.0 from nist.gov.

### 16.2.2. Implementation Tiers & Profiles

**Tiers (1–4)** describe the maturity of the risk management process (NOT a security score):

| Tier | Name | Characteristics |
|------|-----|----------|
| 1 | Partial | Reactive, ad-hoc, no process |
| 2 | Risk Informed | Risk awareness exists but is not organization-wide |
| 3 | Repeatable | Formalized as policy, repeatable processes, updated periodically |
| 4 | Adaptive | Continuous improvement, using lessons learned & predictive analysis |

**A Profile** = a mapping of Functions/Categories suited to a specific business. Compare the **Current Profile** vs the **Target Profile** to produce a gap list.

**A real example — a profile file in JSON used to track gaps:**

```json
{
  "organization": "CEX-Example",
  "csf_version": "2.0",
  "assessment_date": "2026-06-19",
  "subcategories": [
    { "id": "GV.SC-04", "desc": "Suppliers prioritized by criticality",
      "current_tier": 2, "target_tier": 4, "gap": 2, "owner": "Procurement" },
    { "id": "PR.DS-01", "desc": "Data-at-rest protected",
      "current_tier": 3, "target_tier": 4, "gap": 1, "owner": "Platform" },
    { "id": "DE.CM-01", "desc": "Networks monitored",
      "current_tier": 2, "target_tier": 3, "gap": 1, "owner": "SOC" }
  ]
}
```

```bash
# List gaps > 0, sorted descending — runnable with jq
jq -r '.subcategories | sort_by(-.gap)[] | select(.gap>0)
       | "\(.id)\tgap=\(.gap)\towner=\(.owner)"' csf_profile.json
```

Output:

```
GV.SC-04	gap=2	owner=Procurement
PR.DS-01	gap=1	owner=Platform
DE.CM-01	gap=1	owner=SOC
```

**SECURITY NOTES.** CSF specifies the framework only; it does *not* say "you must configure AES-256." For concrete action you must drop down to the Informative References → NIST SP 800-53 or the CIS Controls. Do not stop at the CSF level and assume you have controls in place.

---

## 16.3. NIST Special Publications

### 16.3.1. SP 800-53 — Catalog of Security and Privacy Controls

**WHAT IT IS.** NIST's most detailed control catalog (Rev. 5). Mandatory for U.S. federal systems (via FISMA), and widely used as a control library. Organized by **control family** (20 families in Rev. 5).

**Control identifier structure:**

```
   AC - 2 ( 3 )
   │    │   │
   │    │   └── Control Enhancement (optional, number in parentheses)
   │    └────── Control number within the family
   └─────────── Family identifier (2 letters)

Example: AC-2(3) = Account Management, enhancement 3 (Disable Inactive Accounts)
```

**Control families table (selection):**

| Code | Family | Domain |
|----|--------|----------|
| AC | Access Control | Authorization, accounts, least privilege |
| AU | Audit and Accountability | Logs, audit trail, time stamp |
| AT | Awareness and Training | Training |
| CM | Configuration Management | Baseline, hardening |
| CP | Contingency Planning | DR/BCP |
| IA | Identification and Authentication | Identification, MFA |
| IR | Incident Response | Incident response |
| RA | Risk Assessment | Risk assessment, scanning |
| SC | System and Communications Protection | Crypto, network, boundary |
| SI | System and Information Integrity | Patching, AV, flaw remediation |
| SA | System and Services Acquisition | SDLC, supply chain |
| PM | Program Management | Program management |

> Rev. 5 has **20 families** (adding families such as PT - PII Processing, SR - Supply Chain Risk Management). `[NEEDS VERIFICATION]` the complete list of 20 families if an official citation is required.

**Anatomy of a control — example AU-2 Audit Events:**

```
Control:        AU-2 EVENT LOGGING
Statement (a):  Identify the types of events the system is capable of logging
Statement (b):  Coordinate the event logging function with other org entities...
Discussion:     [explains the rationale]
Related:        AC-6, AU-3, AU-12, SI-4 ...
Enhancements:   AU-2(...) [Rev.5 withdrew some]
Baseline:       LOW / MODERATE / HIGH allocation
```

**Baseline by impact classification (from FIPS 199):** each system is classified Low/Moderate/High for each CIA objective, and controls are selected according to the corresponding baseline (SP 800-53B).

**A real example — OSCAL.** NIST publishes the 800-53 catalog in the machine-readable **OSCAL** format (JSON/XML/YAML). This is how it is actually used in DevSecOps to automate compliance:

```bash
# Download the 800-53 Rev5 catalog in OSCAL JSON (public repo usnistgov/oscal-content)
# then extract control AU-2 with jq
jq -r '.catalog.groups[]?.controls[]?
        | select(.id=="au-2")
        | "\(.id | ascii_upcase): \(.title)"' \
   NIST_SP-800-53_rev5_catalog.json
```

Sample output:

```
AU-2: Event Logging
```

**Mapping a control → real configuration (example AU-2/AU-3 on Linux auditd):** the control says "log events," while the real configuration is the file `/etc/audit/rules.d/audit.rules`:

```bash
# /etc/audit/rules.d/00-compliance.rules  (auditd)
# AU-2/AU-3: log all permission configuration changes & record who/what/when
-w /etc/passwd  -p wa -k identity         # track user edits
-w /etc/sudoers -p wa -k privilege        # sudo privilege changes
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_cmd   # commands run as root
# AU-9: protect logs from modification
-e 2                                       # lock the audit config (immutable until reboot)
```

Apply and verify:

```bash
sudo augenrules --load            # load rules
sudo auditctl -l                  # list active rules
# find records related to the key 'privilege'
sudo ausearch -k privilege --start today
```

**SECURITY NOTES.** The control `AU-9 Protection of Audit Information` requires that logs cannot be modified by an attacker. On auditd, `-e 2` makes the configuration immutable; in addition, logs must be pushed **away** (remote syslog/SIEM) immediately, because an attacker who gains root will delete local logs. The audit trail loses its non-repudiation property if an attacker can modify it.

### 16.3.2. SP 800-61 — Computer Security Incident Handling Guide

**WHAT IT IS.** A guide to the incident response (IR) process. It defines a **4-phase lifecycle** (note: this differs from the 6-step SANS PICERL model):

```
   ┌──────────────────────┐
   │ 1. Preparation       │  Prepare: tools, playbooks, training, IR team
   └──────────┬───────────┘
              ▼
   ┌──────────────────────┐
   │ 2. Detection &       │  Detect & analyze: triage, scope, severity
   │    Analysis          │
   └──────────┬───────────┘
              ▼   ◄──────────────┐   (loop: contains multiple rounds)
   ┌──────────────────────┐      │
   │ 3. Containment,      │──────┘
   │    Eradication &     │
   │    Recovery          │
   └──────────┬───────────┘
              ▼
   ┌──────────────────────┐
   │ 4. Post-Incident     │  Lessons learned, update controls & playbooks
   │    Activity          │
   └──────────────────────┘
```

> Comparison: **SANS PICERL** = Preparation, Identification, Containment, Eradication, Recovery, Lessons learned (6 steps). NIST merges Containment/Eradication/Recovery into one large phase (4 phases). `[SP 800-61 Rev.3, 2025, integrated the CSF 2.0 language — NEEDS VERIFICATION of detailed changes]`.

**Containment is divided into 2 types (an important technical decision):**

| Type | Objective | Technical example |
|------|----------|-----------------|
| Short-term | Isolate immediately, prevent spread | Isolate the VLAN, disconnect the NIC, block the IP at the firewall |
| Long-term | Temporary patch so the system runs during the investigation | Temporary patch, increased monitoring, clean replacement host |

**A real example — evidence & chain of custody.** During containment, evidence must be collected *before* destroying state. The order of collection follows volatility (order of volatility, RFC 3227):

```
High volatility  ->  low
1. CPU registers, cache
2. RAM (memory), routing table, ARP cache, process list
3. Temp files, swap
4. Disk
5. Remote logging / monitoring data
6. Physical config, network topology
7. Archival media
```

Commands to collect RAM and hash it to preserve integrity (chain of custody):

```bash
# Dump RAM on the Linux system under investigation (LiME or avml), then hash immediately
sudo ./avml /evidence/mem-$(hostname)-$(date +%Y%m%dT%H%M%SZ).lime
sha256sum /evidence/mem-*.lime | tee /evidence/HASHES.txt
# Record the chain of custody (who, when, what)
printf '%s\tcollector=%s\thost=%s\tsha256=%s\n' \
  "$(date -u +%FT%TZ)" "$USER" "$(hostname)" "$(sha256sum /evidence/mem-*.lime|cut -d' ' -f1)" \
  >> /evidence/custody.log
```

**SECURITY NOTES.** Hashing with SHA-256 *at the moment of collection* is legal proof that the evidence was not modified afterward. If the hash changes → the evidence loses its value in court. Never analyze the original — work on a copy whose hash has been verified.

### 16.3.3. SP 800-207 — Zero Trust Architecture

**WHAT IT IS.** A model that drops "trust based on network location" (no more "inside the network = safe"). Every access request must be authenticated + authorized + have its risk continuously evaluated, based on 7 principles (tenets).

**Logical architecture — PEP/PDP:**

```
   Subject (user/device) ── request ──►  ┌──────── PEP ────────┐
                                          │  Policy Enforcement │  (gateway/proxy)
                                          │     Point           │
                                          └─────────┬───────────┘
                                                    │ allow/deny?
                                                    ▼
                              ┌──────────── Control Plane ──────────────┐
                              │  PDP = Policy Decision Point             │
                              │   ├─ Policy Engine (PE): computes trust score│
                              │   └─ Policy Administrator (PA): grants/revokes │
                              │      tokens, configures the channel      │
                              └────────────┬─────────────────────────────┘
        Signals into the PE:               │
        CDM, threat intel, SIEM, ID mgmt, data access policy, PKI
```

**State machine flow of a Zero Trust request:**

```
1. Subject sends a request to a resource -> intercepted at the PEP
2. PEP asks the PDP: "subject X, device Y, requesting access to resource Z"
3. PE gathers signals: identity (MFA done?), device posture (patched? EDR?),
   context (time, location), threat intel -> computes a trust score
4. Compared against policy -> ALLOW / DENY / STEP-UP (require additional MFA)
5. If ALLOW: the PA issues a short-lived session/token, the PEP opens the channel
6. Continuously re-evaluated: if posture degrades -> revoke the session
```

**A real example — OPA/Rego policy (a real PDP in a K8s/microservice environment):**

```rego
package zerotrust.authz

import future.keywords.if

default allow := false

# Allow if: MFA done, device compliant, within business hours, not threat-intel flagged
allow if {
    input.subject.mfa == true
    input.device.compliant == true
    input.device.patch_age_days <= 30
    input.context.threat_score < 50
    valid_business_hours
}

valid_business_hours if {
    h := time.clock([time.now_ns(), "Asia/Ho_Chi_Minh"])[0]
    h >= 7
    h < 20
}

# Require step-up MFA for a sensitive action
step_up if {
    input.resource.sensitivity == "high"
    input.subject.mfa_age_minutes > 15
}
```

Decision query (runnable with the `opa` binary):

```bash
echo '{
  "subject": {"mfa": true, "mfa_age_minutes": 5},
  "device":  {"compliant": true, "patch_age_days": 12},
  "context": {"threat_score": 10},
  "resource":{"sensitivity": "high"}
}' | opa eval -I -d zerotrust.rego 'data.zerotrust.authz.allow' --format=pretty
```

Output:

```
true
```

**SECURITY NOTES.** The PDP/PEP becomes a point of concentrated power — if an attacker takes over the Policy Administrator, they control all authorization. The control plane must be protected at the highest level (HSM-backed signing tokens, log every decision to the SIEM, never let the PEP fail-open). Issued tokens must be short-lived (a few minutes) for continuous evaluation to be meaningful.

---

## 16.4. ISO/IEC 27001 & 27002

### 16.4.1. ISO/IEC 27001 — ISMS

**WHAT IT IS.** The international standard for an **Information Security Management System (ISMS)**. Unlike the NIST CSF (voluntary), 27001 is a **certifiable** standard — an organization is audited by a third party and issued a certificate. Current version: **ISO/IEC 27001:2022**.

**Structure of 27001 = the clause section (clauses 4–10, MANDATORY) + Annex A (reference controls).**

**PDCA (Plan-Do-Check-Act)** is the engine of continual improvement, mapped onto the clauses:

```
       PLAN ───────────────► DO
   (4 Context,            (8 Operation)
    5 Leadership,             │
    6 Planning,               ▼
    7 Support)            CHECK (9 Performance
        ▲                      evaluation:
        │                      monitoring, audit,
        │                      mgmt review)
        │                         │
       ACT ◄──────────────────────┘
   (10 Improvement:
    nonconformity,
    corrective action)
```

**Clauses 4–10 table (mandatory clauses) — digging into each clause:**

| Clause | Name | Core operational requirement |
|--------|-----|---------------------------|
| 4 | Context of the organization | Define the context, interested parties, **scope of the ISMS** |
| 4.3 | Scope | The scope of applicability (important: a narrow scope = easier audit but less protection) |
| 5 | Leadership | Leadership commitment, ISMS policy, roles & responsibilities |
| 6 | Planning | **Risk assessment + risk treatment**, security objectives, **SoA** |
| 6.1.2 | Risk assessment | A repeatable risk assessment process |
| 6.1.3 | Risk treatment | Select controls + produce the **Statement of Applicability** |
| 7 | Support | Resources, competence, awareness, communication, **documented information** |
| 8 | Operation | Implement the risk treatment plan, change control |
| 9 | Performance evaluation | Measurement, **internal audit**, **management review** |
| 10 | Improvement | Handle nonconformity, corrective action, continual improvement |

**Statement of Applicability (SoA)** — the central document of 27001. It lists **every** Annex A control, recording: whether it is applicable, the rationale, and whether it has been implemented.

**A real example — an SoA as a table (CSV):**

```csv
control_id,control_name,applicable,justification,status,evidence
A.5.1,Policies for information security,YES,Required by ISMS scope,Implemented,POL-001 v3
A.5.7,Threat intelligence,YES,CEX faces APT,In progress,TI feed contract
A.8.1,User endpoint devices,YES,BYOD allowed,Implemented,MDM Intune
A.8.24,Use of cryptography,YES,PII + funds,Implemented,KMS+AES-256-GCM
A.7.4,Physical security monitoring,NO,No own datacenter (cloud only),N/A,AWS SOC2 report
```

```bash
# Check: which controls are applicable=YES but not yet Implemented (an audit gap)
awk -F',' 'NR>1 && $3=="YES" && $5!="Implemented" {print $1" ("$2") -> "$5}' soa.csv
```

Output:

```
A.5.7 (Threat intelligence) -> In progress
```

**WHY is the SoA important?** The auditor uses the SoA as a starting point: for each "Applicable + Implemented" control, they demand **evidence**. For each "Not applicable," they demand a **reasonable justification**. The SoA is the contract between the organization and the auditor.

**Annex A of 27001:2022 — 93 controls, 4 themes** (restructured from the 114 controls/14 domains of the 2013 version):

| Theme | Code | # of controls | Content |
|-------|-----|-----------|----------|
| Organizational | A.5 | 37 | Policy, roles, suppliers, IR, compliance |
| People | A.6 | 8 | Recruitment, training, disciplinary process, remote work |
| Physical | A.7 | 14 | Security zones, equipment, data destruction |
| Technological | A.8 | 34 | Access control, crypto, logging, network, secure development |

### 16.4.2. ISO/IEC 27002 — Code of practice

**WHAT IT IS.** While 27001 *says which control* (Annex A lists the names), **27002 explains what that control means and how to implement it** (implementation guidance). It uses the same numbering (A.5–A.8).

**The 5 new attributes in 27002:2022** — each control is tagged to enable filtering/mapping:

| Attribute | Possible values |
|------------|----------------|
| Control type | Preventive / Detective / Corrective |
| Information security properties | Confidentiality / Integrity / Availability |
| Cybersecurity concepts | Identify / Protect / Detect / Respond / Recover (maps to CSF) |
| Operational capabilities | Governance, Asset_mgmt, Identity_and_access_mgmt... |
| Security domains | Governance_and_Ecosystem, Protection, Defence, Resilience |

**WHY have attributes?** They allow you to slice the control catalog across multiple dimensions — for example, filtering all "Detective + Detect" controls to build monitoring capability. This is the technical bridge between ISO and the NIST CSF.

### 16.4.3. Audit & certification

**The 27001 certification process (2 stages):**

```
Stage 1 audit  (Documentation review)
  - Check that the ISMS has complete documentation: scope, policy, SoA, risk assessment,
    risk treatment plan, internal audit, management review.
  - Outcome: whether it is ready for Stage 2.
        │
        ▼
Stage 2 audit  (Implementation / effectiveness)
  - The auditor samples controls and demands evidence of execution (logs, tickets, screenshots,
    configuration). Interviews staff.
  - Findings: Major NC / Minor NC / Observation.
        │
        ▼
Certification (certificate valid for 3 years)
        │
        ▼
Surveillance audit (year 1, year 2) -> Recertification (year 3)
```

**Classification of findings:**

| Type | Meaning | Consequence |
|------|-------|--------|
| Major nonconformity | A systemic violation/missing mandatory control | Blocks certification until remediated |
| Minor nonconformity | A localized, non-systemic deviation | Requires a corrective action plan |
| Observation/OFI | An opportunity for improvement | Not mandatory, but should be addressed |

**SECURITY NOTES.** A 27001 certificate certifies that a *management system* exists and operates, NOT that the system "cannot be hacked." A narrow scope (e.g. only one department) can still receive a valid certificate — always read the **scope statement** on a vendor's certificate before trusting it. This is an important due diligence point when assessing a vendor.

---

## 16.5. PCI DSS (overview — financial/card industry)

**WHAT IT IS.** The Payment Card Industry Data Security Standard — a standard mandated by *contract* (not by law) for any organization that stores/processes/transmits **cardholder data (CHD)**. Current version **PCI DSS v4.0 / v4.0.1**. 6 objectives, **12 requirements**.

**Cardholder data — classified down to each field (EXTREMELY important, it determines what may be stored):**

| Group | Field | Storable after authorization? | Note |
|------|--------|------------------------------|---------|
| Cardholder Data (CHD) | PAN (Primary Account Number, 13–19 digits) | YES — but must be encrypted/truncated | Display at most the first 6 + last 4 |
| CHD | Cardholder name | YES | |
| CHD | Expiration date | YES | |
| CHD | Service code | YES | |
| Sensitive Auth Data (SAD) | Full track data (magnetic stripe) | **NEVER** | Prohibited from storage after auth |
| SAD | CAV2/CVC2/CVV2/CID (3–4 digit code) | **NEVER** | Prohibited from storage after auth |
| SAD | PIN / PIN block | **NEVER** | Prohibited from storage after auth |

**The 12 PCI DSS requirements (6 objectives):**

```
Build & Maintain Secure Network
  1. Install & maintain network security controls (firewall)
  2. Apply secure configurations (no vendor defaults)
Protect Account Data
  3. Protect stored account data (encrypt the PAN)
  4. Encrypt CHD transmitted over public networks (TLS)
Maintain Vulnerability Mgmt
  5. Protect against malware
  6. Develop & maintain secure systems/software
Strong Access Control
  7. Restrict access on a need-to-know basis
  8. Identify & authenticate access (MFA)
  9. Restrict physical access
Monitor & Test
  10. Log & monitor all access to CHD
  11. Test security regularly (scan, pentest)
Maintain Policy
  12. Information security policy
```

**A real example — masking the PAN (Requirement 3.4) in logs.** Never log the full PAN. The masking function keeps the first 6 + last 4:

```python
def mask_pan(pan: str) -> str:
    pan = pan.replace(" ", "")
    if len(pan) < 13:
        raise ValueError("Invalid PAN")
    return pan[:6] + "*" * (len(pan) - 10) + pan[-4:]

print(mask_pan("4111111111111111"))   # -> 411111******1111
```

**Luhn check (mod-10) — PAN structurally valid:**

```python
def luhn_ok(pan: str) -> bool:
    digits = [int(d) for d in pan if d.isdigit()][::-1]
    total = sum(d if i % 2 == 0 else (d*2 - 9 if d*2 > 9 else d*2)
                for i, d in enumerate(digits))
    return total % 10 == 0

print(luhn_ok("4111111111111111"))   # -> True
```

**SECURITY NOTES.** The most effective way to reduce PCI scope is **tokenization** — replace the PAN with a meaningless token, keeping the real PAN in a vault or offloading it entirely to a payment processor (the PAN never touches your system). Every system that "touches" CHD falls into audit scope, so a good architecture isolates the **Cardholder Data Environment (CDE)** with strict segmentation (Requirement 1) to narrow the scope.

---

## 16.6. Vietnamese law (at the level of operational meaning)

> This section interprets the **operational meaning** for engineers. Specific document numbers/articles are marked `[NEEDS VERIFICATION]` where uncertain — do NOT use this as formal legal advice; for legal decisions you must cross-check the original text and consult the legal department.

### 16.6.1. Law on Cyber Information Security 2015

**WHAT IT IS.** The Law on Cyber Information Security No. **86/2015/QH13**, effective **2016-07-01**. The foundational legal framework for information security: protecting information on networks, classifying information, protecting personal information (at the level of principle), information system security, the business of information security products/services (licensing), and civil cryptography.

**Operational meaning for engineers:**

| Topic in the law | Real operational consequence |
|-------------------|--------------------------|
| Protection of personal information (principle) | Consent is required when collecting; data may be corrected/deleted on request (more detail in Decree 13/2023) |
| Classification of systems by level | Lays the foundation for the level 1–5 classification (detail in Decree 85/2016) |
| Business of information security products/services | Providing pentest/security monitoring services requires a license |
| Civil cryptography | Trading in civil cryptography products requires a license (Government Cipher Committee) |

### 16.6.2. Cybersecurity Law 2018

**WHAT IT IS.** The Cybersecurity Law No. **24/2018/QH14**, effective **2019-01-01**. It focuses on **national security and social order and safety** in cyberspace — a different emphasis from the Cyber Information Security Law (which leans technical).

**Two notable operational points (controversial and affecting system architecture):**

| Topic | Operational meaning |
|--------|-------------------|
| **Data localization (in-country storage)** | Some enterprises (especially those providing services over telecom/Internet networks that collect Vietnamese user data) may be required to **store data within Vietnam** and establish a branch/representative office. This is a key **data residency** factor when designing a cloud architecture. |
| **Protection of information systems important to national security** | Systems in this category are subject to cybersecurity inspection/monitoring by the authorities |
| Cooperation in investigations | An obligation to provide information/support to the authorities as prescribed |

> `[NEEDS VERIFICATION]` The scope of affected parties and the specific conditions of the localization requirement are detailed in the implementing decree (e.g. Decree 53/2022/NĐ-CP guiding the Cybersecurity Law). The affected parties and the application "trigger" should be read carefully in the decree.

### 16.6.3. Classifying systems by level — Decree 85/2016/NĐ-CP

**WHAT IT IS.** Decree **85/2016/NĐ-CP** on **ensuring the security of information systems by level** (guiding the Cyber Information Security Law 2015). It classifies information systems into **5 levels** by the severity of consequences if compromised. The higher the level → the stricter the technical & management requirements.

**Similar in spirit to the U.S. FIPS 199 (Low/Mod/High) but with 5 levels:**

| Level | Description of consequences (operational interpretation) | Illustrative example |
|--------|-------------------------------------|----------------|
| Level 1 | Minor harm to the legitimate rights/interests of an organization or individual | An internal showcase website |
| Level 2 | Serious harm to rights/interests | An enterprise's internal service system |
| Level 3 | Serious harm to production, public interest, social order | A system with much personal data; a large-scale online service |
| Level 4 | Very serious harm to national defense and security OR especially serious harm to public order and interest | A large financial/banking system, critical infrastructure |
| Level 5 | Especially serious harm to national defense and security | A nation's most critical systems |

**Operational consequence (the level-dossier process):**

```
1. Preliminarily classify the system -> determine the proposed level
2. Prepare a DOSSIER proposing the level (system description, security assurance plan)
3. Appraise & approve the level (competent authority)
4. Implement the security assurance plan as required by the LEVEL
   (technical requirements reference TCVN 11930:2017 - basic requirements for
    ensuring information system security by level)
5. Inspect and assess periodically
```

> **Level 4 and above** carry strict technical & management requirements (monitoring, response plans, strong access control...). `[NEEDS VERIFICATION]` The detailed technical requirements for each level are in **TCVN 11930:2017** and the guiding circulars of the Ministry of Information and Communications — consult the original text for a precise list of each technical requirement for level 4.

**SECURITY NOTES.** For an exchange/financial system in Vietnam, determining the level (usually falling into level 3 or 4) drives the entire legally mandatory control baseline — similar to how FIPS 199 determines the 800-53 baseline. You must prepare the level dossier before designing controls, not the other way around.

### 16.6.4. Personal data protection — Decree 13/2023/NĐ-CP

**WHAT IT IS.** Decree **13/2023/NĐ-CP** on **personal data protection (PDPD)**, effective **2023-07-01**. This is the instrument closest to the GDPR in Vietnam to date. It defines personal data, sensitive personal data, the roles of the parties, data subject rights, and obligations.

**Classification of personal data (determines the level of technical protection):**

| Type | Operational definition | Example |
|------|---------------------|-------|
| Basic personal data | Ordinary identifying information | Full name, date of birth, phone number, email, national ID |
| Sensitive personal data | Requires enhanced protection | Health, biometrics, financial, political/religious views, location, sexual life... |

**Roles of the parties (mapped to GDPR controller/processor):**

| Role under Decree 13/2023 | GDPR equivalent | Meaning |
|---------------------|-------------------|-------|
| Personal Data Controller | Controller | Decides the purpose & means of processing |
| Personal Data Processor | Processor | Processes under authorization from the controller |
| Controller-cum-Processor | Controller+Processor | Both decides and processes |
| Third party | Third party | |

**Key operational obligations:**

| Obligation | Technical consequence |
|----------|------------------|
| **Consent** before processing | Must have a mechanism to collect + log consent (timestamp, purpose, policy version) |
| Data subject rights: access, correct, delete, withdraw consent, object | Must have a DSAR (Data Subject Access Request) API/process |
| **Data processing impact assessment dossier (DPIA)** — `[NEEDS VERIFICATION of the exact name/form]` | Prepare a personal data processing impact assessment dossier, store it, and have it ready to provide to the authority (Ministry of Public Security - A05) |
| Notification of processing sensitive data / transferring data abroad | A dossier for transferring personal data abroad (TIA) |
| Breach notification | A breach notification process within the prescribed time limit |

> `[NEEDS VERIFICATION]` The breach notification time limit (72h?) and the specific DPIA/TIA dossier forms under Decree 13/2023 — consult the original text.

**A real example — a consent logging schema (auditable, satisfying the obligation to prove):**

```sql
CREATE TABLE consent_records (
    consent_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    data_subject  VARCHAR(64)  NOT NULL,         -- pseudonym, do NOT store raw PII
    purpose       VARCHAR(128) NOT NULL,         -- the specific purpose
    policy_version VARCHAR(16) NOT NULL,         -- version of the policy that was shown
    consent_given BOOLEAN      NOT NULL,
    granted_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    withdrawn_at  TIMESTAMPTZ,                   -- null if not yet withdrawn
    source_ip_hash CHAR(64),                     -- sha256(ip) — evidence, not the raw IP
    evidence_hash CHAR(64)                       -- hash of the full consent record
);
-- Right to withdraw consent: update withdrawn_at, do NOT delete the record (keep the audit trail)
UPDATE consent_records SET withdrawn_at = now()
 WHERE data_subject = 'subj_8f2a' AND purpose = 'marketing';
```

**SECURITY NOTES.** The consent table is **legal evidence** — it must be immutable (append-only/audit log), with no arbitrary UPDATE/DELETE allowed on `granted_at`. When handling the "right to erasure," it must be balanced against other retention obligations (e.g. anti-money-laundering law requires keeping KYC for many years) — not all data can be deleted immediately; this is a very real retention conflict.

### 16.6.5. Decree 356/2025 (needs verification)

> `[NEEDS VERIFICATION — INSUFFICIENT RELIABLE DATA]` At the time of writing, I have **no verified information** about the detailed content of "Decree 356/2025." Do not fabricate content. When a citation is needed, it is mandatory to:
> 1. Look up the original text on the legal information portal (vbpl.vn / thuvienphapluat.vn / the official gazette).
> 2. Confirm the document number, date of issue, scope of regulation, and its relationship to existing decrees (e.g. whether it replaces any decree).
> 3. Update this section with specific provisions after cross-checking.
>
> Citing a decree number/article incorrectly in a compliance document can lead to serious legal errors — therefore this document deliberately leaves it blank rather than filling in unverified information.

---

## 16.7. Operational Compliance

### 16.7.1. Data Classification

**WHAT IT IS.** Labeling data by sensitivity to apply corresponding controls. This is a *prerequisite* for every other control (encryption, retention, access) — without classification you do not know what to apply.

**A typical 4-level model + control mapping:**

| Label | Description | Encryption control | Retention | Who has access |
|------|-------|----------------|-----------|--------------|
| Public | May be made public | Not required | As needed | Everyone |
| Internal | Internal | TLS in transit | 1–3 years | Employees |
| Confidential | Business secret | At-rest + transit | Per business need | Need-to-know |
| Restricted/Secret | Sensitive PII, wallet keys, CHD | AES-256 + KMS + key separation | Per law (KYC for many years) | Minimal, MFA, log all access |

**A real example — labeling at the infrastructure layer (AWS S3 tag + a bucket policy that enforces encryption):**

```json
// bucket policy: deny upload if not SSE-KMS encrypted (enforce the control for Restricted data)
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyUnEncryptedUploads",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::cex-kyc-restricted/*",
    "Condition": {
      "StringNotEquals": { "s3:x-amz-server-side-encryption": "aws:kms" }
    }
  }]
}
```

```bash
# Attach classification labels to the resource (tag-based policy)
aws s3api put-bucket-tagging --bucket cex-kyc-restricted \
  --tagging 'TagSet=[{Key=DataClass,Value=Restricted},{Key=Regulation,Value=ND13-2023}]'
```

### 16.7.2. Access control & audit trail

**Audit trail — a log record of "who did what, when, and the result" — structured down to each field:**

| Field | Size/Type | Meaning | Example |
|--------|------------------|---------|-------|
| `timestamp` | ISO-8601, UTC | The moment (NTP-synced) | 2026-06-19T03:22:11.482Z |
| `actor` | string | The acting subject | uid=svc_payment / user=alice |
| `actor_ip` | IPv4/IPv6 | The source | 10.4.2.17 |
| `action` | enum | The action | READ / WRITE / DELETE / LOGIN |
| `resource` | URI/ID | The target | kyc-db/customer/8842 |
| `result` | enum | The result | SUCCESS / DENIED / ERROR |
| `session_id` | uuid | The session | b1f2... |
| `correlation_id` | uuid | Cross-system trace | trace-... |
| `prev_hash` | hex(32B) | Hash of the previous record (tamper-evidence) | 9f3c... |

**Why is there a `prev_hash`?** To turn the log into a **hash chain** — modifying one old record breaks every hash that follows, making tampering detectable. This is the core of a non-repudiation audit trail:

```
record[n].hash = SHA256( record[n].fields || record[n-1].hash )

If an attacker modifies record[k], then record[k].hash changes
-> record[k+1].prev_hash no longer matches -> a break in the chain is detected
```

**A real example — generating a hash-chain log (Python):**

```python
import hashlib, json
def chain_append(prev_hash: str, event: dict) -> str:
    payload = json.dumps(event, sort_keys=True).encode() + bytes.fromhex(prev_hash or "00"*32)
    return hashlib.sha256(payload).hexdigest()

prev = "00"*32
for ev in [{"ts":"2026-06-19T03:22:11Z","actor":"alice","action":"READ","res":"kyc/8842","result":"SUCCESS"}]:
    prev = chain_append(prev, ev)
    print(ev["action"], "->", prev[:16], "...")
```

### 16.7.3. Log retention & data residency

**Log retention** — how long logs are kept, governed by: (1) legal requirements, (2) investigative capability, (3) storage cost.

| Log type | Recommended retention (reference) | Reason |
|----------|-----------------------------------|-------|
| Security/audit log (PII access, privileged) | usually ≥ 1 year (PCI DSS Req.10: minimum 1 year, 3 months online) | Incident investigation, audit |
| KYC/AML records | many years per anti-money-laundering law | Legal obligation |
| Application/debug log | 30–90 days | Operations |

> `[NEEDS VERIFICATION]` The specific legal retention periods in Vietnam (e.g. under the Anti-Money-Laundering Law 2022, the decree on classification levels) — cross-check the text. PCI DSS Req.10 mandates **retention ≥12 months, ≥3 months immediately retrievable**, which is a figure verified in the PCI standard.

**Data residency** — which geographic region the data must reside in. Directly related to the Cybersecurity Law (localization). Applied technically via region pinning:

```hcl
# Terraform: pin resources to a region in/near Vietnam & forbid replication outward
provider "aws" {
  region = "ap-southeast-1"   # Singapore (near Vietnam); if it must be located in Vietnam, use
                              # a domestic provider (VNG, Viettel, FPT...)
}
resource "aws_s3_bucket" "kyc" {
  bucket = "cex-kyc-restricted"
}
# Block cross-region replication: do NOT declare replication_configuration
# + use an SCP (Service Control Policy) to forbid creating buckets outside the allowed region
```

**An SCP enforcing data residency org-wide (AWS Organizations):**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyOutsideAllowedRegions",
    "Effect": "Deny",
    "NotAction": [ "iam:*", "organizations:*", "route53:*" ],
    "Resource": "*",
    "Condition": {
      "StringNotEquals": { "aws:RequestedRegion": [ "ap-southeast-1" ] }
    }
  }]
}
```

**SECURITY NOTES.** Data residency is not only the bucket's region — beware of: automatic backups to another region, CDN edge cache, log forwarding to a US SaaS (Datadog/Splunk Cloud), an international email/SMS provider. You must draw a complete **data flow map** to know where PII *actually* goes, and not trust only the primary DB's region configuration.

### 16.7.4. Control crosswalk across frameworks

**WHY.** An organization is often subject to multiple frameworks at once (27001 + CSF + Decree 85 + PCI). Implementing one physical control → satisfies multiple requirements. A **crosswalk** avoids duplicated work.

**Example mapping of the control "MFA for privileged access":**

| Framework | Control identifier |
|-----------|--------------------|
| NIST CSF 2.0 | PR.AA-03 (authenticate) |
| NIST 800-53 | IA-2(1), IA-2(2) |
| ISO 27001:2022 Annex A | A.8.5 (Secure authentication) |
| PCI DSS v4.0 | Req. 8.4 / 8.5 (MFA) |
| Decree 85/2016 (TCVN 11930) | Authentication requirements by level `[NEEDS VERIFICATION of the section code]` |

**A real example — a crosswalk file in YAML used in DevSecOps (1 control → multiple frameworks, with evidence attached):**

```yaml
controls:
  - id: ORG-MFA-PRIV
    name: "Mandatory MFA for privileged access"
    implementation: "Okta + FIDO2 for admins; conditions in OPA"
    evidence:
      - "okta_policy_export_2026Q2.json"
      - "opa_test_results.txt"
    satisfies:
      nist_csf: ["PR.AA-03"]
      nist_800_53: ["IA-2(1)", "IA-2(2)"]
      iso_27001: ["A.8.5"]
      pci_dss: ["8.4.2", "8.5.1"]
```

```bash
# Count how many requirements 1 control satisfies (measure the control's "leverage")
yq '.controls[] | .id + ": " + ([.satisfies[][]] | length | tostring) + " requirements"' crosswalk.yaml
```

Output:

```
ORG-MFA-PRIV: 7 requirements
```

---

## 16.8. GRC in banking / finance

### 16.8.1. The Three Lines Model

**WHAT IT IS.** The standard risk governance model in the financial industry (IIA — the Institute of Internal Auditors). It separates responsibilities to avoid conflicts of interest.

```
┌────────────────────────────────────────────────────────────┐
│ BOARD OF DIRECTORS / AUDIT COMMITTEE (oversight)            │
└───────────────┬──────────────────────────────────────────────┘
   1st Line            2nd Line              3rd Line
┌──────────────┐ ┌──────────────────┐ ┌─────────────────────┐
│ Owns &       │ │ Risk oversight & │ │ Independent          │
│ manages risk │ │ compliance        │ │ assurance           │
│ day-to-day   │ │ (Risk, Compliance,│ │ (Internal Audit)    │
│ (Dev, SecOps,│ │  CISO office)     │ │                     │
│  IT, biz)    │ │ - sets policy     │ │ - independent audit │
│              │ │ - monitors        │ │   of 1st & 2nd line │
│              │ │   controls        │ │ - reports directly  │
│              │ │                   │ │   to the Board       │
└──────────────┘ └──────────────────┘ └─────────────────────┘
        ▲                                  │ External Audit + Regulator
        └──────────────────────────────────┘ (external)
```

**WHY separate the lines?** The people who *operate* the controls (1st) must not *assess* their own controls (3rd) — otherwise it is a case of "playing and refereeing at the same time." Internal Audit (3rd line) reports straight to the Board, not through the CISO, to preserve independence.

### 16.8.2. The legal/supervisory framework for the Vietnamese financial industry (operational level)

| Authority/Document | Operational role |
|------------------|-------------------|
| State Bank of Vietnam (SBV) | The supervisory authority; issues circulars on banking IT security |
| Circular on the security of banking information systems | `[NEEDS VERIFICATION of the document number]` — typically prescribes system classification, backup, DR, access control, and logging for credit institutions |
| Anti-Money-Laundering Law (2022) | KYC/CDD obligations, suspicious transaction reporting (STR), record-keeping |
| Basel / international standards | A reference for operational risk governance |

> `[NEEDS VERIFICATION]` The number of the SBV circular on IT security (e.g. circulars prescribing information system security assurance in banking operations) — consult the original text before citing.

### 16.8.3. Continuous Compliance in DevSecOps

**WHAT IT IS.** Instead of a manual audit once a year, **continuous compliance control** via policy-as-code running in CI/CD. This is the intersection of GRC and DevSecOps.

**A real example — checking a control in the pipeline (OPA Conftest checking IaC before deploy):**

```rego
# policy/encryption.rego — fail the build if a Restricted resource is not encrypted
package main
deny[msg] {
    input.resource.aws_s3_bucket[name]
    not input.resource.aws_s3_bucket_server_side_encryption_configuration[name]
    msg := sprintf("S3 bucket '%s' is missing at-rest encryption (violates A.8.24 / Decree 13)", [name])
}
```

```bash
# Run in CI: block the merge if the encryption control is violated
conftest test --policy policy/ terraform-plan.json
```

Sample output on violation:

```
FAIL - terraform-plan.json - main - S3 bucket 'cex-kyc-restricted' is missing at-rest encryption (violates A.8.24 / Decree 13)
1 test, 0 passed, 1 failure
```

**Example — automatically collecting evidence for an audit (a script that gathers logs + configuration into an evidence package with a hash):**

```bash
#!/usr/bin/env bash
# collect_evidence.sh — package evidence for the Q2 audit cycle
set -euo pipefail
OUT="evidence_$(date +%Y%m%d).tar.gz"
mkdir -p evidence/{access,config,scan}
aws iam get-account-password-policy            > evidence/config/pw_policy.json
aws s3api get-bucket-encryption --bucket cex-kyc-restricted > evidence/config/s3_enc.json
auditctl -l                                    > evidence/access/auditd_rules.txt
tar czf "$OUT" evidence/
sha256sum "$OUT" | tee "${OUT}.sha256"
echo "Evidence package: $OUT"
```

**SECURITY NOTES.** Policy-as-code can **fail-open** if the pipeline skips the test step on error (e.g. `|| true`). In a financial environment, the compliance control must **fail-closed** — the pipeline must stop (exit non-zero) when a policy is violated or when the policy engine itself fails. At the same time, automated evidence must be immutable (write-once, pushed to object lock / WORM storage) for the auditor to trust it.

---

## 16.9. Summary & quick-reference checklist

**When to use which framework:**

| Need | Use |
|---------|------|
| A common language to describe security posture, reporting to leadership | NIST CSF 2.0 |
| A detailed technical control library to select & implement | NIST SP 800-53 |
| An incident response process | NIST SP 800-61 |
| Dropping location-based trust, microsegmentation | NIST SP 800-207 (ZT) |
| International certification of a management system | ISO/IEC 27001 + 27002 |
| Handling payment card data | PCI DSS v4.0 |
| Vietnamese law — security by level | Cyber Info Sec Law 2015 + Decree 85/2016 + TCVN 11930 |
| Vietnamese law — national security, localization | Cybersecurity Law 2018 (+ implementing decree) |
| Vietnamese law — personal data | Decree 13/2023 |

**Self-protection rule when writing compliance documentation:** every document number, article, and legal retention period must be cross-checked against the original text before official use. This document marks `[NEEDS VERIFICATION]` everywhere it could not be verified — especially **Decree 356/2025** (no reliable information yet), the SBV circular numbers, the TCVN 11930 section codes, and the breach notification time limit of Decree 13/2023.
