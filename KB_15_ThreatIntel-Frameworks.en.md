# Chapter 15 — Threat Intelligence & Attack Frameworks

## Overview

This chapter explains how security engineers **describe, detect, measure, and respond to** adversary behavior through a "common language" of standardized frameworks and tools. When every team describes attacks in its own way, the organization loses the ability to exchange intelligence, measure defensive coverage, and prioritize investment. The frameworks below address precisely that problem: they are unified identifiers and reference models that turn scattered alerts into actionable knowledge.

**Threat Intelligence (CTI).** This is threat data that has been processed and enriched with context to support decision-making, as distinct from raw data. An IP address in a log is *data*; identifying that IP as the C2 server of a group targeting the financial sector, together with a recommendation to block it, is *intelligence*. CTI addresses the problem of alert overload: it filters out what is worth worrying about, why, and what to do next.

**Cyber Kill Chain.** A model that divides a targeted attack into **7 linear stages**, from reconnaissance to actions on the objective. Its core value: breaking any single link breaks the whole chain, while also providing a strategic-level narrative framework for leadership.

**Diamond Model.** Models each intrusion event through **4 vertices**: adversary, capability (tools/malware), infrastructure (C2 hosts, domains, IPs), and victim. Its strength lies in **pivoting**: knowing one vertex lets you trace the others — from a malicious domain, infer the shared IP, then the group's other domains.

**IOC and IOA.** An **IOC (Indicator of Compromise)** is static evidence indicating that an incident has occurred: a malicious file hash, a bad IP, a registry key. An **IOA (Indicator of Attack)** is a chain of suspicious behavior in progress: for example, Word spawning PowerShell which then downloads a file from the Internet. IOCs are easily changed (alter one byte and you get a new hash), so they are short-lived; IOAs are based on attack logic, making them harder to evade and capable of catching even previously unseen variants.

**Pyramid of Pain.** Ranks indicator types by **the cost an attacker must pay to evade** when blocked. The base of the pyramid (hashes, IPs) changes within minutes; the apex (TTPs — how the adversary operates) forces the attacker to change their entire approach. The model guides detection investment: prioritize the upper tiers for durable effectiveness.

**MITRE ATT&CK.** A knowledge base listing adversary behaviors **observed in the real world**, organized as a matrix and a hierarchy tree: *Tactic* (the goal — "why"), *Technique* (the method — "what"), *Sub-technique* (the variant — "how"), *Procedure* (the concrete implementation). Each entry has a unique identifier (e.g., `T1059.001`), enabling you to measure detection coverage and write rules against each behavior.

**ATT&CK Navigator.** A web application that colors the ATT&CK matrix to visualize detection coverage, the activity of an APT group, and gap analysis. The data is stored as a layer file (JSON), letting leadership and defenders see weaknesses immediately rather than reading a long list.

**Detection Engineering: Sigma, YARA, Suricata.** Three rule formats corresponding to three layers of evidence:
- **Sigma**: detection rules over **logs** in a SIEM-agnostic format, compiled to Splunk, Elastic, Sentinel, etc.
- **YARA**: rules matching **strings/bytes/regex in files or memory** to classify malware.
- **Suricata**: an IDS/IPS that inspects **network traffic** to detect C2 channels and exfiltration.

All three can be tagged with ATT&CK identifiers to measure coverage per technique.

**Intelligence sharing: STIX, TAXII, MISP.**
- **STIX**: a standard JSON format for representing threat information for machine consumption.
- **TAXII**: a REST/HTTPS protocol for automatically exchanging STIX between parties.
- **MISP**: a platform for storing and sharing IOCs, integrating TLP labels and the ATT&CK Galaxy.

The rationale for sharing: attackers reuse their tradecraft against many victims, so timely warnings protect the next organizations in line.

**Malware classification and analysis.** The final part of the chapter distinguishes malware types (virus, worm, trojan, ransomware, rootkit, RAT, botnet, fileless) by their propagation mechanism and self-replication capability, then presents two approaches to dissecting a sample: **static analysis** (examining the file without executing it) and **dynamic analysis** (running it in an isolated environment to observe behavior). Correctly naming the malware type and understanding its mechanism is the basis for choosing appropriate prevention and response measures.

> Chapter goal: equip security engineers (Blue Team / AppSec / DevSecOps) with a unified mental model to **describe**, **detect**, **measure**, and **respond to** adversary behavior. The chapter goes from intelligence theory (CTI) down to concrete data structures (STIX objects, MISP attributes, IOC formats, PE headers), and on to runnable commands and configuration files (Sigma, YARA, Suricata, ATT&CK Navigator JSON, MISP REST API).

---

## 15.1. Why frameworks are needed: from "scattered alerts" to a "common language"

Before standardized frameworks existed, every security team described attacks in its own way: "someone logged in with the wrong password many times," "a strange file ran PowerShell." The problem was not a lack of data but a **lack of a common language** to:

1. **Exchange** between teams/organizations (internal SOC ↔ ISAC ↔ vendor).
2. **Measure detection coverage**: what percentage of the behaviors an adversary could perform can we detect?
3. **Prioritize investment**: which detection rule should we write first?
4. **Reproducibility**: the same behavior is always referred to by the same identifier.

The frameworks in this chapter solve different problems but complement one another:

| Framework | The question it answers | Level of abstraction |
|---|---|---|
| Cyber Kill Chain | What **linear stages** does an attack pass through? | High (strategic) |
| Diamond Model | How does an event relate to **adversary / capability / infrastructure / victim**? | Medium (event analysis) |
| MITRE ATT&CK | What does the adversary **actually do** at each stage (observed behavior)? | Low (technical, measurable) |
| Pyramid of Pain | Which IOC, when blocked, **hurts** the adversary most? | A measure of IOC value |

**Why so many frameworks?** The Kill Chain is too coarse to write detections from; ATT&CK is too detailed to report to leadership; the Diamond Model helps analyze relationships but does not enumerate techniques. A mature SOC uses all three: the Kill Chain to tell the story, the Diamond Model to pivot investigations, and ATT&CK to measure coverage and write rules.

---

## 15.2. Cyber Threat Intelligence (CTI): definition, classification, lifecycle

### 15.2.1. What CTI is and is not

**Threat Intelligence** = threat data that has been **processed + analyzed + contextualized** to support **decision-making**. The key point distinguishing it from raw "data":

```
Data      → "IP 185.220.101.45 appeared in the logs"
Information→ "This IP is a Tor exit node, connected at 03:00"
Intelligence→ "This IP was used by the FIN7 group as C2 in a campaign
              targeting the financial sector in May; recommend blocking
              + hunting for hosts that have beaconed to it"
```

Intelligence must be **actionable** and carry **context** (who, what target, why).

### 15.2.2. The four types of CTI

| Type | Consumer | Time horizon | Concrete example | Typical format |
|---|---|---|---|---|
| **Strategic** | Leadership, CISO | Long-term (months/years) | "The crypto-exchange sector is targeted by Lazarus with financial motives" | Prose report, non-technical |
| **Operational** | SOC manager, IR lead | Medium-term (weeks) | "An ongoing campaign uses Office macros → Cobalt Strike; TTPs include T1566.001, T1059.001" | Campaign report, TTP list |
| **Tactical** | Threat hunter, detection engineer | Short–medium | "Specific TTP: PowerShell `-enc` base64 spawned from winword.exe" | Sigma rule, ATT&CK technique |
| **Technical** | SOC analyst L1/L2, automated systems | Very short (hours/days) | "Hash `a1b2c3...`, IP `185.x`, domain `evil.com`" | IOC feed (STIX/MISP), CSV |

**Why tier it?** Because technical IOCs are **perishable** (the adversary changes IPs/hashes easily) while TTPs/strategic intelligence are more **durable**. Detection investment should shift toward the higher tiers (see the Pyramid of Pain in 15.6).

### 15.2.3. The Intelligence Lifecycle — 6 phases

The classic model (originating in the military/CIA intelligence community, applied to CTI):

```
        ┌──────────────────────────────────────────┐
        ▼                                            │
 1.Direction → 2.Collection → 3.Processing →         │
                                   4.Analysis →       │
                                   5.Dissemination →  │
                                   6.Feedback ────────┘
```

| Phase | What is done | Output | Technical note |
|---|---|---|---|
| **1. Direction (Planning)** | Define intelligence requirements (PIR – Priority Intelligence Requirements) | "Who is targeting us? With which TTPs?" | No PIR → aimless collection, drowning in useless IOCs |
| **2. Collection** | Gather from OSINT, commercial feeds, internal telemetry, dark web, ISAC | Raw data | Record source + timestamp to assess reliability |
| **3. Processing** | Normalize: parse logs, decode, dedupe, normalize to STIX | Structured data | An often-skipped step → "garbage in" |
| **4. Analysis** | Correlate, assign TTPs, assess reliability (Admiralty Code) | Intelligence product | Avoid confirmation bias; use ACH (Analysis of Competing Hypotheses) |
| **5. Dissemination** | Publish in the right format for the right audience | Reports, feeds, rules | Strategic ≠ technical in format |
| **6. Feedback** | Users evaluate: was it actionable? | Adjust PIR | Closes the loop; without it, CTI drifts from need |

**The Admiralty Code (NATO)** is used to assign reliability along two axes: **source reliability (A–F)** and **information credibility (1–6)**. For example, "B2" = a usually reliable source, information probably true.

| Source reliability | Information credibility |
|---|---|
| A = Completely reliable | 1 = Confirmed |
| B = Usually reliable | 2 = Probably true |
| C = Fairly reliable | 3 = Possibly true |
| D = Not usually reliable | 4 = Doubtful |
| E = Unreliable | 5 = Improbable |
| F = Cannot be judged | 6 = Cannot be judged |

---

## 15.3. Cyber Kill Chain (Lockheed Martin) — 7 steps

A model published by Lockheed Martin (2011) describing targeted attacks (APTs) as a linear chain. The defensive philosophy: **break any single link** and the whole chain breaks → the "intrusion kill chain."

```
 [1]            [2]             [3]          [4]             [5]            [6]            [7]
Recon ──▶ Weaponization ──▶ Delivery ──▶ Exploitation ──▶ Installation ──▶ C2 ──▶ Actions on Objectives
 scout       pair exploit    deliver to    run exploit       install        control   steal / destroy /
 the target  + payload       the victim    code              persistence    channel   move laterally
                                                                            ▲
   ── break ANY single link ──▶ the whole chain breaks ────────────────────┘
```

The diagram shows the model's linear nature: an attack proceeds sequentially from left to right, and defenders only need to break one step to neutralize the entire campaign. This is also its weakness — the model assumes a one-directional flow, making it hard to describe repeated lateral movement or cloud attacks with no malware "delivery" stage.

| # | Stage | Attacker action | Indicators / Blue Team defense |
|---|---|---|---|
| 1 | **Reconnaissance** | Gather emails, technologies, personnel (LinkedIn, whois, scanning) | WAF/IDS logs detecting scans; honeytokens; monitoring registrations of brand-lookalike domains |
| 2 | **Weaponization** | Pair exploit + payload (e.g., a PDF with a macro) | Hard to detect (occurs on the attacker's side); analyze obtained samples |
| 3 | **Delivery** | Send via email/USB/web | Email gateway, attachment sandbox, proxy logs |
| 4 | **Exploitation** | Exploit a vulnerability to run code | EDR exploit detection, EMET/CFG, patching |
| 5 | **Installation** | Install a backdoor/persistence | Monitor autoruns, new services, registry Run keys |
| 6 | **Command & Control (C2)** | Establish a control channel | Beacon analysis, DNS tunneling, JA3 fingerprinting |
| 7 | **Actions on Objectives** | Steal data, destroy, move laterally | DLP, exfil monitoring, mass-encryption detection (ransomware) |

**Limitations:** The Kill Chain assumes linearity and is centered on "external malware"; it is weak at describing insider attacks, repeated lateral movement, or cloud attacks with no "malware delivery." ATT&CK was created to fill this gap (looping, non-linear, observed behavior).

**The Unified Kill Chain (Paul Pols, 2017)** merges the Kill Chain + ATT&CK into 18 stages across 3 clusters (In → Through → Out), addressing the linearity issue. Verify the number of stages against the original if citing precisely.

---

## 15.4. Diamond Model of Intrusion Analysis

Published in 2013 (Caltagirone, Pendergast, Betz). Each **intrusion event** is modeled by 4 interlinked diamond vertices:

```
                 Adversary
                    /\
                   /  \
                  /    \
   Infrastructure ------ Capability
                  \    /
                   \  /
                    \/
                  Victim
```

| Vertex | Meaning | Concrete example |
|---|---|---|
| **Adversary** | The attacker (operator/customer) | The APT29 group |
| **Capability** | Capabilities: malware, exploits, skills (TTPs) | The "WellMess" backdoor, exploit for CVE-XXXX |
| **Infrastructure** | Infrastructure: C2 domains, IPs, sending email | `185.220.101.45`, `update-msft[.]com` |
| **Victim** | The victim: organization, person, asset | Pharmaceutical company X, mail server |

**The strength — Pivoting:** when you hold one vertex, you trace the others. For example: from a **C2 domain** (infrastructure) → query passive DNS for the **shared IP** → find **other domains** pointing to the same IP → infer the group's other **capabilities/adversaries**.

```
Domain evil.com ─(passive DNS)→ 1.2.3.4 ─(reverse)→ bad2.com, bad3.com
       │                                                    │
   (whois)                                              (sandbox)
       ▼                                                    ▼
 reg email X ─────(pivot adversary)──────► same campaign
```

**Extended meta-features**: timestamp, phase (mapped to the Kill Chain), result, direction, methodology, resources. **Social-Political** (the adversary↔victim motive) and **Technology** (capability↔infrastructure) are two additional axes.

The Diamond Model complements ATT&CK: ATT&CK fills in **Capability** (concrete TTPs), while the Diamond Model places it in an investigative relationship.

---

## 15.5. IOC vs IOA

| Criterion | **IOC (Indicator of Compromise)** | **IOA (Indicator of Attack)** |
|---|---|---|
| Nature | Static evidence of what has happened | Behavior/intent in progress |
| Example | Hash `e3b0c44...`, IP, domain, mutex, registry key | "winword.exe spawns powershell.exe which then downloads a file from the Internet" |
| Durability | Low (easily changed) | High (attack logic is hard to change) |
| Detection | Match against a list | Analyze behavior chains (EDR) |

**Example IOA (a cause-and-effect chain) that an EDR detects:**

```
1. outlook.exe  → creates process winword.exe (opens attachment)
2. winword.exe  → spawns cmd.exe /c powershell -enc <base64>
3. powershell   → connects out to 185.x (download)
4. powershell   → writes file to %APPDATA%\svchost.exe
5. new file     → creates registry Run key (persistence)
```

No single indicator above is "absolutely malicious" — it is the **chain** itself that signals an attack. This is the core difference: IOC = "what has been seen"; IOA = "what is being attempted." An ATT&CK technique is essentially a standardized way of expressing an **IOA**.

---

## 15.6. Pyramid of Pain (David Bianco, 2013)

Measures the **degree of pain** that blocking a type of indicator causes the adversary — that is, the cost they must pay to evade.

```
                /\
               /  \   TTPs            ←  TOUGH!   (hardest for the attacker to change)
              /----\
             / Tools \                ←  Challenging
            /--------\
           / Network/ \  Host Artifacts ← Annoying
          /------------\
         /  Domain Names \            ←  Simple
        /----------------\
       /   IP Addresses    \          ←  Easy
      /--------------------\
     /     Hash Values       \        ←  Trivial (change 1 byte → new hash)
    /------------------------\
```

| Tier | Indicator | Adversary cost to evade | Blue Team action |
|---|---|---|---|
| Trivial | Hash (MD5/SHA256) | Change 1 byte → an entirely different hash | Block anyway, but don't expect much |
| Easy | IP address | Rent a new IP (a few minutes) | Block + track infrastructure patterns |
| Simple | Domain | Register a new domain (automated DGA) | DNS sinkhole, DGA detection |
| Annoying | Host/Network artifacts (mutex, unusual User-Agent, registry) | Must modify the malware | Write detections against the artifact |
| Challenging | Tools (Mimikatz, Cobalt Strike) | Must switch tools | YARA against the tool, JA3 |
| Tough | **TTPs** (behaviors: dump LSASS, pass-the-hash) | Must change **how they operate** | ATT&CK detection — invest here |

**Operational lesson:** investing in detection at the apex of the pyramid (TTPs) yields long-term returns; IOCs at the base are cheap but only block the specific known campaign. This is why MITRE ATT&CK (a TTP catalog) is at the center of modern detection engineering.

---

## 15.7. MITRE ATT&CK — architecture and data model

**ATT&CK** = *Adversarial Tactics, Techniques, and Common Knowledge*. It is a **knowledge base** of adversary behaviors **observed in the real world** (curated from public reports). It is not a linear framework like the Kill Chain — it is a **matrix** of behaviors.

### 15.7.1. Conceptual hierarchy

```
Tactic  = the tactical GOAL ("WHY" — what the attacker wants to achieve)
   └─ Technique = the general WAY to achieve the goal ("WHAT")   → ID  Txxxx
        └─ Sub-technique = a specific variant ("HOW") → ID Txxxx.xxx
              └─ Procedure = the CONCRETE implementation by a group/malware
```

| Level | Answers | Identifier | Example |
|---|---|---|---|
| **Tactic** | Why (the goal) | `TAxxxx` | TA0006 Credential Access |
| **Technique** | What (the method) | `Txxxx` | T1003 OS Credential Dumping |
| **Sub-technique** | How (the variant) | `Txxxx.xxx` | T1003.001 LSASS Memory |
| **Procedure** | Who does it, specifically how | (description) | "Mimikatz `sekurlsa::logonpasswords` reads LSASS" |

**ID structure — component breakdown:**

| Component | Format | Meaning | Example |
|---|---|---|---|
| Prefix | 1 character | Object type | `T`=Technique, `TA`=Tactic, `S`=Software, `G`=Group, `M`=Mitigation, `C`=Campaign, `DS`=Data Source |
| Technique number | 4 digits | Technique identifier | `1003` |
| Dot + 3 digits | `.xxx` | Sub-technique | `.001` |

Full example: `T1059.001` = Technique 1059 (Command and Scripting Interpreter), sub-technique 001 (PowerShell).

### 15.7.2. Relationship model (ATT&CK STIX data model)

ATT&CK is published as a **STIX 2.1 bundle** (JSON) on GitHub at `mitre/cti`. The main object types and their mappings:

| ATT&CK concept | STIX 2.1 type | Relationship |
|---|---|---|
| Technique | `attack-pattern` | — |
| Tactic | `x-mitre-tactic` | a technique's `kill_chain_phases` point to the tactic |
| Group | `intrusion-set` | `uses` → attack-pattern / malware |
| Software (malware/tool) | `malware` / `tool` | `uses` → attack-pattern |
| Mitigation | `course-of-action` | `mitigates` → attack-pattern |
| Data Source/Component | `x-mitre-data-source` / `x-mitre-data-component` | `detects` → attack-pattern |
| Relationship | `relationship` | links the objects together |

**An excerpt of an `attack-pattern` (abbreviated, with correct STIX structure):**

```json
{
  "type": "attack-pattern",
  "id": "attack-pattern--0a3ead4e-6d47-4ccb-854c-a6a4f9d96b22",
  "spec_version": "2.1",
  "name": "PowerShell",
  "x_mitre_is_subtechnique": true,
  "kill_chain_phases": [
    { "kill_chain_name": "mitre-attack", "phase_name": "execution" }
  ],
  "external_references": [
    { "source_name": "mitre-attack",
      "external_id": "T1059.001",
      "url": "https://attack.mitre.org/techniques/T1059/001" }
  ],
  "x_mitre_platforms": ["Windows"],
  "x_mitre_data_sources": ["Command: Command Execution",
                           "Process: Process Creation",
                           "Module: Module Load"],
  "x_mitre_detection": "Monitor for execution of powershell.exe with..."
}
```

Important note: the **technique ID is placed in `external_references`** (where `source_name == "mitre-attack"`), NOT in the `id` field (that is the STIX UUID). This is a common point of confusion when writing scripts that parse ATT&CK.

### 15.7.3. Fetching and querying ATT&CK data — runnable examples

Download the Enterprise bundle and count techniques with `jq`:

```bash
# Download the Enterprise ATT&CK STIX bundle
curl -sSL -o enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

# Count attack-patterns that are not deprecated/revoked
jq '[.objects[]
      | select(.type=="attack-pattern")
      | select((.revoked // false)|not)
      | select((.x_mitre_deprecated // false)|not)] | length' \
   enterprise-attack.json

# List technique ID + name for the "credential-access" tactic
jq -r '.objects[]
        | select(.type=="attack-pattern")
        | select(.kill_chain_phases[]?.phase_name=="credential-access")
        | (.external_references[]
            | select(.source_name=="mitre-attack").external_id)
          + "  " + .name' \
   enterprise-attack.json | sort | head
```

Parameter explanation: `select(.type=="attack-pattern")` filters for techniques; `.kill_chain_phases[]?.phase_name` accesses the tactic (the `?` avoids errors when the array is absent); `.external_references[] | select(.source_name=="mitre-attack").external_id` extracts the technique ID.

Querying at the Python layer with the official `mitreattack-python` library:

```python
from mitreattack.stix20 import MitreAttackData

mad = MitreAttackData("enterprise-attack.json")

# Get a technique by ATT&CK ID
t = mad.get_object_by_attack_id("T1003.001", "attack-pattern")
print(t.name)                       # LSASS Memory

# Which groups use this technique?
groups = mad.get_groups_using_technique(t.id)
for g in groups:
    print(g["object"].name)         # e.g.: APT28, ...
```

### 15.7.4. The 14 Enterprise Tactics (Reconnaissance → Impact)

The order of columns in the Enterprise matrix (this is the **logical order**, not a mandatory linear sequence in a real attack):

| # | Tactic | ID | Attacker's goal | Example technique |
|---|---|---|---|---|
| 1 | **Reconnaissance** | TA0043 | Gather information before the attack | T1595 Active Scanning, T1589 Gather Victim Identity Info |
| 2 | **Resource Development** | TA0042 | Prepare infrastructure/tools | T1583 Acquire Infrastructure, T1587 Develop Capabilities |
| 3 | **Initial Access** | TA0001 | Gain a foothold in the network | T1566 Phishing, T1190 Exploit Public-Facing App |
| 4 | **Execution** | TA0002 | Run malicious code | **T1059** Command and Scripting Interpreter |
| 5 | **Persistence** | TA0003 | Maintain the foothold across reboots | T1547 Boot/Logon Autostart, T1053 Scheduled Task |
| 6 | **Privilege Escalation** | TA0004 | Elevate privileges | T1548 Abuse Elevation Control, T1068 Exploit for PrivEsc |
| 7 | **Defense Evasion** | TA0005 | Evade detection | T1070 Indicator Removal, T1027 Obfuscated Files |
| 8 | **Credential Access** | TA0006 | Steal accounts/passwords | **T1110** Brute Force, **T1003** OS Credential Dumping |
| 9 | **Discovery** | TA0007 | Probe the environment | T1083 File/Directory Discovery, T1018 Remote System Discovery |
| 10 | **Lateral Movement** | TA0008 | Move to other hosts | **T1021** Remote Services, T1550 Use Alternate Auth Material |
| 11 | **Collection** | TA0009 | Gather target data | T1005 Data from Local System, T1113 Screen Capture |
| 12 | **Command and Control** | TA0011 | Control remotely | T1071 App Layer Protocol, T1572 Protocol Tunneling |
| 13 | **Exfiltration** | TA0010 | Smuggle data out | **T1041** Exfil Over C2 Channel, T1048 Exfil Over Alt Protocol |
| 14 | **Impact** | TA0040 | Destroy/extort | T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery |

**Why the two tactics "Reconnaissance" and "Resource Development" were added later (PRE-ATT&CK folded in):** initially, ATT&CK Enterprise started from Initial Access. Pre-intrusion activities (recon, acquiring infrastructure) occur outside the victim's network and are therefore hard to gather telemetry on; they were split into PRE-ATT&CK and then (in 2020) reintegrated as the first two columns.

---

## 15.8. Deep dive into key techniques (mechanism + detection signals)

### 15.8.1. T1110 — Brute Force (Credential Access)

**What it is:** trying many credential pairs until one succeeds. Sub-techniques:

| ID | Name | Mechanism |
|---|---|---|
| T1110.001 | Password Guessing | Try many passwords for **one** account |
| T1110.002 | Password Cracking | Crack hashes **offline** (after dumping them) |
| T1110.003 | Password Spraying | Try **one** common password across **many** accounts (evading lockout) |
| T1110.004 | Credential Stuffing | Use user/password pairs leaked from elsewhere |

**Why password spraying is dangerous:** lockout policies typically lock an account after N wrong attempts *on a single account*. Spraying `Summer2024!` across 5000 users one at a time → each user has only 1 failed attempt → no lockout is triggered.

**Real-world example — spraying SMB/RDP with `crackmapexec` (used in an authorized lab):**

```bash
# One password, many users, with --continue-on-success to collect all hits
crackmapexec smb 10.0.0.0/24 -u users.txt -p 'Summer2024!' \
    --continue-on-success
```

**Blue Team signals (Windows Security log):**

| Field | Value to watch for |
|---|---|
| Event ID | `4625` (logon failed) — many, spread across many `TargetUserName` values |
| Event ID | `4771` (Kerberos pre-auth failed), `4768` |
| Failure Reason / Status | `0xC000006A` (wrong password), `0xC0000234` (account locked) |
| Pattern | **Many distinct usernames within the same password attempt window** → spray |

```
Detection logic (pseudo-SIEM):
  COUNT(distinct TargetUserName) WHERE EventID=4625
  GROUP BY SourceIP, time_bucket(5m) > 20  → alert: password spraying
```

### 15.8.2. T1059 — Command and Scripting Interpreter (Execution)

| Sub | Interpreter |
|---|---|
| T1059.001 | PowerShell |
| T1059.003 | Windows Command Shell (cmd) |
| T1059.004 | Unix Shell (bash) |
| T1059.005 | Visual Basic |
| T1059.006 | Python |
| T1059.007 | JavaScript |

**Example of an encoded PowerShell payload — part-by-part explanation:**

```powershell
powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi...
```

| Parameter | Meaning | Why the attacker uses it |
|---|---|---|
| `-nop` | `-NoProfile` | Skip the profile (avoid logging/initialization) |
| `-w hidden` | `-WindowStyle Hidden` | Hide the window |
| `-enc` | `-EncodedCommand` (Base64 of **UTF-16LE**) | Evade string detection, avoid quote escaping |

**Encoding note:** the string after `-enc` is the Base64 of **UTF-16 Little Endian** text, not UTF-8. To decode correctly:

```bash
# The real command: decode the encoded command
echo 'SQBFAFgAIAAoAE4AZQB3AC0ATwBi' | base64 -d | iconv -f UTF-16LE -t UTF-8
# → "IEX (New-Ob..."   (Invoke-Expression — download & run from memory)
```

**Blue Team signals:**
- **Script Block Logging** (Event ID `4104`) records the decoded script content — enable it via the GPO `Administrative Templates → Windows PowerShell → Turn on PowerShell Script Block Logging`.
- Process creation (`4688` / Sysmon `1`) with a `CommandLine` containing `-enc`, `-e`, `FromBase64String`, `IEX`, `DownloadString`.
- Unusual parent–child relationships: `winword.exe → powershell.exe` (an IOA).

### 15.8.3. T1003 — OS Credential Dumping (Credential Access)

| Sub | Credential source | Mechanism |
|---|---|---|
| T1003.001 | **LSASS Memory** | Read the memory of the `lsass.exe` process (containing hashes/Kerberos tickets/sometimes plaintext) |
| T1003.002 | Security Account Manager (SAM) | Read the `SAM` registry hive → local NTLM hashes |
| T1003.003 | NTDS (`ntds.dit`) | The AD database on a Domain Controller → all domain hashes |
| T1003.004 | LSA Secrets | `HKLM\SECURITY\Policy\Secrets` |
| T1003.006 | DCSync | Impersonate a DC, request replication (`DRSGetNCChanges`) to retrieve hashes |

**Why LSASS is a target:** the Local Security Authority Subsystem Service holds credential material to support SSO. Mimikatz's `sekurlsa::logonpasswords` opens a handle to `lsass.exe`, reads the memory structures, and decrypts them.

**Real-world example (lab):**

```
mimikatz # privilege::debug          # enable SeDebugPrivilege
mimikatz # sekurlsa::logonpasswords  # dump credentials from LSASS
```

Dumping with a "living off the land" tool (LOLBIN) is less likely to draw AV attention:

```cmd
:: Create an LSASS minidump using comsvcs.dll (LOLBIN)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID_lsass> C:\temp\l.dmp full
```

**Blue Team signals:**
- Sysmon **Event ID 10** (ProcessAccess) with `TargetImage` = `lsass.exe` and `GrantedAccess` = `0x1010`/`0x1410`/`0x143A` (memory-read rights) from a non-system process.
- **Credential Guard** (VBS) isolates LSASS secrets → neutralizes mimikatz `logonpasswords`.
- **PPL (Protected Process Light)** for LSASS: `RunAsPPL=1` at `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`.

A Sysmon configuration to detect LSASS access:

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="lsass-access" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="image">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

### 15.8.4. T1021 — Remote Services (Lateral Movement)

| Sub | Service | Port | Signal |
|---|---|---|---|
| T1021.001 | RDP | TCP **3389** | Event `4624` Logon Type **10** (RemoteInteractive) |
| T1021.002 | SMB/Windows Admin Shares (C$, ADMIN$) | TCP **445** | Logon Type **3**; access to `\\host\ADMIN$` |
| T1021.004 | SSH | TCP 22 | auth log |
| T1021.006 | WinRM | TCP 5985/5986 | Logon Type 3; `wsmprovhost.exe` |

**Logon Type — lookup table (Windows Event 4624):**

| Type | Meaning | Relevance to lateral movement |
|---|---|---|
| 2 | Interactive (at the machine) | — |
| 3 | Network (SMB, share, WinRM) | **Yes** — pass-the-hash, psexec |
| 10 | RemoteInteractive (RDP) | **Yes** |
| 5 | Service | persistence |

**Real-world example — pass-the-hash over SMB (`impacket`):**

```bash
# Use the NTLM hash instead of the password to execute remotely (T1021.002 + T1550.002)
impacket-psexec -hashes :32ed87bdb5fdc5e9cba88547376818d4 \
    Administrator@10.0.0.5
```

**Signal:** the sequence `4624 (Type 3) → creation of the "PSEXESVC" service (Event 7045) → child process cmd.exe` on the target host.

### 15.8.5. T1041 — Exfiltration Over C2 Channel (Exfiltration)

**What it is:** smuggling data out **over the very C2 channel already in use** (HTTP/HTTPS/DNS) rather than opening a separate channel — to blend in with the traffic.

**Blue Team signals — detecting C2/beacons at the packet level:**
- **Beaconing**: regular periodic connections (e.g., every 60s ± jitter) to the same host. Detected by analyzing the **periodicity** of NetFlow.
- **Anomalous upload/download ratio** (bytes_out >> bytes_in for exfiltration).
- **JA3/JA3S** fingerprints of the TLS client hello matching Cobalt Strike/Metasploit.
- **DNS exfil**: long subdomains, high entropy, many TXT/NULL queries.

```
Beacon pattern (NetFlow viewed over time):
  10:00:00  client → C2  220 bytes
  10:01:00  client → C2  240 bytes   ← period ~60s
  10:02:01  client → C2  225 bytes
  ...  (small deviation = jitter)  → alert: regular beaconing
```

---

## 15.9. The matrices: Enterprise, Mobile, ICS

ATT&CK has multiple "domains" with their own tactics/techniques suited to each environment:

| Matrix | Scope | Sub-platforms | Domain-specific tactics |
|---|---|---|---|
| **Enterprise** | Enterprise IT | Windows, Linux, macOS, **Cloud** (IaaS, SaaS, Office/Google Workspace, Azure AD/Entra ID), Network, Containers | 14 tactics (listed above) |
| **Mobile** | Android, iOS | — | Adds device-related tactics; e.g., Network Effects |
| **ICS** | Industrial control systems/OT | PLC, SCADA, HMI | 12 tactics including **Impair Process Control**, **Inhibit Response Function** |

**Cloud (within Enterprise):** examples of cloud-specific techniques:
- T1078.004 Valid Accounts: **Cloud Accounts**
- T1098 Account Manipulation (adding IAM credentials/roles)
- T1530 Data from Cloud Storage (reading a public S3 bucket)
- T1526 Cloud Service Discovery

**ICS — why it is separate:** in OT, "Impact" can mean **causing physical damage** (opening/closing valves, destroying a turbine — like Stuxnet/Triton). The `Inhibit Response Function` tactic describes disabling safety systems (Safety Instrumented Systems) — a concept with no equivalent in IT. Example techniques: T0816 Device Restart/Shutdown, T0831 Manipulation of Control.

---

## 15.10. ATT&CK Navigator: mapping detections & measuring coverage

The **Navigator** is a web application (runnable offline) that colors the technique cells of the matrix to visualize: detection coverage, the activity of an APT group, and gap analysis. The data is stored in a **layer file (JSON)**.

### 15.10.1. The layer JSON structure — field by field

```json
{
  "name": "SOC Detection Coverage Q2",
  "versions": { "attack": "15", "navigator": "5.0.0", "layer": "4.5" },
  "domain": "enterprise-attack",
  "description": "Current SIEM rule coverage",
  "techniques": [
    {
      "techniqueID": "T1059.001",
      "tactic": "execution",
      "score": 100,
      "color": "",
      "comment": "Covered by Sigma rule win_susp_powershell_enc",
      "enabled": true,
      "metadata": [
        { "name": "rule_id", "value": "SIGMA-0421" }
      ]
    },
    {
      "techniqueID": "T1003.001",
      "tactic": "credential-access",
      "score": 50,
      "comment": "Only a Sysmon EID10 rule, comsvcs not yet covered"
    }
  ],
  "gradient": {
    "colors": ["#ff6666", "#ffe766", "#8ec843"],
    "minValue": 0, "maxValue": 100
  },
  "legendItems": [],
  "showTacticRowBackground": true,
  "tacticRowBackground": "#dddddd",
  "selectTechniquesAcrossTactics": true
}
```

| Field | Type | Meaning |
|---|---|---|
| `domain` | string | `enterprise-attack` / `mobile-attack` / `ics-attack` |
| `versions.attack` | string | The ATT&CK version (e.g., "15") — must match for IDs to be valid |
| `techniques[].techniqueID` | string | Technique/sub-technique ID |
| `techniques[].tactic` | string | tactic shortname (since one technique can belong to multiple tactics → you must specify which cell) |
| `techniques[].score` | number | A score to color the gradient (e.g., % coverage) |
| `gradient` | object | Maps score→color (min→max) |

**Why `tactic` is needed on each technique:** a technique like T1078 Valid Accounts appears in **multiple columns** (Initial Access, Persistence, Privilege Escalation, Defense Evasion). The `tactic` field specifies which cell to color.

### 15.10.2. The real-world coverage measurement process

1. List all existing detection rules (Sigma/SIEM).
2. Map each rule → one or more technique IDs (via the `tags: attack.txxxx` field in Sigma — see 15.11).
3. Generate the layer JSON (via script), with `score=100` for techniques that have a rule and `0` for those that don't.
4. Open Navigator → import the layer → the red areas are your **detection gaps**.
5. Compare against the layers of APTs targeting your industry (MITRE provides ready-made layers per group) → **combine the two layers** with arithmetic to prioritize.

**Script to generate a layer from a Sigma repository (abbreviated):**

```python
import glob, yaml, json, re

techs = {}
for f in glob.glob("rules/**/*.yml", recursive=True):
    doc = yaml.safe_load(open(f, encoding="utf-8"))
    for tag in (doc.get("tags") or []):
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", tag, re.I)
        if m:
            techs[m.group(1).upper()] = techs.get(m.group(1).upper(), 0) + 1

layer = {
  "name": "Sigma coverage", "domain": "enterprise-attack",
  "versions": {"attack": "15", "navigator": "5.0.0", "layer": "4.5"},
  "techniques": [
     {"techniqueID": t, "score": min(100, c*25),
      "comment": f"{c} rule(s)"} for t, c in techs.items()
  ],
  "gradient": {"colors": ["#ff6666","#8ec843"], "minValue":0, "maxValue":100}
}
json.dump(layer, open("coverage.json","w"), indent=2)
```

Navigator supports **layer arithmetic**: for example, create a new layer = `a - b` to find the techniques an APT uses (a) that you do not yet cover (b).

---

## 15.11. Detection Engineering: Sigma, YARA, Suricata mapped to ATT&CK

### 15.11.1. Sigma — SIEM-agnostic rules

**What it is:** a YAML format that describes detections over **logs** in a neutral way, which `sigma-cli` then converts into Splunk/Elastic/Sentinel queries, etc.

**Rule structure — field by field:**

```yaml
title: PowerShell EncodedCommand Suspicious
id: f7d4c3b2-1a2b-4c3d-9e8f-0a1b2c3d4e5f
status: experimental
description: Detects powershell.exe running with the -EncodedCommand parameter
references:
  - https://attack.mitre.org/techniques/T1059/001
author: Blue Team
date: 2026/06/19
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -e '
  condition: selection
falsepositives:
  - Some legitimate administration scripts use -enc
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

| Field | Required | Meaning |
|---|---|---|
| `id` | Yes | A unique UUID (deduplication, referencing) |
| `logsource.category` | Yes | Log type (`process_creation`, `firewall`, `dns_query`, ...) |
| `detection.selection` | Yes | Matching conditions (mapping key→log field) |
| `detection.condition` | Yes | The boolean logic combining the selections |
| `tags` | Recommended | `attack.txxxx` → links to ATT&CK (used to measure coverage) |

**Modifiers** (`|`): `endswith`, `contains`, `startswith`, `re` (regex), `all`. Why modifiers exist: real-world logs contain full paths → you need `endswith` rather than an exact match.

**Compiling to a backend (the real command):**

```bash
pip install sigma-cli pysigma-backend-splunk
sigma convert -t splunk -p splunk_windows powershell_enc.yml
# Output (SPL):
# Image="*\\powershell.exe" (CommandLine="* -enc *" OR CommandLine="* -e *" ...)
```

### 15.11.2. YARA — pattern matching on files/memory

**What it is:** a rule language that matches **strings/bytes/regex** in files or process memory → to classify malware (the "Tools" tier on the Pyramid of Pain).

**Rule structure:**

```yara
import "pe"

rule Mimikatz_Strings
{
    meta:
        author      = "BlueTeam"
        description = "Detects characteristic Mimikatz strings"
        attack      = "T1003.001"
        reference   = "https://attack.mitre.org/software/S0002/"

    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide
        $s2 = "privilege::debug"          ascii wide
        $s3 = { 6D 69 6D 69 6B 61 74 7A }      // "mimikatz" hex
        $re = /gentilkiwi|benjamin delpy/ nocase

    condition:
        uint16(0) == 0x5A4D and          // MZ header (PE file)
        pe.number_of_sections > 1 and
        2 of ($s*) and $re
}
```

| Part | Meaning |
|---|---|
| `strings` | Declares patterns: `ascii`/`wide` (UTF-16), `nocase`, hex `{ .. }`, regex `/../` |
| `condition` | The logic; `uint16(0)==0x5A4D` checks that the first 2 bytes = `MZ` (PE); `2 of ($s*)` = at least 2 strings match |
| `import "pe"` | The PE analysis module (number of sections, imports, entry point) |

**Why `uint16(0)==0x5A4D`:** a PE file begins with the **"MZ"** signature (0x4D 0x5A) — reading the first 2 bytes in little-endian yields `0x5A4D`. This condition rejects non-PE files early → making the rule faster.

**The real scanning command:**

```bash
yara -r -w mimikatz.yar /path/to/scan        # -r recursive, -w suppress warnings
yara mimikatz.yar --scan-list pids.txt        # scan by PID (memory)
```

### 15.11.3. Suricata — IDS/IPS for network detection (C2/exfil)

**What it is:** a signature-based IDS/IPS with protocol analysis. Rules match packets/flows and are tagged with ATT&CK `metadata`.

**Rule structure — part by part:**

```
alert http $HOME_NET any -> $EXTERNAL_NET any ( \
    msg:"ATT&CK T1071.001 Suspicious User-Agent CobaltStrike default"; \
    flow:established,to_server; \
    http.user_agent; content:"Mozilla/5.0 (compatible; MSIE 9.0"; \
    http.uri; content:"/__utm.gif"; \
    classtype:trojan-activity; \
    metadata: attack_target Client_Endpoint, mitre_technique_id T1071; \
    sid:9000001; rev:1; )
```

| Component | Meaning |
|---|---|
| `alert http` | Action (`alert`/`drop`/`reject`) + app-layer protocol |
| `$HOME_NET any -> $EXTERNAL_NET any` | Direction: source IP/port → destination IP/port |
| `flow:established,to_server` | Only match client→server packets within an established connection |
| `http.user_agent` + `content` | Sticky buffer: only search within the User-Agent header |
| `sid` | Signature ID (unique); `rev` is the revision |
| `metadata: mitre_technique_id` | Tags with the ATT&CK ID |

**Why use a sticky buffer (`http.user_agent`):** it confines the `content` search to exactly the field you want, avoiding false positives and improving speed (no scanning of the entire payload).

**Running it for real on a pcap file:**

```bash
suricata -r capture.pcap -S local.rules -l ./out/
# Alert results in ./out/fast.log and eve.json (JSON, with full fields)
cat ./out/fast.log
# 06/19/2026-10:00:01  [**] [1:9000001:1] ATT&CK T1071.001 ... [**] ...
```

---

## 15.12. Intelligence sharing: STIX, TAXII, MISP

### 15.12.1. STIX 2.1 — the language for describing CTI

**STIX (Structured Threat Information eXpression)** uses **JSON**; everything is an **SDO** (STIX Domain Object), an **SRO** (Relationship Object), or an **SCO** (Cyber-observable Object).

**A STIX Indicator (SDO) — field by field:**

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created": "2026-06-19T08:00:00.000Z",
  "modified": "2026-06-19T08:00:00.000Z",
  "name": "Malicious C2 domain",
  "indicator_types": ["malicious-activity"],
  "pattern": "[domain-name:value = 'update-msft.com']",
  "pattern_type": "stix",
  "valid_from": "2026-06-19T00:00:00Z"
}
```

| Field | Size/Format | Meaning |
|---|---|---|
| `type` | string | Object type (`indicator`, `malware`, `threat-actor`, ...) |
| `id` | `type--UUIDv4` | Globally unique identifier |
| `created`/`modified` | ISO 8601 UTC (timestamp) | Versioning |
| `pattern` | STIX Patterning language | An expression matching an observable |
| `pattern_type` | enum | `stix`, `snort`, `yara`, `sigma`, ... |

**The STIX Pattern** is a mini-language: `[file:hashes.'SHA-256' = 'abc...' AND file:size > 1024]`. Operators: `AND OR FOLLOWEDBY`, qualifiers `WITHIN`, `REPEATS`. Why `pattern` is kept separate: it allows expressing compound conditions, not just a single IOC.

### 15.12.2. TAXII 2.1 — the protocol for transporting STIX

**TAXII (Trusted Automated eXchange of Indicator Information)** is an **HTTPS REST** API for exchanging STIX. The model: **Server → API Roots → Collections → Objects**.

| Endpoint | Method | Returns |
|---|---|---|
| `/taxii2/` | GET | Discovery: lists the API roots |
| `/{api-root}/collections/` | GET | The list of collections |
| `/{api-root}/collections/{id}/objects/` | GET | Fetches STIX objects (supports the `?added_after=` filter) |
| `/{api-root}/collections/{id}/objects/` | POST | Pushes an object up |

```bash
# You must set the correct TAXII 2.1 Accept media type
curl -s -H "Accept: application/taxii+json;version=2.1" \
     -u user:pass \
     "https://taxii.example.org/api1/collections/<id>/objects/?added_after=2026-06-18T00:00:00Z"
```

The `Accept: application/taxii+json;version=2.1` header is **mandatory** — the server uses it to negotiate the version; without it, it returns a 406.

### 15.12.3. MISP — a pragmatic sharing platform

**MISP** uses the model **Event → Attribute → Object → Tag/Galaxy**.

| Concept | Meaning |
|---|---|
| **Event** | An event/campaign (containing many attributes) |
| **Attribute** | An IOC: `type` (ip-dst, domain, sha256, url, ...), `value`, `category`, `to_ids` (whether to push it to the IDS) |
| **Object** | A structured group of attributes (e.g., a "file" comprising filename+md5+sha256) |
| **Galaxy / Cluster** | Contextual knowledge; **MITRE ATT&CK is embedded as a Galaxy** → attach techniques to events |
| **Tag** | A label (TLP, ATT&CK, threat-actor) |

**The `to_ids` field is important:** `true` = the IOC is reliable enough to push as an IDS/SIEM rule; `false` = context only, no automatic blocking (avoiding false positives).

**TLP (Traffic Light Protocol)** governs sharing:

| Tag | Shared with |
|---|---|
| `tlp:red` | Direct recipients only |
| `tlp:amber` | The organization + partners who need to know |
| `tlp:amber+strict` | Within the organization only |
| `tlp:green` | The community, not publicly |
| `tlp:clear` (formerly white) | Public |

**A real example — creating an event + adding attributes via the REST API (PyMISP):**

```python
from pymisp import PyMISP, MISPEvent, MISPAttribute

misp = PyMISP("https://misp.local", "<AUTH_KEY>", ssl=False)

ev = MISPEvent()
ev.info = "FIN7 phishing campaign June 2026"
ev.distribution = 1          # 1 = This community only
ev.threat_level_id = 2       # 1=High,2=Medium,3=Low,4=Undefined
ev.analysis = 1              # 0=Initial,1=Ongoing,2=Completed
ev.add_tag("tlp:amber")
ev.add_tag('misp-galaxy:mitre-attack-pattern="OS Credential Dumping - T1003"')

ev.add_attribute("domain", "update-msft.com", to_ids=True,
                 category="Network activity")
ev.add_attribute("sha256",
                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                 to_ids=True, category="Payload delivery")

created = misp.add_event(ev, pythonify=True)
print(created.id)
```

Or plain HTTP:

```bash
curl -s https://misp.local/events/add \
  -H "Authorization: <AUTH_KEY>" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  -d '{"Event":{"info":"Test","distribution":"0","threat_level_id":"2",
        "analysis":"0",
        "Attribute":[{"type":"ip-dst","value":"185.220.101.45","to_ids":true}]}}'
```

---

## 15.13. Malware classification

| Type | Propagation mechanism/definition | Needs a host? | Self-replicates? | Related ATT&CK |
|---|---|---|---|---|
| **Virus** | Inserts code into another file/program; runs when the host runs | Yes | Yes (via the host) | T1204 User Execution |
| **Worm** | Spreads itself over the network/via vulnerabilities, with no user action | No | Yes (automatically) | T1210 Exploit Remote Services |
| **Trojan** | Masquerades as legitimate software, opens a backdoor | — | No | T1036 Masquerading |
| **Ransomware** | Encrypts data, demands a ransom | — | Possibly | **T1486** Data Encrypted for Impact |
| **Rootkit** | Hides its presence (kernel/bootkit), hooks APIs | — | No | T1014 Rootkit |
| **RAT** | Remote Access Trojan: comprehensive remote control | — | No | T1219 Remote Access Software |
| **Botnet** | A network of infected machines under centralized control (DDoS/spam) | — | Yes | T1583.005 Botnet |
| **Fileless** | Lives in memory/registry/WMI, touching the disk little or not at all | No | — | T1059, T1047 WMI, T1620 Reflective Loading |

**Why fileless is hard to detect:** there is no file for AV to scan by hash/signature → you must detect at the **behavioral** level (IOA): PowerShell loading code into RAM, WMI event subscriptions for persistence, the registry containing a base64 payload. This directly illustrates the Pyramid of Pain — forcing the Blue Team up to the TTP tier.

---

## 15.14. Basic malware analysis

### 15.14.1. Static Analysis (without running the sample)

**Strings** — extract ASCII/Unicode strings to find traces (URLs, IPs, commands, mutexes):

```bash
strings -n 8 sample.exe | grep -Ei 'http|\.exe|powershell|HKEY|cmd'
strings -e l sample.exe          # -e l = little-endian 16-bit (Unicode/UTF-16)
```

`-n 8` only takes strings ≥ 8 characters (reducing noise); `-e l` is necessary because Windows often uses UTF-16LE strings that `strings` skips by default.

**PE Header — the Windows executable file structure (down to the byte):**

A PE file is laid out as follows (offsets from the start of the file):

```
Offset 0x00  ┌────────────────────────┐
             │ DOS Header (IMAGE_DOS_HEADER, 64 bytes) │
             │   e_magic  = "MZ" (0x4D5A)              │  ← 2 bytes, offset 0x00
             │   e_lfanew = offset to the PE header     │  ← 4 bytes, offset 0x3C
0x3C ───────►│                                          │
             ├────────────────────────┤
e_lfanew ──► │ PE Signature "PE\0\0" (0x50450000)       │  ← 4 bytes
             ├────────────────────────┤
             │ COFF File Header (IMAGE_FILE_HEADER, 20B)│
             │   Machine          (2B)  0x8664=x64      │
             │   NumberOfSections (2B)                  │
             │   TimeDateStamp    (4B)  epoch compile   │
             │   ... SizeOfOptionalHeader (2B)          │
             │   Characteristics  (2B)                  │
             ├────────────────────────┤
             │ Optional Header (PE32: 224B / PE32+:240B)│
             │   Magic (2B) 0x10B=PE32, 0x20B=PE32+     │
             │   AddressOfEntryPoint (4B) RVA           │
             │   ImageBase, SectionAlignment, ...       │
             │   Subsystem (2B) 2=GUI,3=CUI             │
             │   DataDirectory[16] (Import, Export...)  │
             ├────────────────────────┤
             │ Section Table (each entry 40 bytes)      │
             │   .text  .data  .rdata  .rsrc            │
             └────────────────────────┘
```

| Field | Offset | Size | Meaning | Example value |
|---|---|---|---|---|
| `e_magic` | 0x00 | 2 B | DOS signature | `4D 5A` ("MZ") |
| `e_lfanew` | 0x3C | 4 B | Offset to the PE header | `0x000000E8` |
| PE signature | e_lfanew | 4 B | `50 45 00 00` ("PE\0\0") | — |
| `Machine` | +0x04 | 2 B | Architecture | `0x8664` (x64), `0x014C` (x86) |
| `NumberOfSections` | +0x06 | 2 B | Number of sections | `5` |
| `TimeDateStamp` | +0x08 | 4 B | Compile time (epoch) | `0x5F2A...` |
| `Magic` (Opt.) | +0x18 | 2 B | PE32 vs PE32+ | `0x010B` / `0x020B` |
| `AddressOfEntryPoint` | Opt+0x10 | 4 B | RVA of the code entry point | `0x1500` |
| `Subsystem` | Opt | 2 B | GUI/Console | `2`=GUI, `3`=Console |

**Why reading the PE header has forensic value:**
- A `TimeDateStamp` that is absurdly off (far in the future/past) → may have been forged (anti-forensics).
- A section with **RawSize ≈ 0 but a large VirtualSize** + high entropy → a sign of being **packed** (UPX, themida).
- **Sparse imports** (only `LoadLibrary`+`GetProcAddress`) → dynamic import resolution → packed/obfuscated.

```bash
# Analyze a PE with pefile (Python)
python3 - <<'PY'
import pefile, math
pe = pefile.PE("sample.exe")
print("Machine:", hex(pe.FILE_HEADER.Machine))
print("Compile time:", pe.FILE_HEADER.TimeDateStamp)
print("EntryPoint RVA:", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
for s in pe.sections:
    data = s.get_data()
    ent = 0
    if data:
        from collections import Counter
        for c in Counter(data).values():
            p = c/len(data); ent -= p*math.log2(p)
    print(s.Name.decode(errors='replace').strip('\x00'),
          "vsize=%#x rawsize=%#x entropy=%.2f" %
          (s.Misc_VirtualSize, s.SizeOfRawData, ent))
PY
```

Entropy > ~7.0 on an executable section suggests compressed/encrypted data (packed). This is an important heuristic in triage.

**Hashing & lookup:**

```bash
sha256sum sample.exe                # hash to look up in VirusTotal/MISP
# Import hash (imphash) – characteristic of the import table, groups variants from the same builder
python3 -c "import pefile;print(pefile.PE('sample.exe').get_imphash())"
```

The `imphash` (import hash) is more durable than a file hash because samples from the same "builder" usually have the same import order → grouping variants together (the Tools tier on the Pyramid of Pain).

### 15.14.2. Dynamic Analysis (running in a sandbox)

**What it is:** running the sample in an isolated environment (a VM snapshot, with no route to the real Internet or using INetSim to simulate it), capturing its behavior: processes created, files written, registry changes, network connections, API calls.

**Safe setup — why:**
- The VM is **not connected to the production network**; a snapshot allows reverting.
- **INetSim/FakeNet** simulates DNS/HTTP so the sample "believes" it is online → revealing the C2 without actually connecting out.
- Beware of sandbox-aware malware: many samples check for `VMware`, the CPU count, `sbiedll.dll`, or sleep for a long time to evade.

**Tools & real commands:**

```bash
# 1. Simulate network services (Linux analysis)
inetsim                          # logs the DNS queries and HTTP requests the sample sends

# 2. Trace system calls (Linux ELF)
strace -f -e trace=network,file ./sample 2>strace.log

# 3. Procmon (Windows) — filter:
#    Operation = Process Create / RegSetValue / WriteFile
#    → export to CSV to map to ATT&CK
```

**Sample output (Procmon) → mapped to ATT&CK:**

```
winword.exe → Process Create powershell.exe -enc ...   → T1059.001
powershell  → WriteFile %APPDATA%\Microsoft\svchost.exe → T1105 Ingress Tool Transfer
powershell  → RegSetValue HKCU\...\Run\Updater          → T1547.001 Registry Run Key
svchost.exe → TCP Connect 185.220.101.45:443            → T1071.001 / T1041
```

**Cuckoo/CAPE Sandbox reports** automate this: they run the sample, hook the APIs, and return JSON containing a list of behaviors + **already mapped to ATT&CK techniques** (`ttps` in the report). CAPE also dumps the unpacked payload from memory — useful because static analysis on a packed sample is useless.

---

## 15.15. Synthesis: attack lifecycle ↔ detection signals

A quick-reference table linking **stage → technique → telemetry → detection**:

| Stage | Representative technique | Telemetry source | Signal / Rule |
|---|---|---|---|
| Initial Access | T1566.001 Spearphishing Attachment | Email gateway, EDR | Office spawns a script (IOA) |
| Execution | T1059.001 PowerShell | EID 4104, Sysmon 1 | `-enc`, `IEX`, `DownloadString` |
| Persistence | T1547.001 Run Key | Sysmon 13 (RegSet) | Writing to `...\CurrentVersion\Run` |
| Priv Esc | T1068 Exploit for PrivEsc | EDR, kernel log | Token manipulation, crash dump |
| Defense Evasion | T1070.001 Clear Windows Event Logs | EID 1102 | The audit log is cleared |
| Credential Access | T1003.001 LSASS | Sysmon 10 | GrantedAccess `0x1010` to lsass |
| Discovery | T1018 Remote System Discovery | Sysmon 1 | `net view`, `nltest /dclist` |
| Lateral Movement | T1021.002 SMB/Admin Shares | EID 4624 Type 3, 7045 | PSEXESVC service created |
| Collection | T1560 Archive Collected Data | Sysmon 11 | `rar.exe a -hp`, 7zip |
| C2 | T1071.001 Web Protocols | Proxy, NetFlow, Zeek | Beaconing, JA3 match |
| Exfiltration | T1041 Exfil over C2 | NetFlow | bytes_out >> bytes_in |
| Impact | T1486 Data Encrypted | Sysmon 11, EDR | Mass file-extension renaming, deletion of shadow copies (T1490 `vssadmin delete shadows`) |

**Detection engineering principles:**
1. Map every rule → an ATT&CK ID (for measuring coverage in Navigator).
2. Prioritize TTPs (the apex of the Pyramid) over IOCs (the base).
3. A single technique should have **multiple rules across multiple data sources** (defense-in-depth detection) — e.g., LSASS dumping detected via both Sysmon 10 and EDR memory scanning.
4. Track **false positives** via Sigma's `falsepositives` field; an untuned rule will be ignored (alert fatigue).
5. Close the loop: use feedback from real IR (Diamond Model pivots) to create new PIRs → updating collection (the CTI lifecycle).

---

## 15.16. Security & operational notes — summary

- **IOCs are perishable**: automatically expire technical IOCs (via `valid_from`/TTL in STIX, or MISP's decay model) to avoid bloating the block list and causing FPs.
- **`to_ids` must be reviewed by a human**: do not auto-block every IOC received from a feed — a legitimate domain mistakenly tagged can cause an outage.
- **Strict TLP**: leaking `tlp:red` intelligence can expose the source/victim; enforce TLP at both the human and the sharing-system level.
- **ATT&CK is not a compliance checklist**: "100% coverage" is an illusion — techniques are always expanding and procedures are infinite; coverage is only a prioritization tool, not a goal.
- **Malware analysis = a risky activity**: always isolate the network, use a throwaway VM, and never analyze a live sample on a machine connected to the production network.
- **Threat-informed defense**: select the APT groups actually targeting your industry (via reports/ISACs), take their ATT&CK layers, and prioritize detection accordingly rather than trying to cover the entire matrix.

---

### References to verify when citing precisely
- The number of tactics/techniques and specific IDs change with each ATT&CK version — always cross-check `attack.mitre.org` and the `versions.attack` value in your layer.
- The number of Unified Kill Chain stages (18) and the details of the STIX media types should be re-checked against the original specification (OASIS STIX/TAXII 2.1) before use in formal documentation.
