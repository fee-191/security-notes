# Chapter 8 — SIEM & Centralized Log Management

## Overview

This chapter explains how an organization collects and analyzes logs to detect attacks and incidents across its entire infrastructure. There are two focal points: **SIEM** (the software layer that aggregates, normalizes, correlates, and stores security logs) and **Wazuh** (an open-source SIEM/HIDS platform that implements this full pipeline). Visibility is a prerequisite for defense: if you do not collect logs of password probing or file changes on a server, you cannot detect or respond. The sections below define each core concept and the problem it solves before diving into technical detail.

### SIEM

**Definition.** A SIEM is the software layer that centralizes logs from many sources (servers, firewalls, applications, network devices), synchronizes time, normalizes them into a common data model, and performs correlation analysis to generate alerts.

**Problem solved.** The traces of an attack are scattered across many systems and many log files; a volume of millions of lines per day exceeds what can be read by hand. A SIEM gathers logs in one place, reduces them to a common "language," and automatically stitches the fragments of evidence together to raise an alarm when suspicious behavior occurs.

### Data pipeline (log-processing pipeline)

**Definition.** This is the fixed sequence of processing steps that every event passes through: collect → parse → normalize → enrich → correlate → alert → store.

**Problem solved.** Raw logs come in a different format from every source and cannot be compared directly. The pipeline turns heterogeneous data into a structured, uniform form. The **normalize** step is especially important: it maps the "source IP address" from many pieces of software (each of which uses a different field name) to one common field name, so that a single rule applies to every source.

### Distinguishing AV / EDR / SIEM / SOAR / XDR / NDR

The different layers of defensive tooling differ in their scope of visibility and the data they see:

- **AV (Antivirus):** protects a single endpoint, blocking known malware by signature/hash.
- **EDR (Endpoint Detection & Response):** a single endpoint, with deep behavioral monitoring (process tree, syscalls, registry, host network).
- **NDR (Network Detection & Response):** monitors network traffic (packets, flows, metadata) to detect C2, exfiltration, and lateral movement.
- **SIEM:** observes the full picture from all normalized log sources; correlation, storage, investigation, compliance.
- **SOAR (Security Orchestration, Automation & Response):** automates response according to playbooks (block, open a ticket, enrich).
- **XDR (Extended Detection & Response):** a unified bundle of multiple layers (EDR/NDR/email/cloud) from a single vendor, already correlated.

**Problem solved.** Each layer sees a different dataset; choosing the wrong one leaves a permanent blind spot. Wazuh simultaneously plays the role of a lightweight EDR-style agent and a SIEM.

### Wazuh

**Definition.** Wazuh is an open-source security platform that acts as a SIEM together with many endpoint-monitoring features. It has four components:

- **Agent:** software on each endpoint that collects logs/telemetry and sends them to the manager.
- **Manager:** the core that receives, decodes, applies rules, and generates alerts.
- **Indexer:** the store and search engine for alerts (OpenSearch).
- **Dashboard:** the web interface for visualization and administration.

**Problem solved.** It provides a complete SIEM without dependence on expensive commercial software. Understanding the four components helps you picture the path of data from the endpoint to the operator's screen.

### Enrollment — the agent registers with the manager

**Definition.** Before sending logs, the agent performs **enrollment** (registration) to obtain a secret key (a pre-shared key). The agent then uses this key to encrypt and continuously transmit logs over a dedicated data channel.

**Problem solved.** Only valid hosts can send data, which prevents log spoofing and eavesdropping. Separating the enrollment port (which issues keys) from the data-transmission port helps shrink the attack surface.

### ossec.conf — the configuration file

**Definition.** An XML configuration file that declares Wazuh's behavior: which log sources to read, where to send them, and what alert thresholds to use; it applies to both the manager and the agent.

**Problem solved.** Each system has different log sources and sensitivity levels that must be declared explicitly. A syntax error in this file can leave the system unable to monitor, so the syntax must be checked before applying it.

### Decoder

**Definition.** A decoder is a rule that tells Wazuh how to extract meaningful fields (user, source IP, action) from a raw log line. The decoder prepares the data; it does not generate alerts.

**Problem solved.** Detection logic cannot operate on free text; the text must be broken into clear fields (for example, `srcip = 203.0.113.5`) so they can be compared, counted, and alerted on.

### Rule (detection rule)

**Definition.** A rule decides which event becomes an alert and at what severity (level), based on the decoded fields. For example: an IP that fails to log in 8 times within 120 seconds is classified as brute-force at a high level.

**Problem solved.** The decoder only extracts data; the rule is the decision layer that distinguishes normal behavior from dangerous behavior — the heart of detection capability.

### FIM / Syscheck (file integrity monitoring)

**Definition.** FIM (File Integrity Monitoring) tracks the creation, modification, and deletion of important files and directories by storing content hashes and checking for changes periodically or in real time.

**Problem solved.** Many attacks leave a trace through dropping unfamiliar files (a webshell) or modifying configuration files. FIM detects exactly this kind of change, even when an attacker forges the mtime — because it compares the content hash, not just metadata.

### Active Response (automated response)

**Definition.** When a rule matches, Wazuh can automatically execute an action (script) — for example, blocking the attacking IP with a firewall and then automatically removing the block after a timeout.

**Problem solved.** Responding within seconds exceeds the capacity of humans on duty 24/7; automation blocks attacks instantly. In exchange, it requires tight control to avoid mistakenly blocking legitimate infrastructure.

### Vulnerability Detection (vulnerability detection)

**Definition.** This feature cross-references the list of installed packages (with versions) against a catalog of known vulnerabilities (a CVE feed) to determine which hosts run a vulnerable version.

**Problem solved.** Outdated software often carries published, actively exploited vulnerabilities; detecting them early to patch is a low-cost, high-impact defensive measure.

### SCA (Security Configuration Assessment)

**Definition.** SCA checks system configuration against a secure baseline (for example, the CIS Benchmark) — such as prohibiting direct login with the highest-privilege account — and reports pass/fail for each check.

**Problem solved.** Many breaches stem from loose configuration rather than software bugs. SCA detects these configuration weaknesses and helps harden them.

### MITRE ATT&CK & Detection Engineering

**Definition.** **MITRE ATT&CK** is a framework that standardizes attacker techniques, each technique having an identifier (`T####`), helping describe attacks in a common language. **Detection Engineering** is the work of writing and tuning rules to balance misses (false negatives) against false alarms (false positives).

**Problem solved.** Tagging alerts with a MITRE code helps you quickly recognize the type of attack and measure detection coverage. Balancing FP/FN is the core skill that makes a SIEM useful instead of becoming a source of noisy alerts that get ignored.

> An in-depth reference for Blue Team / AppSec / DevSecOps engineers. Each section proceeds from **WHAT IT IS → INTERNAL MECHANISM (down to the bit/byte/step/parameter) → REAL-WORLD EXAMPLE → SECURITY NOTES**.

---

## 8.1. What a SIEM is and why it exists

### 8.1.1. Definition and the root problem

**SIEM (Security Information and Event Management)** is the software layer that collects, normalizes, correlates, and stores security events from the entire infrastructure, in order to detect and investigate threats in near real-time and to support compliance.

This term unifies two older product lines:

| Term | Stands for | Original focus |
|-----------|--------------|---------------|
| SIM | Security Information Management | Long-term log storage, compliance reporting, forensics |
| SEM | Security Event Management | Real-time correlation, alerting, dashboards |
| SIEM | Unification of SIM + SEM | Both: real-time correlation **and** long-term retention |

**WHY it exists:** In a real system, an attack does not leave its traces in one place. A single SSH brute-force login leaves:
- A log in `/var/log/auth.log` on the Linux host;
- A Netflow/connection log on the firewall;
- A log from the EDR recording an abnormal process after entry is gained;
- A log from Active Directory if the attacker performs lateral movement.

No single human sits and reads, in parallel, millions of log lines per day from thousands of sources. SIEM solves the problem of **gathering into one place + one common data model + automatic correlation**.

### 8.1.2. Units of data: Event, Log, Alert

You must distinguish precisely between three concepts that are often confused:

| Concept | Definition | Example |
|-----------|------------|-------|
| **Log line / raw event** | A line of text (or a binary record) produced by a source, in a source-specific format | `Jun 19 10:22:41 web01 sshd[2931]: Failed password for invalid user admin from 203.0.113.5 port 51244 ssh2` |
| **Normalized event** | A record that has been parsed into fields with standard names (structured) | `{ "timestamp": ..., "program": "sshd", "srcip": "203.0.113.5", "srcuser": "admin", "action": "auth_failed" }` |
| **Alert** | The result of a rule matching one or more events, together with a severity | `Rule 5710 (level 5): sshd: Attempt to login using a non-existent user` |

---

## 8.2. SIEM architecture & data pipeline

Every SIEM (Splunk, Elastic SIEM, QRadar, Wazuh, Sentinel, etc.) executes the same logical pipeline. Understanding this pipeline is the key to understanding Wazuh in the sections that follow.

```
            ┌─────────┐   ┌────────┐   ┌───────────┐   ┌────────┐   ┌──────────┐   ┌───────┐   ┌────────┐
  Sources──▶│ COLLECT │──▶│ PARSE  │──▶│ NORMALIZE │──▶│ ENRICH │──▶│CORRELATE │──▶│ ALERT │──▶│ STORE  │
            └─────────┘   └────────┘   └───────────┘   └────────┘   └──────────┘   └───────┘   └────────┘
             (ship)        (decode)     (field map)     (geoip,      (rules,         (notify)   (index/
                                                         threat       stateful)                  retain)
                                                         intel)
```

### 8.2.1. COLLECT

**WHAT IT IS:** Bringing an event from the source to the collector. Two models:

| Model | Mechanism | Example protocol/port |
|---------|--------|----------------------|
| **Push (agent-based)** | An agent installed on the host reads files/events and pushes them to the manager | Wazuh agent → manager (UDP/TCP 1514); Filebeat → Logstash (5044) |
| **Pull / agentless** | The server pulls logs from the source, or receives them via syslog | Syslog UDP/TCP 514; WMI; SNMP; API polling (cloud) |

**INTERNAL MECHANISM — Syslog (RFC 5424) at the byte level.** Because syslog is the most common collection medium, let us dissect one record:

```
<34>1 2026-06-19T10:22:41.003Z web01 sshd 2931 ID47 - Failed password...
 └┬┘│ └──────────┬──────────┘ └─┬─┘ └─┬┘ └┬┘ └┬┘ │ └──────┬──────┘
  │ │            │              │     │    │    │  │        │
  │ │            │              │     │    │    │  │        └─ MSG (free-form UTF-8, may contain a BOM)
  │ │            │              │     │    │    │  └─ STRUCTURED-DATA ("-" = none)
  │ │            │              │     │    │    └─ MSGID
  │ │            │              │     │    └─ PROCID (PID)
  │ │            │              │     └─ APP-NAME
  │ │            │              └─ HOSTNAME
  │ │            └─ TIMESTAMP (ISO 8601 / RFC 3339)
  │ └─ VERSION (always = 1 in RFC 5424)
  └─ PRI = "<34>"  (Priority value)
```

**The PRI field decoded down to the bit:** PRI is a decimal number inside the `< >` brackets, computed as:

```
PRI = Facility × 8 + Severity
```

| Component | Bits | Value range | Meaning | Example with PRI=34 |
|-----------|-----|-------------|---------|------------------|
| Facility | high 5 bits (PRI >> 3) | 0–23 | Source generating the log | 34 >> 3 = **4** → "security/authorization (auth)" |
| Severity | low 3 bits (PRI & 7) | 0–7 | Severity level | 34 & 7 = **2** → "Critical" |

Severity table (3 bits, RFC 5424 §6.2.1):

| Code | Name | Meaning |
|----|-----|---------|
| 0 | Emergency | System is unusable |
| 1 | Alert | Must be handled immediately |
| 2 | Critical | Critical condition |
| 3 | Error | Error |
| 4 | Warning | Warning |
| 5 | Notice | Normal but noteworthy |
| 6 | Informational | Information |
| 7 | Debug | Debugging |

> **Note:** RFC 3164 (the old BSD syslog) limits the message to ~1024 bytes and its timestamp has no year/timezone, which easily causes time skew during correlation. RFC 5424 allows longer messages (limited by the transport) and a full timestamp with timezone — this is WHY you should prefer 5424.

**SECURITY NOTES when collecting:**
- Syslog UDP 514 does **not** authenticate, does **not** encrypt, and does **not** guarantee delivery → an attacker can spoof logs (log injection) or cause congestion to drop logs. Prefer TLS (RFC 5425, syslog over TLS, port 6514) or an encrypted agent channel.
- Lost logs = blindness. You must measure latency and packet drop rate.

### 8.2.2. PARSE (extract / decode)

**WHAT IT IS:** Turning the free-text string (MSG) into discrete fields. This is where regex/grok/decoders operate.

Example raw SSH MSG:
```
Failed password for invalid user admin from 203.0.113.5 port 51244 ssh2
```
After parsing:
```
action  = "Failed password"
srcuser = "admin"
srcip   = "203.0.113.5"
srcport = 51244
```

### 8.2.3. NORMALIZE

**WHAT IT IS:** Mapping the freshly parsed fields to **a common schema** so that events from many different sources can be compared/correlated. This is the point that distinguishes a real SIEM from a log-grepping tool.

WHY it is needed: source A calls the source IP `src`, source B calls it `client_ip`, source C calls it `SourceAddress`. Without normalization you cannot write a single rule that "counts login failures by source IP" applicable to all three.

Example fields before/after normalization (per ECS — the Elastic Common Schema, or Wazuh's standard fields):

| Source | Original field | Normalized field (Wazuh) | Normalized field (ECS) |
|-------|-----------|--------------------------|------------------------|
| sshd | `from 203.0.113.5` | `srcip` | `source.ip` |
| Windows 4625 | `Source Network Address` | `srcip` / `data.win.eventdata.ipAddress` | `source.ip` |
| nginx | `$remote_addr` | `srcip` | `source.ip` |

### 8.2.4. ENRICH

**WHAT IT IS:** Adding context not present in the original log:
- **GeoIP:** `203.0.113.5` → country=US, ASN=AS64500. (Wazuh supports GeoIP through dashboard/indexer integration with the GeoLite2 mmdb.)
- **Threat intel:** cross-referencing IPs/hashes against IoC feeds (for example AlienVault OTX, AbuseIPDB) → flagging as `malicious`.
- **Asset context:** host `web01` belongs to the "production-dmz" group, owner = team-web.
- **Vulnerability context:** this host has an open CVE-2024-XXXX.

### 8.2.5. CORRELATE

**WHAT IT IS:** The detection logic. Two kinds:

| Kind | Description | Example |
|------|-------|-------|
| **Stateless** | 1 event matches 1 pattern → alert | "There is a `Failed password` line" → alert level 5 |
| **Stateful** | Counting/grouping many events over time/key → alert | "≥ 8 `Failed password` from the same `srcip` within 120 seconds" → brute-force level 10 |

Stateful correlation is a **state machine** that counts events by key within a sliding window. Wazuh implements it with the `frequency` + `timeframe` parameter pair (see 8.7).

### 8.2.6. ALERT & STORE

- **ALERT:** generate a notification (send an email, webhook, Slack, trigger SOAR/active response).
- **STORE:** write to an index for querying (Elasticsearch/OpenSearch/Wazuh indexer). There is a retention policy (for example hot for 7 days, warm for 30 days, cold/frozen for 1-year compliance).

---

## 8.3. Classifying defensive tools: AV / EDR / SIEM / SOAR / XDR / NDR

WHY you must distinguish them: these categories are often blended by marketing, but their position in the architecture and the data they see are different.

| Tool | Scope of visibility | Unit of data | Primary action | Examples |
|---------|------------------|----------------|-----------------|-------|
| **AV (Antivirus)** | 1 endpoint | File, signature, hash | Scan/block known malware | ClamAV, Defender (AV mode) |
| **EDR (Endpoint Detection & Response)** | 1 endpoint, behavior | Process tree, syscalls, registry, host network | Detect behavior, isolate host, kill process | CrowdStrike Falcon, Defender for Endpoint, Wazuh (partial) |
| **NDR (Network Detection & Response)** | Network traffic | Packets, flows, metadata (JA3, DNS, TLS SNI) | Detect C2/exfil/lateral movement | Zeek, Suricata, Corelight |
| **SIEM** | The whole infrastructure (logs) | Normalized events from all sources | Correlation, storage, investigation, compliance | Wazuh, Splunk, Elastic SIEM |
| **SOAR (Orchestration, Automation & Response)** | The response process | Case/playbook | Automate response (block, ticket, enrich) | Shuffle, TheHive+Cortex, Splunk SOAR |
| **XDR (Extended Detection & Response)** | EDR + NDR + email + cloud, unified | Pre-correlated multi-layer events from a single vendor | Cross-layer detection | A single vendor's XDR suite |

**Core distinctions:**
- **EDR vs SIEM:** EDR is the specialist for a single endpoint (deep into process telemetry); SIEM is the aggregator of the full picture (broad view, shallower per-source). Wazuh is interesting because it is **both a lightweight EDR-style agent and a SIEM** (the agent collects endpoint telemetry + the manager does correlation).
- **SIEM vs SOAR:** the SIEM *detects*; SOAR *responds according to a playbook*. Wazuh has "Active Response" — a kind of integrated mini-SOAR.
- **XDR vs SIEM:** XDR is usually locked into a single vendor's ecosystem and pre-correlated; a SIEM is open, ingests any source, but you build the correlation yourself.

---

## 8.4. WAZUH — Overview and architecture

### 8.4.1. What Wazuh is

**Wazuh** is an open-source security platform (historically forked from OSSEC HIDS, extended with an indexer/dashboard from the Elastic/OpenSearch family). It provides, at the same time:

- HIDS (Host Intrusion Detection): log analysis, FIM, rootcheck;
- Vulnerability management (Vulnerability Detection);
- SCA (Security Configuration Assessment — configuration checks against CIS);
- Active Response (automated response);
- MITRE ATT&CK framework integration;
- The SIEM role via the indexer + dashboard.

> Version note: the details of ports, service names, and the structure of some modules change by major version (3.x → 4.x). This document describes the **4.x** line. The important numbers (ports 1514/1515/55000/1516/9200/443) should be re-checked against the specific version you deploy.

### 8.4.2. The four main components

```
        ┌──────────────────────────────────────────────────────────────┐
        │                         WAZUH SERVER                          │
        │                                                               │
  Agent │   ┌───────────────┐         ┌────────────────────────────┐    │
  (host)│   │  wazuh-manager │         │   FILTER / FORWARD          │    │
  ──────┼──▶│  - analysisd   │────────▶│   Filebeat ──▶ Indexer      │    │
 1514/  │   │  - remoted     │ alerts  │                             │    │
 1515   │   │  - logcollector│ .json   └────────────┬───────────────┘    │
        │   │  - syscheckd   │                      │                    │
        │   │  - active-resp │                      ▼                    │
        │   └───────────────┘            ┌────────────────────┐          │
        └────────────────────────────────│   WAZUH INDEXER    │──────────┘
                                          │  (OpenSearch)      │
                                          └─────────┬──────────┘
                                                    │ 9200 (REST)
                                          ┌─────────▼──────────┐
                                          │  WAZUH DASHBOARD   │ 443
                                          │  (OpenSearch Dash) │
                                          └────────────────────┘
```

| Component | Role | Main daemon/process | Typical ports |
|-----------|---------|----------------------|----------------|
| **Wazuh agent** | Installed on the endpoint; collects logs, FIM, SCA, sends to the manager | `wazuh-agentd`, `wazuh-logcollector`, `wazuh-syscheckd`, `wazuh-execd` | (client) |
| **Wazuh manager (server)** | Receives, decodes, applies rules, alerts, manages agents | `wazuh-remoted` (receive), `wazuh-analysisd` (analyze), `wazuh-authd` (enroll), `wazuh-modulesd` (vuln/SCA) | 1514 (data), 1515 (enroll), 1516 (cluster), 55000 (REST API) |
| **Wazuh indexer** | Stores + searches alerts (OpenSearch) | `wazuh-indexer` | 9200 (REST), 9300 (node-to-node transport) |
| **Wazuh dashboard** | Web interface, visualization, management | `wazuh-dashboard` | 443/5601 |

### 8.4.3. The daemons inside the manager and the internal data flow

```
agent ─(1514)─▶ wazuh-remoted ─▶ (queue: /var/ossec/queue/sockets/queue)
                                        │
                                        ▼
                                 wazuh-analysisd
                                  ├─ PreDecoding (extract timestamp/host/program)
                                  ├─ Decoding    (decoders/*.xml → extract fields)
                                  ├─ Rule matching (rules/*.xml → assign level/id)
                                  └─ if matched ⇒ write alert
                                        │
                       ┌────────────────┼─────────────────┐
                       ▼                ▼                 ▼
            /var/ossec/logs/        active-response   archives (if enabled)
            alerts/alerts.json      (wazuh-execd)     alerts/archives.json
                       │
                       ▼
                   Filebeat ──▶ Wazuh indexer ──▶ Dashboard
```

**The path of an event (decapsulation logic):**
1. The agent reads a log line → packages it with metadata (agent id, location) → encrypts it → sends it over **1514**.
2. `wazuh-remoted` decrypts it and places the event in a local socket queue.
3. `wazuh-analysisd` takes the event and runs **PreDecoding → Decoding → Rule matching**.
4. If a rule matches with a level ≥ the threshold (`<log_alert_level>`, default 3), the event is written to `alerts.json`.
5. If the rule has an associated `<active-response>`, `wazuh-execd` runs the response script on the agent/manager.
6. `Filebeat` reads `alerts.json` and pushes it into the **indexer (9200)**.
7. The `Dashboard` queries the indexer to display it.

---

## 8.5. The agent → manager flow: enrollment and data transmission (byte/port level)

### 8.5.1. The two ports and WHY they are separated

| Port | Protocol | Listening daemon | Purpose |
|------|-----------|-------------|----------|
| **1515/TCP** | TLS | `wazuh-authd` | **Enrollment** (registering the agent, issuing the key) — used only once when the agent joins |
| **1514/UDP or TCP** | Shared-key encryption (Blowfish/AES depending on configuration) | `wazuh-remoted` | **Data transmission** of events, continuous |
| **1516/TCP** | — | `wazuh-clusterd` | Communication between managers in a cluster |
| **55000/TCP** | HTTPS | `wazuh-apid` | Management API (RBAC, JWT) |

**WHY enrollment (1515) is separated from data (1514):** Enrollment is a sensitive operation (handing over a key). Separating the ports lets an administrator enable `authd` only during the registration window and then disable it, reducing the attack surface. The 1514 data channel uses the symmetric key that was already exchanged, optimized for high throughput and either stateless (UDP) or reliable (TCP).

### 8.5.2. The enrollment process (state machine, step by step)

```
   AGENT                                   MANAGER (authd:1515)
     │                                            │
     │ 1. TLS ClientHello ───────────────────────▶│
     │◀── 2. TLS handshake complete (TLS 1.2/1.3) │
     │                                            │
     │ 3. Send the enroll request:                 │
     │    "OSSEC A:'<agent_name>'" [+ password]    │
     │    (optional host_name/ip)        ─────────▶│
     │                                            │ 4. authd:
     │                                            │    - check the password (if enabled)
     │                                            │    - issue an agent ID (e.g. 001)
     │                                            │    - generate a client.key entry
     │◀── 5. "OSSEC K:'<id> <name> <ip> <key>'" ──│
     │                                            │
     │ 6. Save to /var/ossec/etc/client.keys       │
     │ 7. Start wazuh-agentd, connect to 1514      │
     ▼                                            ▼
```

**Structure of a `client.keys` line:**

```
001 web01 any 6b2c...e1f9a3...   (64 hex chars = 256-bit pre-shared key)
└┬┘ └─┬─┘ └┬┘ └──────────┬─────┘
 │    │    │             └─ Pre-shared key (hex) used to encrypt the 1514 channel
 │    │    └─ Allowed IP ("any" = any)
 │    └─ Agent name
 └─ Agent ID (3 digits)
```

| Field | Size | Meaning | Example |
|--------|-----------|---------|-------|
| Agent ID | usually 3 numeric characters | Unique identifier of the agent within the manager | `001` |
| Name | string | Agent name | `web01` |
| Allowed IP | string | IP/`any` allowed to connect with this ID | `192.0.2.10` |
| Key | 64 hex (≈256-bit) | Shared key to encrypt/decrypt 1514 messages | `6b2c...` |

**SECURITY NOTES:**
- `client.keys` is a host-level secret — permissions `640 root:wazuh`. Leaking the key allows agent spoofing and injection of fake logs.
- Enable `<use_password>yes</use_password>` for authd to prevent unauthorized registration. Better still: use certificates (CA verification) for both manager-verifies-agent and agent-verifies-manager to prevent MITM at the enroll step.
- Duplicate agent name/ID causes "agent flapping" — assign unique, stable names.

### 8.5.3. The data message format on 1514 (at the conceptual field level)

A message from the agent comprises the following logical parts before encryption:

```
[counters][random][MSG]
```

| Part | Purpose |
|------|----------|
| Counter (global + local) | Anti-replay — the manager rejects messages with an old counter |
| Random padding | Noise to resist analysis |
| MSG | The actual payload: `<msg_type>:<location>:<log line>` |

The `location` part indicates where the log came from on the agent, for example `/var/log/auth.log`, so that analysisd knows which decoder to apply. The whole thing is encrypted with the key in `client.keys` (Wazuh 4.x defaults to AES, and Blowfish can be configured for backward compatibility).

---

## 8.6. The `ossec.conf` configuration file — dissecting each block

`ossec.conf` (path `/var/ossec/etc/ossec.conf`) is the main XML configuration for both the manager and the agent. The root structure is inside the `<ossec_config>` tag. Below are the important blocks with an explanation of each parameter.

### 8.6.1. The `<global>` block and alert level (on the manager)

```xml
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>     <!-- write alerts.json (for Filebeat/indexer) -->
    <alerts_log>yes</alerts_log>             <!-- write alerts.log in text form -->
    <logall>no</logall>                       <!-- do NOT save every event to the archives -->
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>      <!-- only write an alert when rule level >= 3 -->
    <email_alert_level>12</email_alert_level> <!-- send email when level >= 12 -->
  </alerts>
```

| Parameter | Example value | Meaning | WHY |
|---------|---------------|---------|--------|
| `jsonout_output` | yes | Generates `alerts.json` | Filebeat needs JSON to push to the indexer |
| `logall` | no | Does not save *all* events to the archives | `logall=yes` generates a huge amount of data — enable it only when investigation/forensics is needed |
| `log_alert_level` | 3 | Threshold for writing an alert | Filters noise — levels 0–2 are noise |
| `email_alert_level` | 12 | Threshold for sending email | Avoids spam — only serious incidents |

### 8.6.2. The `<remote>` block (the manager listens to agents)

```xml
  <remote>
    <connection>secure</connection>   <!-- secure = encrypted with client.keys -->
    <port>1514</port>
    <protocol>tcp</protocol>          <!-- tcp guarantees delivery; udp is lighter but can drop -->
    <queue_size>131072</queue_size>
  </remote>
```

| Parameter | Meaning | Note |
|---------|---------|-------|
| `connection` | `secure` (encrypted) or `syslog` (receive raw syslog) | Use `secure` for agents; `syslog` for devices on which an agent cannot be installed |
| `protocol` | tcp/udp | **TCP** preferred: no log loss; UDP for extremely large scale that can tolerate loss |
| `queue_size` | Number of buffered messages | Increase it if there are large bursts to avoid drops |

### 8.6.3. The `<client>` block (on the agent)

```xml
  <client>
    <server>
      <address>10.0.0.5</address>      <!-- manager IP/hostname -->
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>yes</enabled>
      <manager_address>10.0.0.5</manager_address>
      <port>1515</port>
      <agent_name>web01</agent_name>
    </enrollment>
    <crypto_method>aes</crypto_method>
    <notify_time>10</notify_time>        <!-- keepalive every 10s -->
    <time-reconnect>60</time-reconnect>  <!-- retry after 60s if the connection is lost -->
  </client>
```

### 8.6.4. The `<localfile>` block (logcollector — which log sources the agent reads)

```xml
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/myapp/audit.json</location>
  </localfile>

  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>           <!-- run a command, take its output as a log -->
    <frequency>360</frequency>          <!-- every 360s -->
  </localfile>
```

| `log_format` | Used for |
|--------------|----------|
| `syslog` | Text files with syslog-style lines (auth.log, messages) |
| `json` | Each line is a JSON object — Wazuh parses the fields automatically |
| `command` / `full_command` | Take a command's output as a periodic event |
| `eventchannel` | Windows Event Log (Security, System, Application) |
| `audit` | Linux auditd |

### 8.6.5. The `<syscheck>` and `<rootcheck>` blocks — see details in 8.9.

### 8.6.6. Reloading the configuration

```bash
# Check the configuration + rule/decoder syntax before restarting (very important)
/var/ossec/bin/wazuh-logtest        # interactive rule/decoder testing
/var/ossec/bin/wazuh-analysisd -t   # -t = test mode, reports syntax errors then exits

# Restart
systemctl restart wazuh-manager
# or
/var/ossec/bin/wazuh-control restart
```

> **NOTE:** Always run `wazuh-analysisd -t` before restarting in production. A syntax error in `local_rules.xml` prevents analysisd from starting → total blindness.

---

## 8.7. DECODER — extracting fields from real logs

### 8.7.1. WHAT IT IS

A **decoder** is an XML rule that tells `wazuh-analysisd` how to extract fields (srcip, srcuser, ...) from a raw log line. The decoder does *not* generate an alert — it only prepares the data for rules.

Paths:
- Base decoders: `/var/ossec/ruleset/decoders/*.xml` (do NOT edit — overwritten on update).
- Custom decoders: `/var/ossec/etc/decoders/local_decoder.xml`.

### 8.7.2. The two decoder types and their attributes

| Type | Tag | Role |
|------|-----|---------|
| **Parent decoder** | `<decoder name="...">` | Identifies the *program/source* (via `program_name` or `prematch`) |
| **Child decoder** | `<decoder name="..."><parent>...</parent>` | Extracts specific fields, runs after the parent matches |

| Child tag | Meaning | Processing order |
|---------|---------|--------------|
| `<program_name>` | Matches the program name (taken from PreDecoding) | Fast filter first |
| `<prematch>` | A regex that must match before the decoder runs its `<regex>` | Tier-1 filter |
| `<regex>` | Regex that extracts values; capture groups `()` map to `<order>` | Field extraction |
| `<order>` | The list of field names corresponding to the regex capture groups | Naming |

### 8.7.3. REAL-WORLD EXAMPLE — the SSH decoder (already built into Wazuh, dissected here)

Raw log:
```
Jun 19 10:22:41 web01 sshd[2931]: Failed password for invalid user admin from 203.0.113.5 port 51244 ssh2
```

**PreDecoding** (automatic, no XML required) extracts the syslog header:
```
hostname    = web01
program_name= sshd
timestamp   = Jun 19 10:22:41
log         = "Failed password for invalid user admin from 203.0.113.5 port 51244 ssh2"
```

**Parent decoder** (identifies sshd):
```xml
<decoder name="sshd">
  <program_name>^sshd</program_name>
</decoder>
```

**Child decoder** (extracts user + ip):
```xml
<decoder name="ssh-failed-invalid">
  <parent>sshd</parent>
  <prematch>^Failed password for invalid user</prematch>
  <regex offset="after_prematch">^ (\S+) from (\d+.\d+.\d+.\d+) port (\d+)</regex>
  <order>srcuser, srcip, srcport</order>
</decoder>
```

Explanation of each part:
- `<parent>sshd</parent>`: runs only if the `sshd` parent matched.
- `<prematch>`: requires the line to begin with `Failed password for invalid user`. If it does not match → skip, saving CPU (WHY: the full regex is expensive, the prematch is a cheap filter gate).
- `offset="after_prematch"`: starts the `<regex>` right after the prematched portion. This is an optimization to keep the regex short.
- The capture groups `(\S+)`, `(\d+.\d+.\d+.\d+)`, `(\d+)` map respectively to `srcuser, srcip, srcport` via `<order>`.

> Note on regex syntax: Wazuh supports its internal **OS_Regex** syntax (fast, limited) and **PCRE2** via the `type="pcre2"` attribute. In OS_Regex, `\d`, `\S` are character classes; `.` matches any character. When you need complex regex (lookahead, etc.), use `<regex type="pcre2">`.

**Result after decoding** (fields ready for rules):
```json
{
  "program_name": "sshd",
  "srcuser": "admin",
  "srcip": "203.0.113.5",
  "srcport": "51244"
}
```

### 8.7.4. EXAMPLE — writing a custom decoder for a self-defined application log

Suppose an internal application produces the log:
```
Jun 19 11:05:00 app01 paywall: AUTH_FAIL user=jdoe ip=198.51.100.7 reason=bad_token txn=AB12
```

`local_decoder.xml`:
```xml
<decoder name="paywall">
  <program_name>^paywall</program_name>
</decoder>

<decoder name="paywall-authfail">
  <parent>paywall</parent>
  <prematch>^AUTH_FAIL </prematch>
  <regex>user=(\S+) ip=(\d+.\d+.\d+.\d+) reason=(\S+) txn=(\S+)</regex>
  <order>srcuser, srcip, reason, txn_id</order>
</decoder>
```

Test it immediately with `wazuh-logtest`:
```bash
/var/ossec/bin/wazuh-logtest
# Paste the log line into stdin:
Jun 19 11:05:00 app01 paywall: AUTH_FAIL user=jdoe ip=198.51.100.7 reason=bad_token txn=AB12
```
Sample output:
```
**Phase 1: Completed pre-decoding.
        full event: 'Jun 19 11:05:00 app01 paywall: AUTH_FAIL ...'
        timestamp: 'Jun 19 11:05:00'
        hostname: 'app01'
        program_name: 'paywall'
**Phase 2: Completed decoding.
        name: 'paywall'
        srcuser: 'jdoe'
        srcip: '198.51.100.7'
        reason: 'bad_token'
        txn_id: 'AB12'
**Phase 3: Completed filtering (rules).
        ... (no rule matched yet)
```

**SECURITY NOTES:** A bad decoder (greedy regex, missing the `^` anchor) can extract the wrong field or slow analysisd under heavy load → an indirect DoS. Always anchor your regex and test with `wazuh-logtest` before deploying.

---

## 8.8. RULE — detection and classification

### 8.8.1. WHAT IT IS

A **rule** decides which event becomes an alert, assigns a **level** (0–16), an `id`, groups, and (optionally) a MITRE mapping. Rules run *after* decoders, based on the extracted fields.

Paths:
- Base rules: `/var/ossec/ruleset/rules/*.xml` (do not edit).
- Custom rules: `/var/ossec/etc/rules/local_rules.xml`.

### 8.8.2. Attributes and tags of a rule

| Attribute/Tag | Meaning | Example |
|----------------|---------|-------|
| `id` | Unique identifier. The range **100000–120000** is reserved for custom rules (so as not to collide with base rules) | `100100` |
| `level` | Severity 0–16 (0 = ignore/no alert) | `10` |
| `<if_sid>` | Considered only if a rule with this ID matched earlier (rule chaining) | `<if_sid>5710</if_sid>` |
| `<if_matched_sid>` | Used with correlation: the child rule matches when that SID rule matches frequently enough | — |
| `<match>` | Matches a substring within the log | `<match>AUTH_FAIL</match>` |
| `<regex>` | Matches a regex within the log/field | `<regex>reason=bad_token</regex>` |
| `<field>` | Matches a decoded field | `<field name="srcuser">admin</field>` |
| `<frequency>` | The number of matches required to trigger (correlation) | `8` |
| `<timeframe>` | The time window (seconds) for `frequency` | `120` |
| `<same_source_ip/>` | Requires the same srcip to count (group key) | — |
| `<group>` | Classification group (authentication_failed, attack, etc.) | `authentication_failures,` |
| `<mitre><id>` | A MITRE ATT&CK technique code | `T1110` |
| `<description>` | The description shown on the alert | — |

### 8.8.3. Wazuh's LEVEL scale (0–16)

| Level | General meaning |
|-------|-------------------|
| 0 | Ignored completely (not logged) — used to reduce FPs |
| 1–3 | Informational / low importance |
| 4–6 | Noteworthy (a single auth failure, configuration) |
| 7–9 | Important (multiple failures, suspicious behavior) |
| 10–12 | High probability of attack (brute-force detected) |
| 13–16 | Critical (successful intrusion, system) |

### 8.8.4. EXAMPLE — a stateless rule mapped onto the paywall decoder from 8.7.4

`local_rules.xml`:
```xml
<group name="paywall,authentication,">

  <!-- Base rule: a single AUTH_FAIL from paywall -->
  <rule id="100100" level="5">
    <decoded_as>paywall</decoded_as>
    <field name="reason">bad_token</field>
    <description>Paywall: authentication failed due to a bad token (user $(srcuser), ip $(srcip))</description>
    <group>authentication_failed,</group>
    <mitre>
      <id>T1078</id>   <!-- Valid Accounts (credential abuse) -->
    </mitre>
  </rule>

</group>
```

Explanation:
- `<decoded_as>paywall</decoded_as>`: applies only to events processed by the `paywall` decoder.
- `<field name="reason">bad_token</field>`: matches the decoded `reason` field.
- `$(srcuser)`, `$(srcip)`: interpolate the fields into the alert description.

### 8.8.5. KEY EXAMPLE — brute-force correlation (frequency + timeframe)

This is the classic stateful example: many login failures from the same IP within a time window → a single brute-force alert.

```xml
<group name="paywall,authentication,attack,">

  <!-- Correlation rule: >=8 occurrences of rule 100100 from the SAME srcip within 120 seconds -->
  <rule id="100110" level="10" frequency="8" timeframe="120">
    <if_matched_sid>100100</if_matched_sid>
    <same_source_ip />
    <description>Paywall: token BRUTE-FORCE — >=8 failures from $(srcip) within 120s</description>
    <group>authentication_failures,brute_force,</group>
    <mitre>
      <id>T1110</id>   <!-- Brute Force -->
    </mitre>
  </rule>

</group>
```

**INTERNAL MECHANISM (the analysisd state machine):**

```
Initialize, for each srcip, a counter + a window-start timestamp.

  Event rule 100100 matches, srcip=X:
    ┌─ Find the bucket for key=X
    │     ├─ If none yet: create bucket{count=1, t0=now}
    │     └─ If it exists:
    │           ├─ If (now - t0) > timeframe(120s): RESET bucket{count=1, t0=now}
    │           └─ Otherwise: count++
    │                 └─ If count >= frequency(8): TRIGGER rule 100110 (level 10) → ALERT
    │                       (after triggering, reset to avoid continuous spam)
    ▼
```

A table illustrating an event sequence (frequency=8, timeframe=120):

| t (s) | srcip | count(X) | Action |
|-------|-------|----------|-----------|
| 0 | 203.0.113.5 | 1 | create the bucket |
| 5 | 203.0.113.5 | 2 | count++ |
| ... | ... | ... | ... |
| 40 | 203.0.113.5 | 8 | **count==8 ≤ 120s → ALERT 100110 level 10** |
| 200 | 203.0.113.5 | 1 | the old t0 has expired (200-0>120) → reset |

**WHY the `frequency`+`timeframe`+`same_source_ip` design:**
- `same_source_ip` is the *group key*: without it, 8 failures from 8 different IPs (for example mild distributed password spraying) would be lumped together incorrectly. With it, we split the buckets by IP to correctly detect concentrated brute-force.
- `timeframe` defines the "speed" — distinguishing brute-force (8 times in 2 minutes) from 8 failures scattered across the whole day (a user who forgot their password).

> Other group keys: `<same_source_user/>`, `<same_destination_ip/>`, `<different_source_ip/>` (for distributed detection). In addition, `<if_matched_group>` allows counting by a rule *group* rather than a single SID.

### 8.8.6. Overriding and adjusting base rules (overwrite / `<if_sid>`)

Do not edit the base files; instead, in `local_rules.xml`:

```xml
<!-- Lower the level of a noisy base rule in your environment -->
<rule id="5710" level="0" overwrite="yes">
  <description>sshd: non-existent user (silenced in the admin subnet)</description>
</rule>
```

Or create a conditional exception:
```xml
<rule id="100200" level="0">
  <if_sid>5710</if_sid>
  <field name="srcip">10.0.0.0/8</field>   <!-- ignore if from the trusted internal network -->
  <description>Ignore sshd failures from the internal admin network</description>
</rule>
```

---

## 8.9. FIM / Syscheck — file integrity monitoring

### 8.9.1. WHAT IT IS

**FIM (File Integrity Monitoring)** — the `syscheckd` module — detects changes to files/directories/registry: creation, modification, deletion. It is used to catch webshells, binary tampering, and modifications to sensitive configuration files.

### 8.9.2. INTERNAL MECHANISM

Syscheck maintains a **state database** (the FIM database, SQLite in Wazuh 4.x) storing for each file:

| Attribute stored | Size/type | Meaning |
|----------------|-----------------|---------|
| `size` | int | Size in bytes |
| `perm` | mode bits | Permissions (rwx) |
| `uid`/`gid` | int | Owner/group |
| `inode` | int | Inode number (Linux) |
| `mtime` | timestamp | Content-modification time |
| `md5` | 128-bit (32 hex) | MD5 hash |
| `sha1` | 160-bit (40 hex) | SHA-1 hash |
| `sha256` | 256-bit (64 hex) | SHA-256 hash (the recommended default) |

Two modes:

| Mode | Mechanism | Detection latency |
|--------|--------|------------------|
| **Scheduled scan** | Periodic scan (`<frequency>`), comparing the new hash to the DB | Per cycle (seconds/hours) |
| **Real-time** | Uses `inotify` (Linux) / `ReadDirectoryChangesW` (Windows) to receive kernel events instantly | Near-instant |

**WHY use a hash and not just mtime:** An attacker can `touch` a file to restore the mtime after editing it. A content hash (SHA-256) catches content changes even when metadata is forged. SHA-256 is chosen because it is more collision-resistant than MD5/SHA-1.

### 8.9.3. EXAMPLE — `<syscheck>` configuration in `ossec.conf`

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>            <!-- scheduled scan every 12 hours -->
  <scan_on_start>yes</scan_on_start>

  <!-- Web directory: realtime + report content changes -->
  <directories check_all="yes" realtime="yes" report_changes="yes">/var/www/html</directories>

  <!-- Sensitive configuration files: track every attribute -->
  <directories check_all="yes" realtime="yes">/etc,/usr/bin,/usr/sbin</directories>

  <!-- Exclusions to reduce noise -->
  <ignore>/etc/mtab</ignore>
  <ignore>/var/www/html/cache</ignore>
  <ignore type="sregex">.log$</ignore>

  <!-- Do not hash large files to save resources -->
  <skip_nfs>yes</skip_nfs>
  <nodiff>/etc/ssl/private</nodiff>       <!-- do not store content diffs (they contain secrets) -->
</syscheck>
```

| `<directories>` attribute | Meaning |
|----------------------------|---------|
| `check_all="yes"` | Checks size+perm+owner+mtime+inode+the hashes |
| `realtime="yes"` | Enables inotify for this directory |
| `report_changes="yes"` | Stores the *content diff* (for text files) so you can see exactly which line changed |
| `whodata="yes"` | Uses auditd to know *who* (uid/process) made the change (more advanced than realtime) |

### 8.9.4. EXAMPLE — a sample FIM alert (webshell)

When an attacker drops `shell.php` into `/var/www/html`, syscheck (realtime) generates an event that matches a base FIM rule (the `syscheck` group, rules 550–554), and alerts.json:
```json
{
  "rule": { "id": "554", "level": 7, "description": "File added to the system." },
  "syscheck": {
    "path": "/var/www/html/shell.php",
    "event": "added",
    "sha256_after": "9f2c...e1",
    "uid_after": "33", "gname_after": "www-data",
    "mtime_after": "2026-06-19T11:30:02"
  },
  "location": "syscheck"
}
```

**SECURITY NOTES:**
- `report_changes`/`nodiff`: do NOT store the diff of files containing secrets (private keys, `/etc/shadow`) — the diff stored in the Wazuh DB could leak secrets. Use `<nodiff>` for sensitive paths.
- Realtime on an extremely large directory (e.g. `/`) exhausts the kernel's inotify watches (`fs.inotify.max_user_watches`) → silent loss of monitoring. Use realtime only where it is needed.

---

## 8.10. Active Response — automated response

### 8.10.1. WHAT IT IS

**Active Response (AR)** allows Wazuh to automatically run a command (script) when a rule matches — for example, blocking an attacking IP with a firewall. This is the integrated "mini-SOAR" capability, executed by `wazuh-execd` on the agent or the manager.

### 8.10.2. INTERNAL MECHANISM (flow + state)

```
Rule X matches (e.g. brute-force level >=10)
        │
        ▼
analysisd checks for any linked <active-response> (via <rules_id> or <level>)
        │  yes
        ▼
the manager sends the AR command down to the target agent (over the 1514 channel)
        │
        ▼
wazuh-execd on the agent calls a script in /var/ossec/active-response/bin/
        ├─ action = "add"     → block (e.g. add an iptables DROP rule for srcip)
        └─ after <timeout> seconds  → call back with action = "delete" → unblock
```

The AR script receives parameters via **stdin (JSON)** in Wazuh 4.x: comprising `command` (`add`/`delete`) and `parameters.alert` (the entire alert, which contains `srcip`). WHY a timeout: blocking permanently risks a self-DoS (mistakenly blocking a legitimate IP, or a shared NAT IP) — the timeout allows automatic removal.

### 8.10.3. REAL-WORLD EXAMPLE — blocking a brute-force IP with firewall-drop

Step 1 — define the **command** and the **active-response** in `ossec.conf` (on the manager):
```xml
<!-- Command: points to the built-in firewall-drop script -->
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>   <!-- /var/ossec/active-response/bin/firewall-drop -->
  <timeout_allowed>yes</timeout_allowed>
</command>

<!-- Active response: run the command on the agent that has the event, block for 600s -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>          <!-- local = run on the agent where the event occurred -->
  <rules_id>100110</rules_id>         <!-- this is the brute-force rule from 8.8.5 -->
  <timeout>600</timeout>              <!-- unblock after 600 seconds -->
</active-response>
```

| `<location>` | Where it runs |
|--------------|-----------|
| `local` | On the agent that generated the event |
| `server` | On the manager |
| `defined-agent` | On a specified agent (`<agent_id>`) |
| `all` | All agents (be careful!) |

Step 2 — `firewall-drop` (the built-in script) on the Linux agent executes the equivalent of:
```bash
# action=add:
iptables -I INPUT -s 203.0.113.5 -j DROP
# after 600s, action=delete:
iptables -D INPUT -s 203.0.113.5 -j DROP
```

Step 3 — the AR alert is written in `active-responses.log` on the agent:
```
2026-06-19 11:31:00 /var/ossec/active-response/bin/firewall-drop: add - 203.0.113.5 - 1718796660.123456 - 100110
```

**SECURITY NOTES:**
- **Anti self-DoS:** an attacker spoofs srcip = the IP of an internal gateway/DNS in the log to force Wazuh to block your own infrastructure. Always maintain an **allowlist** (the firewall-drop script has a mechanism to skip IPs on a whitelist); do NOT enable AR `all` for rules that are easily spoofed.
- AR runs with high privileges (iptables requires root) → the AR script is an attack surface; use only vetted scripts with tight file permissions.
- Prefer AR `local` over `all` to limit the impact.

---

## 8.11. Vulnerability Detection — vulnerability detection (CVE)

### 8.11.1. WHAT IT IS and the MECHANISM

The `wazuh-modulesd` module (Vulnerability Detector) cross-references the **list of installed packages** (sent by the agent via syscollector) against a **CVE feed** to report which host has which vulnerability.

Flow:
```
1. syscollector (on the agent) lists packages + versions + OS  ──▶ manager
2. The Vulnerability Detector downloads/updates the CVE feed
      (sources: NVD, Canonical/Ubuntu OVAL, Red Hat, Debian, Microsoft MSU, ALAS, ...)
3. Compare: package P version V vs the condition "affected if V < V_fixed"
4. Generate an alert if it matches, with the CVE id, CVSS, package, fixed version
```

> Version-specific architecture note: the configuration approach and feed sources of Vulnerability Detection **have changed significantly between 4.x minor versions** (the old feed model based directly on OVAL/NVD vs the new "Vulnerability Detection" model based on Wazuh's Content Manager/CTI). Verify the syntax of the configuration block against the documentation for the exact version you are running. The section below illustrates the old OVAL/NVD-style configuration to convey the principle.

### 8.11.2. EXAMPLE — the old-style configuration (illustrating the principle)

```xml
<vulnerability-detector>
  <enabled>yes</enabled>
  <interval>5m</interval>
  <run_on_start>yes</run_on_start>

  <provider name="canonical">          <!-- Ubuntu OVAL -->
    <enabled>yes</enabled>
    <os>focal</os>
    <os>jammy</os>
    <update_interval>1h</update_interval>
  </provider>

  <provider name="nvd">                <!-- NVD supplements CVSS/CPE -->
    <enabled>yes</enabled>
    <update_interval>1h</update_interval>
  </provider>
</vulnerability-detector>
```

### 8.11.3. EXAMPLE — a sample CVE alert

```json
{
  "rule": { "level": 7, "description": "CVE-2024-XXXX affects openssl" },
  "data": {
    "vulnerability": {
      "cve": "CVE-2024-XXXX",
      "package": { "name": "openssl", "version": "3.0.2-0ubuntu1.10" },
      "severity": "High",
      "cvss": { "cvss3": { "base_score": "7.5" } },
      "status": "Active",
      "reference": "https://ubuntu.com/security/CVE-2024-XXXX"
    }
  }
}
```

**NOTE:** Vulnerability Detection reports a **potential vulnerability based on version**, it does NOT confirm actual exploitability (it does not always know whether the distro has backported a patch). You must cross-reference with reachability/exposure before prioritizing a patch — to avoid "CVE noise".

---

## 8.12. SCA — Security Configuration Assessment

### 8.12.1. WHAT IT IS

**SCA** checks system configuration against a baseline (the CIS Benchmark, for example "SSH does not allow root login", "passwords must have a complexity requirement"). This module runs **policies** in YAML form on the agent and reports pass/fail for each check.

### 8.12.2. MECHANISM — the structure of a policy check

An SCA policy (a YAML file in `/var/ossec/ruleset/sca/`) comprises `checks`, each check having `rules` evaluated by logic.

```yaml
policy:
  id: "cis_debian12"
  name: "CIS Debian Linux 12 Benchmark"

checks:
  - id: 5001
    title: "Ensure SSH PermitRootLogin is disabled"
    description: "PermitRootLogin should = no to block direct root login"
    rationale: "Reduces the brute-force surface against the highest-privilege account"
    remediation: "Set 'PermitRootLogin no' in /etc/ssh/sshd_config then reload sshd"
    condition: all          # all rules must be true to PASS
    rules:
      - 'f:/etc/ssh/sshd_config -> r:^\s*PermitRootLogin\s+no'
```

`rules` syntax (atomic checks):

| Prefix | Meaning | Example |
|---------|---------|-------|
| `f:` | File exists | `f:/etc/ssh/sshd_config` |
| `f:... -> r:` | File contains a regex | `f:/etc/ssh/sshd_config -> r:^PermitRootLogin no` |
| `c:` | Run a command, compare its output | `c:sysctl net.ipv4.ip_forward -> r:= 0$` |
| `d:` | Directory exists | `d:/etc/cron.d` |
| `p:` | Process is running | `p:auditd` |
| `r:` | Registry key (Windows) | — |

`condition`: `all` (every rule true), `any` (one rule true), `none` (no rule true).

### 8.12.3. EXAMPLE — an SCA result on the dashboard / alert

```json
{
  "data": {
    "sca": {
      "type": "check",
      "policy": "CIS Debian Linux 12 Benchmark",
      "check": {
        "id": "5001",
        "title": "Ensure SSH PermitRootLogin is disabled",
        "result": "failed",
        "remediation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"
      }
    }
  }
}
```

**NOTE:** SCA is *configuration drift detection* — it runs periodically. A host that "passed 90%" may still have a 10% failure that is a serious vulnerability; read it check by check, not just by the total score.

---

## 8.13. MITRE ATT&CK integration

### 8.13.1. WHAT IT IS

**MITRE ATT&CK** is a matrix that standardizes attacker techniques by Tactic (the objective) → Technique (the method). Wazuh attaches a technique code (`T####`, sub-technique `T####.###`) to rules, allowing the dashboard to display attacks by the matrix and to support threat hunting.

| Concept | Example |
|-----------|-------|
| Tactic | `Credential Access` (TA0006) |
| Technique | `T1110` Brute Force |
| Sub-technique | `T1110.001` Password Guessing |

### 8.13.2. EXAMPLE — attaching MITRE to a rule (as seen in 8.8.5)

```xml
<rule id="100110" level="10" frequency="8" timeframe="120">
  <if_matched_sid>100100</if_matched_sid>
  <same_source_ip />
  <description>Paywall brute-force</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

On the dashboard, this alert appears in the **MITRE ATT&CK** module, grouped by the `Credential Access` Tactic, allowing you to answer "how many events belonging to Credential Access occurred in the past week, and on which hosts."

**NOTE:** Attaching the correct MITRE technique is part of detection engineering — attaching the wrong one distorts the coverage report (you think you have covered technique X but the rule actually catches something else).

---

## 8.14. Detection Engineering — writing and tuning rules, FP vs FN

### 8.14.1. FP and FN

| Concept | Definition | Consequence |
|-----------|------------|---------|
| **False Positive (FP)** | An alert fires but is NOT an attack | Analyst fatigue (alert fatigue), missing real alerts |
| **False Negative (FN)** | A real attack but NO alert | Slips through — the most dangerous |
| **True Positive (TP)** | A correct alert | Ideal |
| **True Negative (TN)** | No alert, and it really is safe | Ideal |

**The core trade-off:** Lowering the threshold (low frequency, high level for a single event) → reduces FN but increases FP. Raising the threshold → reduces FP but increases FN. Detection engineering is finding the balance point according to the asset's context.

Quantitative metrics:
```
Precision = TP / (TP + FP)     (how trustworthy a fired alert is)
Recall    = TP / (TP + FN)     (what fraction of real attacks are caught)
```

### 8.14.2. The tuning process (a loop)

```
1. Write a hypothesis rule (based on the decoder + fields).
2. Test offline with wazuh-logtest on sample logs (both attack samples and benign samples).
3. Deploy at a LOW level (e.g. level 3) — observe the volume, take no action.
4. Measure FP: the fraction of alerts that are benign. If high → add conditions (field/srcip allowlist) or increase frequency.
5. Measure FN: replay known attack samples — does the rule fire?
6. When precision is acceptable, raise the level + (optionally) attach an active-response.
7. Repeat periodically (the environment changes → rules become outdated).
```

### 8.14.3. EXAMPLE — tuning the brute-force rule to reduce FP

The problem: rule 100110 fires when a proxy/NAT makes many real users fail from the same srcip. Tuning:

```xml
<!-- v2: only count brute-force when the same IP BUT a different user (a sign of user enumeration),
         and exclude the trusted internal NAT range -->
<rule id="100111" level="12" frequency="10" timeframe="120">
  <if_matched_sid>100100</if_matched_sid>
  <same_source_ip />
  <different_source_user />      <!-- many different users from 1 IP = account enumeration -->
  <description>Paywall: enumeration of many accounts from $(srcip) (suspected credential stuffing)</description>
  <mitre><id>T1110.004</id></mitre>  <!-- Credential Stuffing -->
</rule>

<!-- Suppress FP: ignore the office NAT range -->
<rule id="100112" level="0">
  <if_sid>100110</if_sid>
  <field name="srcip">^10.20.0.</field>
  <description>Ignore fake brute-force from the office NAT</description>
</rule>
```

### 8.14.4. Principles of writing good rules

| Principle | WHY |
|-----------|--------|
| Anchor your regex (`^`, `$`), match fields rather than substrings when possible | Avoids mismatches, faster |
| Place the `id` in 100000–120000 | Does not collide with base rules, not lost on update |
| Start at a low level, raise gradually | Avoids harm from active-response due to FPs |
| Document the `<description>` clearly with field interpolation | The analyst understands immediately during triage |
| Attach the correct `<mitre>` | Measures coverage |
| Have both positive and negative test cases | Ensures no FN and no FP |

---

## 8.15. END-TO-END EXAMPLE: SSH brute-force from raw log to dashboard alert

Putting the whole chain together: **log → predecode → decode → stateless rule → correlation rule → alert → (active response) → indexer → dashboard.**

### Step 0 — Configure the agent to read auth.log
`ossec.conf` (agent):
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>
```

### Step 1 — The raw logs are produced (3 illustrative lines)
```
Jun 19 10:22:41 web01 sshd[2931]: Failed password for invalid user admin from 203.0.113.5 port 51244 ssh2
Jun 19 10:22:43 web01 sshd[2933]: Failed password for invalid user admin from 203.0.113.5 port 51290 ssh2
... (repeated 8 times within ~30s)
```

### Step 2 — PreDecoding (analysisd)
```
timestamp:    Jun 19 10:22:41
hostname:     web01
program_name: sshd
log:          Failed password for invalid user admin from 203.0.113.5 port 51244 ssh2
```

### Step 3 — Decoding (the base sshd decoder)
```
srcuser: admin
srcip:   203.0.113.5
srcport: 51244
```

### Step 4 — A base stateless rule matches
Wazuh ships a rule for this out of the box:
```xml
<!-- (base rule, illustrative) -->
<rule id="5710" level="5">
  <if_sid>5700</if_sid>
  <match>Failed password|authentication failure|invalid user</match>
  <description>sshd: Attempt to login using a non-existent user.</description>
  <group>authentication_failed,invalid_login,</group>
</rule>
```
→ Each failure line creates a level-5 alert.

### Step 5 — A base correlation rule matches (brute-force)
```xml
<!-- (base rule, illustrative) — many authentication_failed from the same IP -->
<rule id="5712" level="10" frequency="8" timeframe="120">
  <if_matched_sid>5710</if_matched_sid>
  <same_source_ip />
  <description>sshd: brute force trying to get access to the system. Authentication failed.</description>
  <group>authentication_failures,</group>
  <mitre><id>T1110</id></mitre>
</rule>
```
→ After the 8th failure within 120s from `203.0.113.5`, a level-10 alert fires.

### Step 6 — The alert JSON (written to `/var/ossec/logs/alerts/alerts.json`)
```json
{
  "timestamp": "2026-06-19T10:23:11.044+0000",
  "rule": {
    "id": "5712",
    "level": 10,
    "description": "sshd: brute force trying to get access to the system.",
    "groups": ["syslog", "sshd", "authentication_failures"],
    "mitre": { "id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"] },
    "frequency": 8
  },
  "agent": { "id": "001", "name": "web01", "ip": "192.0.2.10" },
  "data": { "srcip": "203.0.113.5", "srcuser": "admin", "srcport": "51244" },
  "decoder": { "name": "sshd" },
  "location": "/var/log/auth.log",
  "full_log": "Jun 19 10:22:41 web01 sshd[2931]: Failed password for invalid user admin from 203.0.113.5 port 51244 ssh2"
}
```

### Step 7 — Active Response (optional) blocks the IP
If you configure `<active-response>` with `<rules_id>5712</rules_id>`, the manager instructs agent web01 to run `firewall-drop`:
```
iptables -I INPUT -s 203.0.113.5 -j DROP   # auto-removed after <timeout>
```

### Step 8 — Filebeat → Indexer → Dashboard
- `Filebeat` (configured in `/etc/filebeat/filebeat.yml` with the `wazuh` module) reads `alerts.json` and pushes it into the index `wazuh-alerts-4.x-2026.06.19` on the indexer (port 9200).
- The Dashboard queries the index and displays the level-10 alert in Security Events; in the MITRE ATT&CK module it belongs to Tactic *Credential Access* / Technique *T1110*.

### Step 9 — Offline testing of the whole chain
```bash
# Quick simulation: paste the log line into logtest to confirm the decoder + rule
/var/ossec/bin/wazuh-logtest
# input:
Jun 19 10:22:41 web01 sshd[2931]: Failed password for invalid user admin from 203.0.113.5 port 51244 ssh2
```
The output confirms Phase 1/2/3 and rule id 5710 → (after sufficient frequency) 5712.

End-to-end summary diagram:
```
auth.log line ──▶ logcollector(agent) ──1514──▶ remoted ──▶ analysisd
                                                              │
                       ┌──────────────────────────────────────┘
                       ▼
            PreDecode ▶ Decode(sshd: srcip/srcuser) ▶ Rule 5710(L5) ▶ [×8/120s, same_source_ip] ▶ Rule 5712(L10)
                                                                                                        │
                                          ┌─────────────────────────────────────────────┬─────────────┘
                                          ▼                                             ▼
                                  active-response: firewall-drop              alerts.json ▶ Filebeat ▶ Indexer(9200) ▶ Dashboard(443)
                                  iptables DROP 203.0.113.5
```

---

## 8.16. Operational summary & Wazuh security checklist

| Item | Recommendation |
|----------|-------------|
| Data transmission | TCP 1514 + `crypto_method aes`; enroll over 1515 with a password/CA |
| `client.keys` | Tight permissions, no leaks; stable, unique agent names |
| Custom rules/decoders | Only in `local_*.xml`, ids 100000+, test with `wazuh-logtest` & `analysisd -t` before restart |
| FIM | Realtime in the right places; `<nodiff>` for paths containing secrets; watch the `inotify` watches |
| Active Response | Allowlist infrastructure IPs; prefer `local`; use `timeout` for auto-removal; tight script permissions |
| Vuln/SCA | Cross-reference the version against the correct feed; read by individual CVE/check, not just the total score |
| Storage | `logall=no` unless doing forensics; a clear retention policy (hot/warm/cold) |
| Tuning | A loop measuring FP/FN; raise the level gradually; review periodically |
| API 55000 | Change default credentials, enable RBAC, restrict the network |

---

*End of Chapter 8.*
