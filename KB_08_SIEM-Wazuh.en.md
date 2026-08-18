# Chapter 8 — SIEM & Centralized Log Management

## Overview

When I was first learning SIEM, I assumed its value was in the pretty dashboard and the real-time alerts. It wasn't until I sat down to investigate an actual scan for the first time that I understood where the real value sits: the ability to ask questions of log data that has already been pulled into one place. This chapter follows that same thread. A **SIEM** is the software layer that centralizes logs from many sources — servers, firewalls, applications, network devices — synchronizes their timestamps, normalizes them into a common data model, and correlates them to generate alerts. Without it, the traces of an attack stay scattered across many systems and log files, at a volume that outpaces anything a human could read by hand; a SIEM gathers everything in one place, reduces it to a common language, and stitches fragments of evidence together automatically. **Wazuh**, the open-source SIEM/HIDS platform this chapter centers on, implements that full pipeline end to end. Visibility always comes before any capacity to defend — if you don't collect the logs of a password-guessing attempt or a file change on a server, there's nothing to detect or respond to.

The first half of the chapter moves from foundational concepts to telling the tools apart. The **data pipeline** — collect → parse → normalize → enrich → correlate → alert → store — is the fixed sequence every event passes through, turning raw logs that arrive in a different shape from every source into one structured, uniform form; the **normalize** step matters most here, since it maps a field like "source IP" from many different pieces of software, each using its own field name, onto one common name so a single rule can apply everywhere. Choosing the right defensive layer matters just as much: **AV** protects a single endpoint by blocking known malware via signature or hash; **EDR** watches that same endpoint far more deeply, down to the process tree, syscalls, registry, and host network; **NDR** watches network traffic itself — packets, flows, metadata — to catch C2, exfiltration, and lateral movement; **SIEM** sits above all of them, correlating the full picture from every normalized source for investigation and compliance; **SOAR** automates the response once an alert fires, following a playbook; and **XDR** bundles several of these layers from a single vendor, already correlated. Each layer sees a different slice of the data, and picking the wrong one leaves a blind spot that usually only shows up after it's been exploited — Wazuh itself plays double duty here, acting as both a lightweight EDR-style agent and a SIEM.

From there the chapter goes deep into **Wazuh's architecture**: an **agent** on each endpoint that collects logs and telemetry, a **manager** that receives, decodes, applies rules, and generates alerts, an **indexer** built on OpenSearch for storage and search, and a **dashboard** for visualization and administration. Wazuh's appeal is delivering a complete SIEM without depending on expensive commercial software, and understanding these four pieces makes it easier to picture how data actually moves from an endpoint to an operator's screen.

The rest of the chapter is about how Wazuh turns logs into action. Before an agent can send anything, it goes through **enrollment**, registering with the manager to obtain a pre-shared key it then uses to encrypt and continuously transmit logs over a dedicated channel — a step that ensures only valid hosts can ever send data, and keeping the enrollment port separate from the data-transmission port helps shrink the attack surface further. All of that behavior, on both manager and agent, is driven by `ossec.conf`, an XML file declaring which log sources to read, where to send them, and what alert thresholds to use; a syntax error here can silently leave a system unmonitored, so it's worth checking before applying.

Turning a raw log line into an alert happens in two steps. A **decoder** extracts meaningful fields — user, source IP, action — from free text that detection logic otherwise couldn't operate on; it prepares the data but never fires an alert on its own. A **rule** is what makes that decision: given the decoded fields, it decides which event becomes an alert and at what severity — an IP that fails to log in eight times within 120 seconds, say, gets classified as a high-severity brute-force attempt. This is the layer that actually separates normal behavior from dangerous behavior.

A few features round out what Wazuh watches and does. **FIM/Syscheck** tracks the creation, modification, and deletion of important files by comparing content hashes rather than just metadata, which is why it still catches a change even when an attacker forges the file's mtime. **Active Response** lets Wazuh act on a rule match automatically — blocking an attacking IP and lifting the block again after a timeout — trading speed (faster than any human on call) for the need to control it tightly, since a misfire can just as easily block legitimate infrastructure. **Vulnerability Detection** cross-references installed package versions against a CVE feed to flag hosts running something exploitable, and **SCA** checks system configuration against a secure baseline like the CIS Benchmark, since plenty of breaches trace back to loose configuration rather than a software bug at all.

The last stretch of the chapter is about making sense of what all this produces. **MITRE ATT&CK** gives attacker techniques a shared vocabulary (`T####` identifiers), and **Detection Engineering** is the ongoing work of writing and tuning rules to balance false negatives against false positives — the difference between a SIEM people actually trust and one that becomes noise they learn to ignore. Section 8.16 turns that into a concrete, repeatable workflow: the dashboard points at an anomaly, aggregation queries on `wazuh-alerts-*` scope it down, `full_log` evidence confirms or rules it out, and the conclusion widens out to the whole fleet — because a dashboard shows that something looks odd, not what actually happened, and without a method that gap turns into random clicking. Closing the chapter is **SOAR**, the automation layer sitting on top of the SIEM: it takes filtered alerts, enriches them automatically with threat intelligence, and notifies the operations channel per playbook — not a replacement for the SIEM, but relief for the repetitive part of triage so people can spend their time on judgment calls instead.

> Every section pairs its concepts with an example that runs on a real Wazuh setup; anywhere a note reflects my own observation rather than verified fact, it's called out as such.

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

**Why:** In a real system, an attack does not leave its traces in one place. A single SSH brute-force login leaves:
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

**What it is:** Bringing an event from the source to the collector. Two models:

| Model | Mechanism | Example protocol/port |
|---------|--------|----------------------|
| **Push (agent-based)** | An agent installed on the host reads files/events and pushes them to the manager | Wazuh agent → manager (UDP/TCP 1514); Filebeat → Logstash (5044) |
| **Pull / agentless** | The server pulls logs from the source, or receives them via syslog | Syslog UDP/TCP 514; WMI; SNMP; API polling (cloud) |

**Mechanism — Syslog (RFC 5424) at the byte level.** Because syslog is the most common collection medium, let us dissect one record:

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

> **Note:** RFC 3164 (the old BSD syslog) limits the message to ~1024 bytes and its timestamp has no year/timezone, which easily causes time skew during correlation. RFC 5424 allows longer messages (limited by the transport) and a full timestamp with timezone — this is why you should prefer 5424.

**Warning (when collecting):**
- Syslog UDP 514 does **not** authenticate, does **not** encrypt, and does **not** guarantee delivery → an attacker can spoof logs (log injection) or cause congestion to drop logs. Prefer TLS (RFC 5425, syslog over TLS, port 6514) or an encrypted agent channel.
- Lost logs = blindness. You must measure latency and packet drop rate.

### 8.2.2. PARSE (extract / decode)

**What it is:** Turning the free-text string (MSG) into discrete fields. This is where regex/grok/decoders operate.

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

**What it is:** Mapping the freshly parsed fields to **a common schema** so that events from many different sources can be compared/correlated. This is the point that distinguishes a real SIEM from a log-grepping tool.

Why: source A calls the source IP `src`, source B calls it `client_ip`, source C calls it `SourceAddress`. Without normalization you cannot write a single rule that "counts login failures by source IP" applicable to all three.

Example fields before/after normalization (per ECS — the Elastic Common Schema, or Wazuh's standard fields):

| Source | Original field | Normalized field (Wazuh) | Normalized field (ECS) |
|-------|-----------|--------------------------|------------------------|
| sshd | `from 203.0.113.5` | `srcip` | `source.ip` |
| Windows 4625 | `Source Network Address` | `srcip` / `data.win.eventdata.ipAddress` | `source.ip` |
| nginx | `$remote_addr` | `srcip` | `source.ip` |

### 8.2.4. ENRICH

**What it is:** Adding context not present in the original log:
- **GeoIP:** `203.0.113.5` → country=US, ASN=AS64500. (Wazuh supports GeoIP through dashboard/indexer integration with the GeoLite2 mmdb.)
- **Threat intel:** cross-referencing IPs/hashes against IoC feeds (for example AlienVault OTX, AbuseIPDB) → flagging as `malicious`.
- **Asset context:** host `web01` belongs to the "production-dmz" group, owner = team-web.
- **Vulnerability context:** this host has an open CVE-2024-XXXX.

### 8.2.5. CORRELATE

**What it is:** The detection logic. Two kinds:

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

Why distinguish them: these categories are often blended by marketing, but their position in the architecture and the data they see are different.

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

### 8.5.1. The two ports and why they are separated

| Port | Protocol | Listening daemon | Purpose |
|------|-----------|-------------|----------|
| **1515/TCP** | TLS | `wazuh-authd` | **Enrollment** (registering the agent, issuing the key) — used only once when the agent joins |
| **1514/UDP or TCP** | Shared-key encryption (Blowfish/AES depending on configuration) | `wazuh-remoted` | **Data transmission** of events, continuous |
| **1516/TCP** | — | `wazuh-clusterd` | Communication between managers in a cluster |
| **55000/TCP** | HTTPS | `wazuh-apid` | Management API (RBAC, JWT) |

**Why enrollment (1515) is separated from data (1514):** Enrollment is a sensitive operation (handing over a key). Separating the ports lets an administrator enable `authd` only during the registration window and then disable it, reducing the attack surface. The 1514 data channel uses the symmetric key that was already exchanged, optimized for high throughput and either stateless (UDP) or reliable (TCP).

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

**Warning:**
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
    <logall>no</logall>                       <!-- do not save every event to the archives -->
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>      <!-- only write an alert when rule level >= 3 -->
    <email_alert_level>12</email_alert_level> <!-- send email when level >= 12 -->
  </alerts>
```

| Parameter | Example value | Meaning | Why |
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

> **Note:** Always run `wazuh-analysisd -t` before restarting in production. A syntax error in `local_rules.xml` prevents analysisd from starting → total blindness.

---

## 8.7. DECODER — extracting fields from real logs

### 8.7.1. What it is

A **decoder** is an XML rule that tells `wazuh-analysisd` how to extract fields (srcip, srcuser, ...) from a raw log line. The decoder does *not* generate an alert — it only prepares the data for rules.

Paths:
- Base decoders: `/var/ossec/ruleset/decoders/*.xml` (do not edit — overwritten on update).
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

### 8.7.3. Real-world example — the SSH decoder (already built into Wazuh, dissected here)

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
- `<prematch>`: requires the line to begin with `Failed password for invalid user`. If it does not match → skip, saving CPU (why: the full regex is expensive, the prematch is a cheap filter gate).
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

### 8.7.4. Example — writing a custom decoder for a self-defined application log

> **[DEMO]** The decoder below only illustrates the parent/child + `<order>` mechanism; test it with `wazuh-logtest` and anchor the regex before using it in production.

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

**Warning:** A bad decoder (greedy regex, missing the `^` anchor) can extract the wrong field or slow analysisd under heavy load → an indirect DoS. Always anchor your regex and test with `wazuh-logtest` before deploying.

---

## 8.8. RULE — detection and classification

### 8.8.1. What it is

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

### 8.8.4. Example — a stateless rule mapped onto the paywall decoder from 8.7.4

> **[DEMO]** A sample rule for the `paywall` decoder above — it illustrates the `<field>` structure, `level`, and MITRE mapping; adjust the `level` and conditions to your environment before real use.

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

### 8.8.5. Key example — brute-force correlation (frequency + timeframe)

This is the classic stateful example: many login failures from the same IP within a time window → a single brute-force alert.

> **[DEMO]** A correlation rule illustrating the `frequency`+`timeframe`+`same_source_ip` mechanism; the thresholds must be tuned to real traffic (see the tuning process in 8.14). Attaching the `T####` code is covered in detail in [Chapter 15](#sec-15).

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

**Mechanism (the analysisd state machine):**

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

**Why the `frequency`+`timeframe`+`same_source_ip` design:**
- `same_source_ip` is the *group key*: without it, 8 failures from 8 different IPs (for example mild distributed password spraying) would be lumped together incorrectly. With it, we split the buckets by IP to correctly detect concentrated brute-force.
- `timeframe` defines the "speed" — distinguishing brute-force (8 times in 2 minutes) from 8 failures scattered across the whole day (a user who forgot their password).

> Other group keys: `<same_source_user/>`, `<same_destination_ip/>`, `<different_source_ip/>` (for distributed detection). In addition, `<if_matched_group>` allows counting by a rule *group* rather than a single SID.

### 8.8.6. Overriding and adjusting base rules (overwrite / `<if_sid>`)

Do not edit the base files; instead, in `local_rules.xml`:

> **[DEMO]** The override/exception example illustrates the `overwrite` and `<if_sid>` mechanisms; the trusted `srcip` range must be set to your real internal network.

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

### 8.9.1. What it is

**FIM (File Integrity Monitoring)** — the `syscheckd` module — detects changes to files/directories/registry: creation, modification, deletion. It is used to catch webshells, binary tampering, and modifications to sensitive configuration files.

### 8.9.2. Mechanism

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

**Why use a hash and not just mtime:** An attacker can `touch` a file to restore the mtime after editing it. A content hash (SHA-256) catches content changes even when metadata is forged. SHA-256 is chosen because it is more collision-resistant than MD5/SHA-1.

### 8.9.3. Example — `<syscheck>` configuration in `ossec.conf`

> **[PROD]** The configuration below is tight enough to use for a typical web host (realtime in the right places, noise exclusions, `<nodiff>` for sensitive paths); still review the `<directories>` list per system.

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

### 8.9.4. Example — a sample FIM alert (webshell)

When an attacker drops `shell.php` into `/var/www/html`, syscheck (realtime) generates an event that matches a base FIM rule (the `syscheck` group, rules 550–554), and alerts.json (for investigating such an alert, see [Chapter 10](#sec-10)):
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

**Warning:**
- `report_changes`/`nodiff`: do not store the diff of files containing secrets (private keys, `/etc/shadow`) — the diff stored in the Wazuh DB could leak secrets. Use `<nodiff>` for sensitive paths.
- Realtime on an extremely large directory (e.g. `/`) exhausts the kernel's inotify watches (`fs.inotify.max_user_watches`) → silent loss of monitoring. Use realtime only where it is needed.

---

## 8.10. Active Response — automated response

### 8.10.1. What it is

**Active Response (AR)** allows Wazuh to automatically run a command (script) when a rule matches — for example, blocking an attacking IP with a firewall. This is the integrated "mini-SOAR" capability, executed by `wazuh-execd` on the agent or the manager.

### 8.10.2. Mechanism (flow + state)

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

The AR script receives parameters via **stdin (JSON)** in Wazuh 4.x: comprising `command` (`add`/`delete`) and `parameters.alert` (the entire alert, which contains `srcip`). Why a timeout: blocking permanently risks a self-DoS (mistakenly blocking a legitimate IP, or a shared NAT IP) — the timeout allows automatic removal.

### 8.10.3. Real-world example — blocking a brute-force IP with firewall-drop

> **[DEMO]** The AR configuration below illustrates the automatic block/unblock flow; before enabling it in production you must have an allowlist of infrastructure IPs and restrict `<location>` (see the Warning at the end of this section).

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

**Warning:**
- **Anti self-DoS:** an attacker spoofs srcip = the IP of an internal gateway/DNS in the log to force Wazuh to block your own infrastructure. Always maintain an **allowlist** (the firewall-drop script has a mechanism to skip IPs on a whitelist); do not enable AR `all` for rules that are easily spoofed.
- AR runs with high privileges (iptables requires root) → the AR script is an attack surface; use only vetted scripts with tight file permissions.
- Prefer AR `local` over `all` to limit the impact.

---

## 8.11. Vulnerability Detection

### 8.11.1. What it is and the mechanism

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

### 8.11.2. Example — the old-style configuration (illustrating the principle)

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

### 8.11.3. Example — a sample CVE alert

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

**Note:** Vulnerability Detection reports a **potential vulnerability based on version**; it does not confirm actual exploitability (it does not always know whether the distro has backported a patch). You must cross-reference with reachability/exposure before prioritizing a patch — to avoid "CVE noise".

---

## 8.12. SCA — Security Configuration Assessment

### 8.12.1. What it is

**SCA** checks system configuration against a baseline (the CIS Benchmark, for example "SSH does not allow root login", "passwords must have a complexity requirement"). This module runs **policies** in YAML form on the agent and reports pass/fail for each check.

### 8.12.2. Mechanism — the structure of a policy check

An SCA policy (a YAML file in `/var/ossec/ruleset/sca/`) comprises `checks`, each check having `rules` evaluated by logic.

> **[DEMO]** The sample check below illustrates the `rules`/`condition` syntax; use Wazuh's official CIS policy directly rather than copying individual checks by hand.

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

### 8.12.3. Example — an SCA result on the dashboard / alert

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

**Note:** SCA is *configuration drift detection* — it runs periodically. A host that "passed 90%" may still have a 10% failure that is a serious vulnerability; read it check by check, not just by the total score.

---

## 8.13. MITRE ATT&CK integration

### 8.13.1. What it is

**MITRE ATT&CK** is a matrix that standardizes attacker techniques by Tactic (the objective) → Technique (the method). Wazuh attaches a technique code (`T####`, sub-technique `T####.###`) to rules, allowing the dashboard to display attacks by the matrix and to support threat hunting. How to map techniques and read the ATT&CK matrix is covered in [Chapter 15](#sec-15).

| Concept | Example |
|-----------|-------|
| Tactic | `Credential Access` (TA0006) |
| Technique | `T1110` Brute Force |
| Sub-technique | `T1110.001` Password Guessing |

### 8.13.2. Example — attaching MITRE to a rule (as seen in 8.8.5)

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

**Note:** Attaching the correct MITRE technique is part of detection engineering — attaching the wrong one distorts the coverage report (you think you have covered technique X but the rule actually catches something else).

---

## 8.14. Detection Engineering — writing and tuning rules, FP vs FN

### 8.14.1. FP and FN

| Concept | Definition | Consequence |
|-----------|------------|---------|
| **False Positive (FP)** | An alert fires but is not an attack | Analyst fatigue (alert fatigue), missing real alerts |
| **False Negative (FN)** | A real attack but no alert | Slips through — the most dangerous |
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

### 8.14.3. Example — tuning the brute-force rule to reduce FP

The problem: rule 100110 fires when a proxy/NAT makes many real users fail from the same srcip. Tuning:

> **[DEMO]** The tuned rule pair below illustrates FP-reduction techniques (changing the group key, excluding a NAT range); the IP ranges and thresholds must be changed to your real environment.

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

| Principle | Why |
|-----------|--------|
| Anchor your regex (`^`, `$`), match fields rather than substrings when possible | Avoids mismatches, faster |
| Place the `id` in 100000–120000 | Does not collide with base rules, not lost on update |
| Start at a low level, raise gradually | Avoids harm from active-response due to FPs |
| Document the `<description>` clearly with field interpolation | The analyst understands immediately during triage |
| Attach the correct `<mitre>` | Measures coverage |
| Have both positive and negative test cases | Ensures no FN and no FP |

### 8.14.5. Tuning lessons from real operations

A few things I learned after some time on duty with a real monitoring stack (not a lab):

- **Whitelist your internal admin IP ranges first.** Most of the repetitive authentication/web alerts turned out to come from the operations team itself: SSH over VPN, healthchecks, CI jobs. A conditional level-0 rule keyed on `srcip` for the admin range (exactly the pattern in 8.8.6) cuts the largest amount of noise for the least effort. Caveat: only whitelist admin/infrastructure ranges for the specific noisy rule groups — do not whitelist the whole office network for every rule type, because an office machine catching malware is entirely possible.
- **Standardize alert content: an alert must answer "which host, what, from where" on its own.** If the on-call person has to open the dashboard just to learn which host an alert fired on, the alert is not finished. Interpolate fields into `<description>` (`$(srcip)`, the agent name in the notification channel) — triage time drops noticeably.
- **Alert on resource symptoms, not only on logs.** I added an alert for abnormally sustained high CPU (from node_exporter metrics, or a `log_format command` entry running a periodic command) — cryptominers usually reveal themselves through CPU before they reveal themselves through any log line. The SIEM catches events; the metrics stack catches symptoms; the two sources complement each other (for metric monitoring see [Chapter 9](#sec-09)).

---

## 8.15. End-to-end example: SSH brute-force from raw log to dashboard alert

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

This alert is the starting point of the incident investigation/response process (see [Chapter 10](#sec-10)).

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

## 8.16. Investigating a real alert with Wazuh — a reusable process

The sections above describe the pipeline in the forward direction (logs flowing in and becoming alerts). This section goes the other way: **from one anomalous number on a dashboard back to the original evidence and a conclusion**. This is the process I used to investigate a real scanning campaign (mid-2026); system details have been stripped out, but the scanner's IP is a public scanning source, so I keep it as is. The end goal is to answer three questions — *what hit us, did it get through, what next* — with evidence, not gut feeling.

### 8.16.1. Step 1 — Detection from the dashboard: one source dominating

The starting point was a **Top source IPs** panel (mine is self-built in Grafana reading Wazuh's alert index; the Security Events module of the Wazuh dashboard offers an equivalent view). One IP — `45.148.10.80` — accounted for **536** alerts in the window, while the next sources trailed at 54, 51... The accompanying rule groups: `web`, `attack`. An unfamiliar source (not an office/partner range) producing ~90% of the attack-group alerts → investigate immediately.

The lesson right at this step: the dashboard does not answer questions — it only **points at where to ask**. Every conclusion that follows comes from queries.

### 8.16.2. Step 2 — Scoping with Dev Tools: three aggregation queries

The Wazuh dashboard has **Dev Tools** (a console that sends queries straight to the indexer — OpenSearch/Elasticsearch DSL syntax) against the `wazuh-alerts-*` index. Three aggregations answer three scoping questions.

**(a) Which hosts is it hitting?** — `terms` on `agent.name`:

```json
GET wazuh-alerts-*/_search
{"size":0,"query":{"term":{"data.srcip":"45.148.10.80"}},
 "aggs":{"by_agent":{"terms":{"field":"agent.name","size":10}}}}
```

Result: all 536 alerts sat on **a single dev machine running a web API** (nginx as the reverse proxy, exposed to the Internet). The scope collapsed to exactly one host.

**(b) Which rules is it triggering?** — `terms` on `rule.id`:

```json
GET wazuh-alerts-*/_search
{"size":0,"query":{"term":{"data.srcip":"45.148.10.80"}},
 "aggs":{"rules":{"terms":{"field":"rule.id","size":15}}}}
```

Result: `31516` (suspicious URL — 230), `31104` (web attack pattern — 218), `31151`/`31153` (many 400/404 errors) — all in the "probed and refused" family. Just as important is the rule that did **not** appear: no `31106` — the rule for a "web attack **returning 200**" (i.e., an attack the server answered successfully). This absent detail is the crux of the conclusion step (8.16.5). These IDs belong to Wazuh's default web access-log ruleset — cross-check against the ruleset version you actually run (needs verification).

**(c) What is the tempo?** — `date_histogram` on `timestamp`:

```json
GET wazuh-alerts-*/_search
{"size":0,"query":{"term":{"data.srcip":"45.148.10.80"}},
 "aggs":{"timeline":{"date_histogram":{"field":"timestamp","fixed_interval":"5m"}}}}
```

Result: it opened with a single stray request (a probe), climbed ~35 minutes later to a peak of **58 requests per 5 minutes** (roughly one request every 5 seconds), held that steady rhythm for ~2 hours, then went silent. A rhythm that steady is not a human clicking through a browser — it is an automated scanner. This observation later became the technical basis for proposing rate-limiting at the reverse proxy.

### 8.16.3. Step 3 — Reading the original evidence: the `full_log` field

Aggregations give you the *shape* of the incident; for *evidence* you must read a full document:

```json
GET wazuh-alerts-*/_search
{"size":1,"query":{"bool":{"filter":[
   {"term":{"data.srcip":"45.148.10.80"}},{"term":{"rule.id":"31516"}}]}},
 "_source":["timestamp","rule.description","full_log","data.url","GeoLocation"],
 "sort":[{"timestamp":"desc"}]}
```

The `full_log` field preserves the access-log line exactly as the agent read it:

```
45.148.10.80 - - [20/Jul/2026:16:50:30 +0000] "GET /....//....//....//....//....//home/admin/.ssh/id_rsa?_=mknzjth2&v=zte2h HTTP/1.1" 301 178 "https://www.bing.com/search?q=3x4et6" "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15"
```

One detail worth dwelling on: when I SSHed into the machine to `grep` this IP in `/var/log/nginx/access.log`, there was **not a single line left** — the events had happened the previous day and the log had rotated (logrotate). But the centralized SIEM still held `full_log` in the index. This was the moment I saw the value of centralized logging with my own eyes: **the evidence does not depend on whether the raw log on the host still exists** — and even if an attacker wipes the logs on the host, they cannot wipe the copy already in the index. (You can still cross-check the original on the machine: `sudo zgrep 45.148.10.80 /var/log/nginx/access.log.*` against the compressed files.)

### 8.16.4. Step 4 — Interpreting the log line: what it is doing, what it is after

Read the log line part by part (combined with a `terms` on `data.url` to see the full list of probed paths):

```json
GET wazuh-alerts-*/_search
{"size":0,"query":{"term":{"data.srcip":"45.148.10.80"}},
 "aggs":{"urls":{"terms":{"field":"data.url","size":25}}}}
```

| Observed component | Assessment |
|---|---|
| `/....//....//....//home/admin/.ssh/id_rsa` | **Path traversal** — trying to escape the web root to read system files |
| `....//` and (in other requests) `%252e%252e` | **Double encoding** — evading filters that only catch a plain `../` |
| Targeting `.ssh/id_rsa`, `.ssh/id_ed25519`, `.env`, `.mysql_history` | Hunting **SSH keys + application secrets + DB history** — any hit is a jackpot |
| Trying `root/admin/ubuntu/deploy/ec2-user/git/www-data` in turn | Probing a **wordlist of common users** — automated behavior |
| Status codes all `301`/`400`/`404` | The proxy/app **refused everything**; no sign of leakage |
| Referer `https://www.bing.com/search?q=...` (random string) | **Fake referer** — disguised as search-engine traffic |
| Rotating User-Agents (Safari/Mac, Chrome/Windows, Android...) | **UA rotation** — an automated tool evading UA-based blocking |
| GeoIP: a VPS at a foreign hosting provider | Not a real user of the system |

### 8.16.5. Step 5 — Concluding from the rules that did and did not appear

My conclusion of "**not breached**" stood on two legs of evidence:

1. Every rule that fired belonged to the "probed and refused" family (suspicious URL, 400/404); the "**web attack returning 200**" rule group — the signature of a *successful* attack — was entirely absent for this IP.
2. The status codes in the sampled `full_log` lines were all 301/400/404, consistent with (1).

Two notes on the reasoning:

- **The absence of an alert is not the absence of an incident** — the conclusion is only valid within the telemetry currently collected (if decoders/rules do not cover some attack form, the SIEM stays silent even when something happens). So state the conclusion with its scope: "in the alert data available, no sign of success."
- It was precisely by using the "returns 200" criterion that, when widening to the whole fleet (step 6), I found a small group of "attack returning 200" alerts **elsewhere** — which was split off into its own high-priority investigation. A good investigation typically spawns new, well-scoped work items instead of expanding without bounds.

### 8.16.6. Step 6 — Widening out: from one IP to the fleet picture

Drop the IP filter, keep the rule-group filter — ask three questions at fleet scale:

```json
GET wazuh-alerts-*/_search
{"size":0,"query":{"terms":{"rule.groups":["attack"]}},
 "aggs":{"ips":{"terms":{"field":"data.srcip","size":20}}}}
```

The result completely changed the picture: the IP under investigation ranked only **third** by alert count; above it were sources with thousands of alerts, and many IPs came in **subnet clusters** (`185.177.72.x` with five distinct addresses, `45.148.10.x`, `195.178.110.x`...). Likewise, a `terms` on `agent.name` (filtered on `rule.groups: ["attack","web"]`) showed that **every web-facing machine was being scanned**, not just the initial one; and a `terms` on `rule.description` revealed further attack types (PHP CGI-bin probes, POST floods, blacklisted UAs) along with a large volume of 500 errors — the scanning was making the app throw internal errors, i.e., it was already affecting stability even without a breach.

The consequence for response: **blocking IPs one by one is "whack-a-mole"** — scanners rotate addresses across whole ranges. The right-layer measures are controlling *behavior* at the reverse proxy (rate limiting, blocking sensitive file names, a `default_server` that cuts off unknown Hosts) and shrinking the attack surface (dev environments should not be publicly exposed); for network-layer defense and WAFs see [Chapter 11](#sec-11).

### 8.16.7. Method summary — a reusable checklist

| Step | Question | Tool / Query |
|------|----------|--------------|
| 1. Detect | Is any source/group anomalous? | Dashboard (Top source IPs, Security Events) |
| 2. Scope | Which host? Which rules? What tempo? | `terms` on `agent.name`, `rule.id` + `date_histogram` on `timestamp`, filtered on `data.srcip` |
| 3. Evidence | What is it actually sending? | Read a full document, the `full_log` field (+ `data.url`, `GeoLocation`) |
| 4. Interpret | What technique, targeting what? | Read the log line part by part; `terms` on `data.url` |
| 5. Conclude | Did it get through? Where is the evidence? | Presence/absence of "success" rules + status codes; state the conclusion with its telemetry scope |
| 6. Widen | Only this IP? Only this host? | Drop the srcip filter; aggs on `data.srcip` / `agent.name` / `rule.description` over the `attack`/`web` groups |

---

## 8.17. SOAR — automation on top of the SIEM

### 8.17.1. What SOAR is and what problem it solves

**SOAR (Security Orchestration, Automation and Response)** is a platform that receives alerts from the SIEM and runs **playbooks** (predefined processing flows): enriching alerts with external data sources, notifying, opening cases, and — once the process has matured — executing responses.

The root problem: even a well-tuned SIEM produces alerts **faster than humans can read them**. My observation while on duty: most of the time spent triaging a web alert goes not into judgment but into repetitive motions — copy the source IP → open 2–3 tabs to check its reputation → look at the results → decide to dismiss or dig further. A machine can do that entire chain, and SOAR exists precisely for it: **automate the repetitive part, save the humans for the judgment part**.

### 8.17.2. Choosing a tool: Shuffle vs TheHive vs n8n

| Tool | Nature | Strength | Consideration |
|------|--------|----------|---------------|
| **Shuffle** | Open-source SOAR, drag-and-drop workflows, a security-oriented app/connector store | Built for the SOC use case: ready-made apps for Wazuh and popular threat-intel sources; easy webhook ingestion | Smaller community than n8n; UI/docs still rough in places |
| **TheHive (+ Cortex)** | A **case-management** platform + an observable-analysis engine (Cortex analyzers) | Case lifecycle management, assignment, evidence storage — a SOC process in the true sense | Heavy for a first-stage "just enrich + notify" need |
| **n8n** | General-purpose automation (not security-specific) | A huge number of connectors; any developer can use it | No native alert/case/observable concepts — you build the security part yourself |

For a first stage, **Shuffle** is the sensible pick: the immediate problem is *enrich + notify* (exactly its home turf), while TheHive-style case management is reserved for the stage when the process has stabilized. n8n fits when the team already uses it for general automation and only needs a few simple security flows.

### 8.17.3. Wazuh → SOAR architecture: filter before you push

```
Wazuh manager ──(integration/webhook, ONLY alerts level ≥ N)──▶ SOAR (Shuffle)
                                                                  │
                                           ┌──────────────────────┤
                                           ▼                      ▼
                                 [IP-enrichment playbook]  [other playbooks...]
                                           │
                                           ▼
                                 ops chat channel (with a link back to the original alert in the SIEM)
```

The most important design point sits right next to Wazuh: **filter by severity before pushing**. Only alerts from a certain level upward (e.g. ≥ 7) go to the SOAR; push everything and the SOAR becomes a noisy mirror of the SIEM while your threat-intel API quota evaporates within an afternoon. Wazuh supports this with the `<integration>` block in `ossec.conf` — calling a webhook when an alert meets the condition:

```xml
<integration>
  <name>custom-soar</name>                    <!-- a custom-* script in /var/ossec/integrations/ -->
  <hook_url>https://soar.example.internal/api/v1/hooks/webhook_xxx</hook_url>
  <level>7</level>                            <!-- only push alerts level >= 7 -->
  <alert_format>json</alert_format>
</integration>
```

(Besides `<level>` you can also filter by `<rule_id>` / `<group>`; cross-check the syntax against the version you run — needs verification.)

### 8.17.4. The first playbook: enrich the IP + notify

The enrichment flow I actually run, in order:

```
alert JSON from Wazuh
   │
   ▼
1. Extract data.srcip
2. Filter: is the IP public?
      ├─ private (RFC 1918) / our own infrastructure IPs → stop (threat-intel lookups on private IPs are both meaningless and quota-burning)
      └─ public → continue
3. Query two threat-intel sources in parallel:
      ├─ an AbuseIPDB-style source  → abuse confidence score (0–100), report count, ISP, usage type
      └─ a VirusTotal-style source  → how many engines flag it malicious
4. Assemble a standardized message: WHICH HOST, which rule (id + description), the IP, the score, the engine-flag count
5. Notify the ops chat channel — always with a link back to the original alert in the SIEM
```

The value showed within the first week: **distinguishing scanners with a track record from legitimate access flagged by mistake**. For the very same brute-force alert, an IP with a 100% confidence score and thousands of reports is a completely different story from an IP with a score of 0 that turns out to be a partner who changed network ranges. The on-call person can decide from the message alone, without opening three tabs for manual lookups — alert noise drops in the true sense of "lowering the cost of handling one alert," not by hiding alerts.

### 8.17.5. Principle: SOAR is a supplementary layer, not a SIEM replacement

- **The original alert and its evidence stay in the SIEM.** The SOAR only keeps a copy for its playbooks. If the SOAR dies, you lose convenience, not data; every notification carries a path back to the SIEM for deep investigation (the process in 8.16).
- **Do not rush into automated response.** The roadmap I follow: (1) enrich + notify — the machine only *reads*, it does not *act* yet; (2) case management (TheHive-style) once the number of incidents worth tracking grows; (3) response with **human approval** — the playbook stages the action (block an IP, isolate a host) and a human clicks approve; (4) only at the end, full automation for a narrow set of very-high-confidence situations — in exactly the same spirit as Active Response (8.10): an infrastructure allowlist + a self-removing timeout.

---

## 8.18. Operational summary & Wazuh security checklist

| Item | Recommendation |
|----------|-------------|
| Data transmission | TCP 1514 + `crypto_method aes`; enroll over 1515 with a password/CA |
| `client.keys` | Tight permissions, no leaks; stable, unique agent names |
| Custom rules/decoders | Only in `local_*.xml`, ids 100000+, test with `wazuh-logtest` & `analysisd -t` before restart |
| FIM | Realtime in the right places; `<nodiff>` for paths containing secrets; watch the `inotify` watches |
| Active Response | Allowlist infrastructure IPs; prefer `local`; use `timeout` for auto-removal; tight script permissions |
| Vuln/SCA | Cross-reference the version against the correct feed; read by individual CVE/check, not just the total score |
| Storage | `logall=no` unless doing forensics; a clear retention policy (hot/warm/cold) |
| Tuning | A loop measuring FP/FN; raise the level gradually; review periodically; whitelist admin ranges for the right rule groups |
| SOAR | Filter by level before pushing; the original alert always stays in the SIEM; automated response comes after human approval |
| API 55000 | Change default credentials, enable RBAC, restrict the network |

---

*End of Chapter 8.*


---

## My notes

> *Personal notes: points I previously misunderstood, areas I'm still exploring, or lessons from hands-on practice — updated over time.*

- When I first studied SIEMs, I thought their value lay in pretty dashboards and real-time alerts. After my first investigation of a real scanning campaign (section 8.16), I saw that the biggest value lies elsewhere: **the ability to ask questions of centralized data**. The dashboard only points at the anomaly; the entire conclusion came from a few aggregation queries on `wazuh-alerts-*`.
- My most expensive lesson about centralized logging: when I SSHed into the machine to grep the access log, it had already rotated — **not a single line left** — yet `full_log` in the index preserved every line of evidence intact. If my monitoring had been "SSH in and read the logs when something happens," I would have been left with nothing. Centralized logging is not for show — it is the only place where evidence survives logrotate (and an attacker wiping logs on the host).
- I used to assume the correct response to an attacking IP was to block it. Only when I dropped the IP filter and aggregated on `data.srcip` across the fleet — and saw dozens of IPs arriving in whole subnet clusters — did I understand why blocking IPs one by one is "whack-a-mole." My ordering is different now: shrink the attack surface (dev environments not publicly exposed) → control behavior at the proxy (rate limiting, blocking sensitive file names) → and only then IP blocking, as a stopgap.
- The surprise when I wired the SIEM into a threat-intel enrichment flow (8.17): the first value was not "catching more attackers" but **quickly telling scanners with a track record apart from false positives** — an IP with a 100% confidence score and thousands of reports is nothing like an IP with a score of 0 that turns out to be legitimate access. It spared us a lot of "whose IP is this?" debates in the ops channel.
- A "not breached" conclusion I dare to put into a report is one standing on two legs of evidence: the "attack returning 200" rules were absent *and* the status codes in `full_log` agreed. I also learned to state conclusions with their scope ("within the telemetry available...") — the absence of an alert is not the absence of an incident.
- Still exploring: automatic IP blocking by threshold using fail2ban combined with Wazuh (still at the research stage — I have not dared enable it for fear of self-DoS, see the warning in 8.10); introducing case management once the number of incidents worth tracking grows; and a WAF (ModSecurity + OWASP CRS) as the layer that blocks traversal thoroughly, which plain nginx cannot.
