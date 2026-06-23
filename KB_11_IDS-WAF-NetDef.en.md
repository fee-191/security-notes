# Chapter 11 — Network Defense: IDS/IPS, WAF, Firewall & VPN

## Overview

This chapter covers the technical controls used to **protect a computer network**: detecting reconnaissance/attack activity, blocking malicious traffic, and establishing secure transport channels across public infrastructure. The problem being addressed: every service (website, internal system, trading exchange) exposes an attack surface once it is connected to the network, and no single control covers everything. Each tool below operates on a different data layer and a different class of threat; combining them yields defense in depth.

### Defense in depth

- **Definition.** A model that stacks multiple independent layers of control (packet filtering, access control, encryption, monitoring) instead of relying on a single layer. If one layer is bypassed, the next layer is still in effect.
- **Problem solved.** No single layer is perfect. Each device "reads" a different scope of data (some devices only see L3/L4 addresses, others can read L7 content), so multiple devices must be combined to cover all the layers.

### IDS and IPS

- **IDS (Intrusion Detection System).** Monitors traffic out-of-band, generating alerts when it detects suspicious indicators, but it does not act on the packets themselves.
- **IPS (Intrusion Prevention System).** Sits inline on the data path, both detecting and blocking (dropping/resetting) malicious traffic; the accompanying risk is false positives that wrongly block traffic and disrupt service.
- **Problem solved.** The two models make different trade-offs between availability and enforcement. In practice, you deploy an IDS (alert mode) first to tune down false positives, then switch to IPS (inline-block).

### NIDS and HIDS

- **NIDS (Network IDS).** Analyzes traffic on the wire at the network edge/core; sees all traffic between hosts but is blind to encrypted traffic without the keys.
- **HIDS (Host IDS).** Runs on each host, observing syscalls, file integrity, logs, and processes; sees the internal behavior of one host in detail but cannot see other hosts.
- **Problem solved.** The two viewpoints complement each other: NIDS catches lateral movement/scanning, HIDS catches persistence/privilege escalation. Combining both is what gives the full picture.

### Snort and Suricata

- **Definition.** Two **signature**-based IDS/IPS engines: they match traffic against data patterns characteristic of known attack types.
- **Problem solved.** Many attacks have recurring indicators that the community has already recorded; a signature set allows fast and accurate detection of familiar attacks. Limitation: a new attack that has no signature yet will slip through — this needs to be supplemented with behavior-based monitoring tools.

### WAF, ModSecurity and OWASP CRS

- **WAF (Web Application Firewall).** A firewall operating at the application layer (L7): it parses and inspects HTTP content (method, URI, headers, body, parameters) to block attacks aimed at the application (for example, SQL injection).
- **ModSecurity.** A popular open-source WAF engine that runs embedded in Apache/NGINX or on a reverse proxy.
- **OWASP CRS (Core Rule Set).** A standard, prebuilt rule set loaded into ModSecurity, which avoids having to build a rule set from scratch.
- **Problem solved.** An L3/L4 firewall does not understand application content, so it cannot distinguish a legitimate request from one carrying an attack payload. The WAF fills that gap at the L7 layer.

### Firewall and pfSense

- **Firewall.** A device/software that decides whether to allow or block a packet based on L3/L4 rules (source/destination IP, protocol, port).
- **pfSense.** An open-source firewall/router platform based on FreeBSD and `pf`, which turns an ordinary machine into a gateway device for an entire network. **Stateful** means it remembers the state of ongoing connections to match reply packets without needing a reverse rule.
- **Problem solved.** This is the cheapest and fastest blocking layer, placed at the outermost edge to discard clearly invalid traffic before it reaches the deeper layers. pfSense also handles network segmentation (VLANs) and serves as a VPN connection point.

### VPN — IPsec, OpenVPN, WireGuard

- **VPN (Virtual Private Network).** An encrypted tunnel running over public infrastructure: the original packet is wrapped and protected for confidentiality + integrity before transmission, so even a third party that intercepts it cannot read or modify it.
- **IPsec / OpenVPN / WireGuard.** Three technologies that implement tunnels with the same goal but differing in how they exchange keys and in their complexity: IPsec is the long-standing standard with many options; OpenVPN is flexible and easy to traverse firewalls; WireGuard is lightweight, high-performance, and easy to audit.
- **Problem solved.** A remote employee or two branch offices need to connect securely over the Internet as if they were on the same private network.

### Proxy and reverse proxy

- **Forward proxy.** Acts on behalf of the client when reaching out: the destination server only sees the proxy, not the client. Used for anonymity, content filtering, and egress access control.
- **Reverse proxy.** Acts on behalf of the server: it receives all connections from outside and then forwards them to the appropriate backend; the client never sees the real server.
- **Problem solved.** A reverse proxy is the ideal place to attach a WAF (it has terminated TLS and can read plaintext), while also load balancing and hiding the backend to reduce the attack surface.

### Zeek

- **Definition.** A network security monitor (NSM) that produces context-rich logs for every connection and protocol event (who connected to whom, when, with what protocol, for how long), in contrast to the signature-matching model of Snort/Suricata.
- **Problem solved.** Incident investigation needs detailed logs for tracing, even for attacks that have no signature yet. Snort/Suricata alert quickly; Zeek provides the full context for threat hunting and post-incident analysis.

> This chapter is a technical reference for Blue Team / AppSec / DevSecOps engineers. The goal: dig down to the field/byte/step level, with practical, runnable examples for each tool. The protocol-structure numbers follow the corresponding RFCs (IPv4 RFC 791, TCP RFC 9293, IPsec/ESP RFC 4303, IKEv2 RFC 7296, the WireGuard whitepaper, the OpenVPN protocol). Where a number depends on a specific version/implementation, the chapter notes "verify against your version."

---

## 11.1. The network defense model and where IDS/IPS/WAF fit

### 11.1.1. Defense in depth and a map of the OSI layers

Every defensive device acts at one (or more) OSI layers. Understanding precisely how far down into a packet a device can "read" is the root of knowing what it can block and what it is blind to.

| OSI layer | Data unit (PDU) | Device reads up to | Decision based on |
|---|---|---|---|
| L2 Data Link | Frame (Ethernet) | Switch, MACsec | MAC src/dst, 802.1Q VLAN tag |
| L3 Network | Packet (IP) | Router, L3 firewall (packet filter) | IP src/dst, protocol number |
| L4 Transport | Segment (TCP) / Datagram (UDP) | Stateful firewall (pfSense/pf), L4 LB | Port, TCP flags, connection state |
| L5-L7 App | Message (HTTP, DNS, TLS) | WAF (ModSecurity), L7 proxy, NGFW DPI | URI, header, body, application signature |

**Why:** an L3/L4 firewall only sees `IP/port/flags`, so it can allow `tcp dst port 443` but has absolutely no idea whether that HTTPS flow contains `UNION SELECT`. That is why the WAF exists — it has to terminate TLS (TLS termination) to read the plaintext HTTP. Conversely, a WAF is ineffective at blocking a SYN flood, because that should be stopped at L3/L4 before resources are spent decrypting TLS.

### 11.1.2. IDS vs IPS

| Criterion | IDS (Detection) | IPS (Prevention) |
|---|---|---|
| Role | Detect + alert | Detect + block |
| Network position | Out-of-band (SPAN/TAP) | Inline (packets pass through) |
| Effect on packets | None (copy only) | Yes (drop/reset/modify) |
| Risk when wrong | False negative = missed detection | False positive = wrongly blocked legitimate traffic |
| Availability risk | No effect on the link if the IDS dies | Single point of failure; needs fail-open/fail-close |
| Latency | 0 (in parallel) | Adds processing latency to every packet |

**Why:** the distinction matters because an IPS sits on the data path, so a bad rule (a catastrophic regex, or a drop based on anomalies) can cause a loss of service. An IDS is safer for availability but is only useful when there is a response process (SOAR/SOC). In practice you typically deploy the IDS first (tuning rules in alert mode), and only after reducing false positives do you switch to IPS (inline-block).

### 11.1.3. NIDS vs HIDS

- NIDS (Network IDS): placed at the network edge/core, analyzing packets on the wire (Snort, Suricata, Zeek). Sees all traffic but is blind to encrypted traffic without the keys.
- HIDS (Host IDS): runs on the host, seeing syscalls, file integrity, logs, processes (OSSEC/Wazuh, auditd, Sysmon, Falco). Can see behavior after decryption (e.g., a shell command), but only sees that one host.

NIDS and HIDS complement each other: NIDS catches lateral movement/scanning; HIDS catches persistence/privilege escalation. A SIEM aggregates both.

### 11.1.4. Packet capture: inline vs SPAN vs TAP

```
SPAN (port mirroring):  Switch copies traffic from the ports → 1 monitor port → NIDS
   Pro: cheap, software config.  Con: an overloaded switch will DROP the copy first (packet loss), does not see physical-layer errors, and the copy may discard CRC-error frames.

TAP (Test Access Point): a hardware device cut into the wire, copying 100% of the bits (including errors).
   Pro: full-fidelity, fail-safe.  Con: consumes ports (separate TX/RX in two directions needs aggregation), requires cutting the cable.

INLINE (IPS): traffic passes THROUGH the device.  Can drop. But is a potential point of failure / chokepoint.
```

**Note:**
- With full-duplex 10G traffic, a TAP splits RX/TX into two 10G flows; the NIDS needs a NIC that receives 20G in total, or a packet broker to aggregate.
- SPAN on the same switch can silently drop packets under high load, missing an attack without anyone knowing.

---

## 11.2. Snort & Suricata — signature-based NIDS/IPS

### 11.2.1. The packet-processing architecture

Both Snort (2.x/3.x) and Suricata divide the pipeline into stages:

```
[ Capture ] → [ Decode L2/L3/L4 ] → [ Preprocessors / App-layer parsers ]
   → [ Detection engine: rule matching ] → [ Output: alert/log/drop ]
```

- Decode: parse Ethernet → IP → TCP/UDP, build a struct describing the packet.
- Preprocessors (Snort) / app-layer (Suricata): reassemble the TCP stream (stream reassembly), defend against evasion via IP fragmentation (frag3), normalize HTTP (http_inspect), decode, and track flow state.
- Detection engine: uses a multi-pattern algorithm (Aho-Corasick) to match the `content` of thousands of rules in parallel, and only then runs the expensive `pcre` on the rules that passed the fast content step.

**Why** put `content` before `pcre`: regex is CPU-intensive; the engine uses `content` (fixed-string matching via Aho-Corasick, O(n)) as a "fast pattern" to quickly eliminate the majority of packets, so only packets containing that string incur the regex cost. This is why every good rule should have at least one `content` to provide a fast pattern.

Key difference: Suricata is multi-threaded by design, supports compatibility with most of the Snort rule syntax, adds `app-layer` keywords (http.uri, tls.sni, dns.query), and exports EVE JSON. Snort 3 has also been rewritten to be multi-threaded. The rule syntax below is compatible with both unless noted otherwise.

### 11.2.2. The structure of a rule — broken down part by part

A rule consists of a RULE HEADER + RULE OPTIONS (in parentheses).

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 ( msg:"..."; content:"..."; sid:1000001; rev:1; )
└─┬─┘ └┬┘ └─────┬──────┘└┬┘ └┬┘ └──┬───┘ └┬┘  └────────────── OPTIONS ──────────────┘
action proto   src_ip  sp dir dst_ip dp
```

#### Rule Header — each field

| Field | Valid values | Meaning | Example |
|---|---|---|---|
| action | alert, log, pass, drop, reject, sdrop | Action taken on a match | `alert` (log+alert), `drop` (block, inline IPS only) |
| protocol | tcp, udp, icmp, ip (Suricata adds: http, tls, dns, ssh...) | Protocol | `tcp` |
| src_ip | IP/CIDR, the `$HOME_NET` variable, a list `[a,b]`, negation `!` | Source | `$EXTERNAL_NET`, `![10.0.0.0/8]` |
| src_port | a number, a range `1:1024`, `any`, `!80`, `[80,443]` | Source port | `any` |
| direction | `->` one-way, `<>` two-way | Direction | `->` |
| dst_ip | same as src_ip | Destination | `$HOME_NET` |
| dst_port | same as src_port | Destination port | `80` |

The actions in detail:
- `alert`: generate an alert and log the packet.
- `log`: log only, no alert.
- `pass`: skip the packet (whitelist), stop further evaluation.
- `drop` (inline): block the packet + log. Sends nothing to the client.
- `reject`: block + send a TCP RST (or ICMP unreachable for UDP) to close the connection immediately.
- `sdrop`: silent drop, block without logging.

The variables `$HOME_NET`, `$EXTERNAL_NET` are defined in `snort.conf`/`suricata.yaml`:
```
ipvar HOME_NET [10.0.0.0/8,192.168.0.0/16,172.16.0.0/12]
ipvar EXTERNAL_NET !$HOME_NET
portvar HTTP_PORTS [80,81,8080,8000]
```

#### Rule Options — full reference table

| Option | Type | Meaning | Example |
|---|---|---|---|
| `msg` | metadata | Descriptive string written into the alert | `msg:"SQLi UNION SELECT";` |
| `content` | payload | Match a byte string (text or hex `\|41 42\|`) | `content:"UNION";` |
| `nocase` | modifier | content is case-insensitive | `content:"union"; nocase;` |
| `offset` | modifier | Start searching for content from byte N (0-based) | `offset:4;` |
| `depth` | modifier | Search only within the first N bytes (from the offset) | `depth:20;` |
| `distance` | modifier | Minimum distance after the previous content | `distance:0;` |
| `within` | modifier | The next content must fall within N bytes after the previous content | `within:10;` |
| `pcre` | payload | Perl-compatible regex | `pcre:"/union\s+select/i";` |
| `flow` | state | Flow direction/state | `flow:established,to_server;` |
| `flowbits` | state | Set/check a flag on the flow (correlate across packets) | `flowbits:set,logged_in;` |
| `threshold`/`detection_filter` | rate | Limit alert frequency | `detection_filter:track by_src, count 5, seconds 60;` |
| `sid` | metadata | Signature ID (unique; >1,000,000 for local) | `sid:1000001;` |
| `rev` | metadata | The rule's revision number | `rev:1;` |
| `classtype` | metadata | Classification (maps to priority) | `classtype:web-application-attack;` |
| `reference` | metadata | A CVE/URL link | `reference:cve,2021-44228;` |
| `priority` | metadata | Manual priority (1 highest) | `priority:1;` |
| `http_uri`/`http.uri` | sticky buffer | Restrict content to the normalized URI | `http.uri; content:"/admin";` |
| `dsize` | payload | Payload size | `dsize:>100;` |
| `byte_test`/`byte_jump` | payload | Compare/jump based on byte values | `byte_test:2,>,1000,0;` |

Explaining `offset`/`depth` and `distance`/`within` (very commonly confused):
- `offset`/`depth` measure ABSOLUTELY from the start of the payload. `offset:4; depth:20;` = search within bytes 4..23.
- `distance`/`within` measure RELATIVE to the end of the previous content's match. Use them to match several fragments close together without knowing the absolute position.

**Why** have both: a real payload has a fixed-length header portion (use offset/depth) and a variable portion that needs relative matching (use distance/within). Constraining the search region also reduces false positives and speeds things up.

### 11.2.3. A real rule example — explaining each parameter

Detecting a `UNION SELECT` SQLi in an HTTP request:
```
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"WEB SQLi UNION SELECT in URI";
    flow:established,to_server;
    http.uri;
    content:"union"; nocase;
    content:"select"; nocase; distance:0; within:100;
    pcre:"/union\s+(all\s+)?select/i";
    classtype:web-application-attack;
    reference:url,owasp.org/sqli;
    sid:1000001; rev:2;
)
```
- `flow:established,to_server`: only consider packets in a TCP connection that has completed its handshake, in the client→server direction. Avoids matching on a single spoofed packet and reduces load.
- `http.uri` (sticky buffer): restricts the `content`/`pcre` that follow it to the NORMALIZED URI (decoding `%55` → `U`). This is anti-evasion: an attacker sends `%75nion` to evade the raw content match, but the normalized buffer has already decoded it.
- `content:"union"; nocase`: fast pattern. `content:"select"; distance:0; within:100`: "select" must appear after "union", within 100 bytes.
- `pcre`: refinement to reduce false positives (requires whitespace in between, allows `union all select`).

Detecting an nmap SYN scan (many SYNs to many ports in a short period):
```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SCAN nmap SYN scan";
    flags:S;
    detection_filter:track by_src, count 20, seconds 5;
    classtype:attempted-recon;
    sid:1000010; rev:1;
)
```
- `flags:S`: only packets with the SYN FLAG set (see the TCP flags section, 11.2.5).
- `detection_filter:track by_src, count 20, seconds 5`: only alert when the same src produces ≥20 matches within 5 seconds — characteristic of a scan, without alerting on a single normal SYN.

Detecting a C2 beacon via a suspicious User-Agent:
```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"MALWARE Suspicious User-Agent C2 beacon";
    flow:established,to_server;
    http.user_agent; content:"Mozilla/5.0 (compatible; MSIE 9.0";
    http.uri; content:"/submit.php"; nocase;
    detection_filter:track by_src, count 3, seconds 30;
    classtype:trojan-activity;
    reference:url,attack.mitre.org/techniques/T1071/001;
    sid:1000020; rev:1;
)
```
**Note:** the rule relies on a default artifact; a threat actor can easily change their profile → this illustrates the mechanism, it is not a durable signature.

Using `flowbits` to correlate across packets (only alert on exfil after a login has been observed):
```
alert http any any -> any any ( msg:"login seen"; http.uri; content:"/login"; flowbits:set,auth; flowbits:noalert; sid:1000030; )
alert http any any -> any any ( msg:"download after login"; http.uri; content:"/export?all=1"; flowbits:isset,auth; sid:1000031; )
```
- `flowbits:set,auth` attaches a flag to the flow; `flowbits:noalert` keeps the first rule from alerting on its own. The second rule only matches once `auth` has been set.

### 11.2.4. Signature vs anomaly detection

| | Signature-based | Anomaly-based |
|---|---|---|
| Principle | Compare against a known pattern (rule/IOC) | Build a "normal" baseline, alert on deviations |
| Catches 0-day | Poorly (no signature yet) | Better (if the behavior deviates) |
| False positives | Low (if the rule is sound) | High (a baseline is hard to get right) |
| Example tools | Snort/Suricata rules | statistics, ML, some preprocessors |

Snort/Suricata are primarily signature-based, but the preprocessors have an anomaly element (e.g., alerting on TCP packets with illegal flags or anomalous headers).

### 11.2.5. TCP flags — needed for the `flags:` rule

TCP flags reside in 1 byte (offset 13 of the TCP header), the low 6 bits (+2 ECN/NS bits):

| Bit | Flag | Meaning |
|---|---|---|
| 0x01 | FIN | Terminate |
| 0x02 | SYN | Open a connection |
| 0x04 | RST | Reset |
| 0x08 | PSH | Push buffer |
| 0x10 | ACK | Acknowledge |
| 0x20 | URG | Urgent |

`flags` syntax: `flags:S` (SYN only), `flags:SA` (SYN+ACK), `flags:S,12` (SYN set, ignore bits 1&2 = CWR/ECE when matching), `flags:!R` (no RST). NULL scan = `flags:0`; XMAS = `flags:FPU`.

### 11.2.6. Install, run, and TEST that a rule triggers

```bash
# Suricata: check the configuration and the rules
suricata -T -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/local.rules

# Run the IDS reading from interface eth0
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Analyze a pcap file offline (great for testing rules)
suricata -r capture.pcap -S local.rules -l ./out/
cat ./out/fast.log         # alerts in text form
jq . ./out/eve.json | less # full JSON alerts

# Snort 3 testing a rule on a pcap
snort -c /etc/snort/snort.lua -R local.rules -r capture.pcap -A alert_fast
```

TEST that the SQLi rule above triggers using curl (lab only):
```bash
curl "http://victim.lab/search?q=1%20union%20select%20password%20from%20users"
# → fast.log:
# 06/19/2026-10:00:00.123456  [**] [1:1000001:2] WEB SQLi UNION SELECT in URI [**]
#   [Classification: Web Application Attack] [Priority: 1] {TCP} 203.0.113.5:51234 -> 10.0.0.10:80
```
Test the scan rule:
```bash
nmap -sS -p1-1000 10.0.0.10    # generates many SYNs → triggers sid:1000010
```

**Note:**
- Always test a rule on a pcap before pushing it to an inline IPS.
- An unanchored `pcre` (with no `content` fast pattern) running on every packet can drive CPU to 100% — a DoS against the defense system itself (ReDoS).
- Set local `sid`s ≥ 1,000,000 so they do not collide with community rules (ET/Talos).

---

## 11.3. ModSecurity + OWASP CRS — a layer-7 WAF

### 11.3.1. What a WAF is and why it differs from an L3/L4 firewall

A WAF (Web Application Firewall) operates at L7: it parses the HTTP request (method, URI, headers, body, cookies, params) after TLS has been terminated, then applies rules to the application CONTENT.

| | L3/L4 firewall (pf, iptables) | L7 WAF (ModSecurity) |
|---|---|---|
| Reads up to | IP/port/flags | URI, header, body, JSON, multipart |
| Can block | Port 22 from the internet | `' OR 1=1--` in the `id` parameter |
| TLS | Not required | Must be terminated to read plaintext |
| Understands application context | No | Yes (per-param, per-route) |

ModSecurity is a rule engine that runs as an embedded module (Apache `mod_security2`, the NGINX `ModSecurity-nginx` connector) or as a reverse proxy. The OWASP CRS (Core Rule Set) is the standard rule set that runs on that engine.

### 11.3.2. The five processing phases of ModSecurity

ModSecurity attaches rules to 5 phases along the lifecycle of an HTTP transaction:

| Phase | Name | When | Data available | Used to |
|---|---|---|---|---|
| 1 | Request Headers | After receiving headers | method, URI, headers, cookies | block early based on header/URI |
| 2 | Request Body | After receiving the body | ARGS (POST), JSON, multipart | block SQLi/XSS in the body |
| 3 | Response Headers | Before sending response headers | status, response headers | mask the server banner, check for leaks |
| 4 | Response Body | Before sending the response body | the response content | data leaks, hiding SQL errors |
| 5 | Logging | When writing the log | everything | decide whether to write the audit log |

**Why** split into phases: a body can be very large; blocking at phase 1 (headers only) is much cheaper. Phase 4 makes it possible to detect sensitive data leaking out (e.g., a MySQL error message revealing the schema).

### 11.3.3. The SecRule directive — breaking down the syntax

```
SecRule VARIABLES "OPERATOR" "ACTIONS"
```
Example:
```
SecRule ARGS "@detectSQLi" "id:1001,phase:2,deny,status:403,log,msg:'SQLi detected',t:none,t:urlDecodeUni,t:lowercase"
```

The components:

| Part | Role | Example values |
|---|---|---|
| VARIABLES | The data source to inspect | `ARGS`, `ARGS:id`, `REQUEST_URI`, `REQUEST_HEADERS:User-Agent`, `REQUEST_BODY`, `XML`, `FILES` |
| OPERATOR | The test | `@rx <regex>`, `@detectSQLi`, `@detectXSS`, `@contains`, `@eq`, `@ipMatch`, `@pmFromFile` |
| ACTIONS | The action + metadata | `id`, `phase`, `deny/pass/block/drop`, `status`, `log/nolog`, `msg`, `t:` (transform), `setvar`, `ctl`, `chain` |

Commonly used variables:
- `ARGS` = all parameters (GET+POST). `ARGS:id` = only the `id` parameter. `ARGS_NAMES` = the parameter names.
- `REQUEST_URI` = path + query (raw). `REQUEST_FILENAME` = path only.
- `REQUEST_HEADERS`, `REQUEST_HEADERS:Host`.
- `REQUEST_BODY`, `XML:/*`, `FILES`, `FILES_TMPNAMES`.

The main operators:
- `@rx`: regex (PCRE). `@detectSQLi`: uses libinjection (tokenizes the SQL, fewer false positives than plain regex). `@detectXSS`: libinjection XSS. `@pmFromFile`: matches many strings from a file (Aho-Corasick, fast).

Transformations (`t:`) normalize before matching — anti-evasion:
- `t:none` (clear inherited transforms), `t:urlDecodeUni` (decode `%XX` and `%uXXXX`), `t:htmlEntityDecode`, `t:lowercase`, `t:removeNulls`, `t:compressWhitespace`, `t:cmdLine`.

**Why** transform: an attacker sends `%27` instead of `'`, or `SeLeCt`. Without normalization, regex is easy to evade. The order of the transforms matters (they are applied in sequence).

Disruptive actions (only ONE per rule chain): `deny`, `drop`, `block`, `pass`, `allow`, `redirect`. `block` delegates the decision to `SecDefaultAction`.

`chain` joins multiple SecRules into an AND condition:
```
SecRule REQUEST_METHOD "@streq POST" "id:1002,phase:2,deny,status:403,chain"
    SecRule REQUEST_HEADERS:Content-Type "!@rx ^application/json" "t:lowercase"
```
→ blocks a POST whose Content-Type is not JSON.

### 11.3.4. DetectionOnly vs On, and a real config file

`modsecurity.conf` (excerpt, with explanations):
```apache
# DetectionOnly = log only, do NOT block (the tuning phase).  On = enforce blocking.
SecRuleEngine DetectionOnly

# Enable reading the request body so phase 2 has the POST ARGS
SecRequestBodyAccess On
SecRequestBodyLimit 13107200          # 12.5MB; over this → SecRequestBodyLimitAction
SecRequestBodyLimitAction Reject

# Read the response body (phase 4) only for a few content-types to avoid wasting RAM
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html application/json

# The default action when a rule uses "block"
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"

# Audit log: records the details of a flagged transaction
SecAuditEngine RelevantOnly           # only record when a rule matches / on errors
SecAuditLogParts ABIJDEFHZ            # A=audit header, B=req headers, C=req body, F=resp headers...
SecAuditLog /var/log/modsec_audit.log
```

**Why:** a safe deployment process is to run `DetectionOnly` for a few days, read `modsec_audit.log` to find rules wrongly blocking legitimate traffic → create exclusions → only then switch to `SecRuleEngine On`. Switching straight to On easily causes an outage due to CRS false positives.

### 11.3.5. OWASP CRS — anomaly scoring & paranoia level

CRS does not block immediately when a single rule matches. It ADDS SCORE (anomaly scoring):

```
Each matching rule → add a score by severity:
   CRITICAL = 5, ERROR = 4, WARNING = 3, NOTICE = 2 (verify against your CRS version)
Finally: if tx.anomaly_score >= tx.inbound_anomaly_score_threshold (default 5) → deny
```

**Why** scoring instead of block-on-first-match: it reduces false positives. A weak signal (e.g., the presence of a `'` character) is not enough to block; multiple signals must accumulate to cross the threshold. An administrator lowers the threshold to be stricter, raises it to loosen.

Paranoia Level (PL1–PL4): the "suspicion" level.
- PL1 (default): high-confidence rules, few false positives.
- PL2–PL4: add increasingly sensitive rules (catching more variants) but false positives rise sharply.

`crs-setup.conf`:
```apache
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=1"
SecAction "id:900110,phase:1,nolog,pass,t:none,\
   setvar:tx.inbound_anomaly_score_threshold=5,\
   setvar:tx.outbound_anomaly_score_threshold=4"
```

An example CRS rule blocking SQLi (illustrating the scoring mechanism):
```apache
SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES "@detectSQLi" \
    "id:942100,phase:2,block,capture,t:none,t:urlDecodeUni,\
     msg:'SQL Injection Attack Detected via libinjection',\
     logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}',\
     severity:'CRITICAL',\
     setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
     setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```
- `block`: follows SecDefaultAction (accumulate score or block).
- `capture` + `%{TX.0}`: stores the matched portion for logging (forensics).
- `setvar:tx.anomaly_score_pl1=+...`: adds to the score; the final "blocking evaluation" rule compares the total against the threshold.

Creating an exclusion (removing a false positive for one route):
```apache
SecRule REQUEST_URI "@beginsWith /api/free-text-comment" \
    "id:1000100,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:comment"
```
→ for that route, do not apply rule 942100 to `ARGS:comment`.

### 11.3.6. An end-to-end SQLi-blocking example and its output

```bash
# The attack request
curl "http://app.lab/product?id=1' OR '1'='1"
# The response when SecRuleEngine is On and the threshold is exceeded:
# HTTP/1.1 403 Forbidden
```
Excerpt from `modsec_audit.log`:
```
--a1b2c3-H--
Message: Access denied with code 403 (phase 2). detected SQLi via libinjection.
   [id "942100"] [msg "SQL Injection Attack Detected via libinjection"]
   [data "Matched Data: 1' OR '1'='1 found within ARGS:id"] [severity "CRITICAL"]
Action: Intercepted (phase 2)
Apache-Error: ModSecurity: Access denied with code 403
```

**Note:**
- A WAF is a compensating control; it does NOT replace fixing the code (prepared statements, output encoding).
- WAF bypass is feasible (unusual encodings, HTTP parameter pollution, request smuggling).
- Always use anomaly scoring and tune for your specific application.
- Enable response-body inspection to defend against data leaks, but weigh the RAM/latency cost.

---

## 11.4. pfSense — firewall/router (pf, NAT, state, VPN)

pfSense is based on FreeBSD + `pf` (Packet Filter). To understand pf is to understand pfSense.

### 11.4.1. The stateful firewall and the state table — the mechanism

pf is STATEFUL: when a packet matches a rule with `keep state` (the default on pfSense), pf creates an entry in the STATE TABLE. A reply packet is matched against the state table before even the ruleset → no reverse rule is needed.

```
Client 192.168.1.10:51000 ──SYN──► Server 203.0.113.9:443
   pf: the "pass out" rule matches → creates state:
   proto tcp, 192.168.1.10:51000 ↔ 203.0.113.9:443, state SYN_SENT
Server ──SYN/ACK──► Client
   pf: looks up the state table → MATCH → allowed through, state → ESTABLISHED
```

A state table entry (the concept of each field):

| Field | Meaning |
|---|---|
| proto | tcp/udp/icmp |
| src host:port | source address/port (after NAT, stores the original too) |
| dst host:port | destination |
| direction | the direction that created the state |
| state | TCP: SYN_SENT, ESTABLISHED, FIN_WAIT...; UDP: SINGLE/MULTIPLE |
| expire | the remaining timeout |
| packets/bytes | a counter for each direction |

**Why** stateful is better than stateless: stateless needs a rule for both directions and is easily fooled by a spoofed ACK packet slipping through. Stateful tracks the whole handshake sequence; only a packet matching a legitimate connection gets through. View the state: `pfctl -ss`. Count: `pfctl -si`.

### 11.4.2. Firewall rules on pfSense — the fields

Each rule on an interface has:

| Field | Meaning | Example |
|---|---|---|
| Action | Pass / Block (silent drop) / Reject (send RST/ICMP) | Pass |
| Interface | The NIC the rule applies to (WAN, LAN, OPT1/VLAN) | LAN |
| Direction | in / out (default is in in the pfSense GUI) | in |
| Address Family | IPv4 / IPv6 | IPv4 |
| Protocol | TCP/UDP/ICMP/... | TCP |
| Source | host/net/alias/`any`, can use `!` | LAN net |
| Source port | usually `any` for a client | any |
| Destination | host/net/alias | any |
| Dest port | the service port | 443 |
| Gateway | policy-based routing | default |
| State type | keep state / sloppy / none | keep state |

pf's evaluation order: native pf uses "LAST MATCH WINS" unless there is a `quick`. The pfSense GUI adds `quick`, so the FIRST matching rule (top to bottom) decides. Default block: pfSense has default-deny inbound on the WAN.

Block vs Reject — **why** choose one: Block = silent drop → a scanner has to wait for a timeout (slowing them down). Reject = returns a RST → closes quickly (good for internal UX) but helps an attacker map ports faster. Rule of thumb: Reject on the LAN, Block on the WAN.

### 11.4.3. Alias

An alias = a named group (hosts/networks/ports/URLs) for reuse and rule consolidation.
```
Alias  WebServers     = 10.0.0.10, 10.0.0.11
Alias  AdminPorts     = 22, 3389, 8443
Rule:  Pass LAN → WebServers proto TCP dst AdminPorts  (source: AdminPCs)
```
**Why:** 1 rule instead of N×M rules; updating one alias applies to every rule. A URL alias (pfBlockerNG) can automatically load a list of malicious IPs.

### 11.4.4. NAT — port forward and outbound

Port Forward (DNAT — inbound):
```
WAN  TCP  any:any  →  203.0.113.9:443   (NAT: redirect to 10.0.0.10:443)
   + accompanying firewall rule: Pass WAN proto TCP dst 10.0.0.10:443
```
- pf rewrites the DESTINATION address of a packet arriving from the public IP to the internal IP. pfSense auto-generates the accompanying firewall rule (the "Associated filter rule" option).

Outbound NAT (SNAT/masquerade): pfSense defaults to "Automatic outbound NAT" — rewriting the SOURCE IP of LAN→WAN traffic to the WAN IP.
```
192.168.1.10:51000  ──►  (SNAT)  203.0.113.1:51000  ──►  internet
   pf stores the mapping in state to translate the reply back.
```
1:1 NAT: maps a whole public IP ↔ a single internal IP (both in and out).

**Why** NAT + state go together: to translate a reply packet back, pf must remember the mapping (original port ↔ translated port) in the state table. This is also why PAT (port address translation) needs to track the source port.

### 11.4.5. VLAN

An 802.1Q VLAN inserts a 4-byte tag into the Ethernet frame (the structure):

| Field | Size | Meaning | Example |
|---|---|---|---|
| TPID | 16 bit | Tag Protocol ID = 0x8100 | 0x8100 |
| PCP | 3 bit | Priority (802.1p QoS) | 0 |
| DEI | 1 bit | Drop Eligible Indicator | 0 |
| VID | 12 bit | VLAN ID (1–4094) | 20 |

pfSense creates a VLAN interface on one physical NIC (router-on-a-stick): each VLAN = one subnet/interface with its own ruleset → network segmentation to defend against lateral movement. **Why** at most 4094 usable VLANs: the VID is 12 bits (0 and 4095 are reserved).

---

## 11.5. VPN — IPsec, OpenVPN, WireGuard (deep dive)

A VPN creates an encrypted "tunnel": the original packet is wrapped in a new packet with authentication + encryption. The core difference between the three technologies lies in: how keys are exchanged, the structure of the wrapping packet, and complexity.

### 11.5.1. IPsec — the architecture

IPsec consists of: a data-protection protocol (AH or ESP) + a key-exchange protocol (IKE). Every protected relationship is defined by an SA (Security Association).

#### SA (Security Association)
An SA is a one-way relationship describing: the algorithm, the key, the SPI, the lifetime. Two directions = 2 SAs. Each SA is identified by the tuple:
```
SA = ( SPI, destination IP, protocol[AH/ESP] )
```
- SPI (Security Parameters Index): 32 bits, an index for the receiver to look up the correct SA/decryption key.

#### AH vs ESP

| | AH (Protocol 51) | ESP (Protocol 50) |
|---|---|---|
| Confidentiality (encryption) | NO | YES |
| Integrity + authentication | YES (including the immutable parts of the IP header) | YES (only the ESP payload, not the outer IP header) |
| NAT compatibility | POOR (the hash includes the IP header → NAT breaks it) | GOOD (with NAT-T, UDP 4500 encapsulation) |
| Real-world use | Rare | Common (almost always uses ESP) |

**Why** ESP wins: AH authenticates the outer IP header → NAT changing the IP corrupts the ICV → it breaks. ESP only protects the payload, and NAT-T wraps an additional UDP/4500 layer so it can traverse NAT. Most VPNs use ESP with encryption + authentication (AES-GCM combines both).

#### Tunnel vs Transport mode

```
Original packet:   [ IP_orig | TCP | Data ]

TRANSPORT mode (ESP):  [ IP_orig | ESP_hdr | TCP | Data | ESP_trailer | ESP_ICV ]
   → protects the payload, KEEPS the original IP header. Used host-to-host.

TUNNEL mode (ESP):     [ IP_new | ESP_hdr | IP_orig | TCP | Data | ESP_trailer | ESP_ICV ]
   → wraps the ENTIRE original packet in a new IP packet. Used gateway-to-gateway (site-to-site).
```
**Why** tunnel for site-to-site: the two gateways have public IPs; the original internal IP is hidden inside the encrypted payload → it conceals the internal topology and routes over the internet using the gateway IPs.

#### ESP header/trailer structure — each field (RFC 4303)

| Field | Size | Meaning | Position |
|---|---|---|---|
| SPI | 32 bit (4 byte) | Indicates the SA for decryption | Start of ESP |
| Sequence Number | 32 bit (4 byte) | Anti-replay (incrementing) | After SPI |
| Payload Data | variable | The encrypted data (the original packet in tunnel mode) | Middle |
| Padding | 0–255 byte | Aligns the block cipher + hides the length | In the trailer |
| Pad Length | 8 bit (1 byte) | The number of padding bytes | Trailer |
| Next Header | 8 bit (1 byte) | The payload type (4=IP, 6=TCP) | Trailer |
| ICV | variable (e.g., 16 bytes with AES-GCM) | Integrity Check Value (authentication) | Last |

Sequence Number + the anti-replay window (default 64 packets): the receiver rejects a packet whose seq has been seen or is too old → defending against replay.

#### IKEv2 — key exchange (RFC 7296)

IKEv2 runs over UDP/500 (or UDP/4500 under NAT-T). Setup consists of 2 initial message pairs:

```
Phase 1 (IKE_SA_INIT):  negotiate crypto + Diffie-Hellman
   Init → Resp:  HDR, SAi1 (proposed algorithms), KEi (DH public), Ni (nonce)
   Resp → Init:  HDR, SAr1 (chosen algorithms), KEr (DH public), Nr (nonce)
   → both compute SKEYSEED from the DH shared secret + nonces → derive keys.

Phase 2 (IKE_AUTH):  authenticate identities + create the CHILD_SA (for ESP)
   Init → Resp:  HDR, [IDi], [AUTH], SAi2, TSi, TSr   (encrypted with the IKE key)
   Resp → Init:  HDR, [IDr], [AUTH], SAr2, TSi, TSr
   → AUTH = a signature/PSK proving identity; TS = traffic selector (the protected subnet).
```

Compared to IKEv1: IKEv1 has Phase 1 (Main mode 6 messages / Aggressive 3 messages) then Phase 2 (Quick mode 3 messages). IKEv2 is more compact (4 messages to set up), supports MOBIKE, integrated NAT-T, and EAP. The "phase 1/phase 2" terminology is still used: phase 1 = the IKE SA (protects the control channel), phase 2 = the CHILD SA = the ESP SA (protects the data).

The IKE header (the main fields):

| Field | Size | Meaning |
|---|---|---|
| Initiator SPI | 64 bit | Identifies the initiating side |
| Responder SPI | 64 bit | Identifies the responding side |
| Next Payload | 8 bit | The type of the next payload |
| Version | 8 bit | Major/Minor (2.0) |
| Exchange Type | 8 bit | IKE_SA_INIT(34), IKE_AUTH(35)... |
| Flags | 8 bit | Initiator/Response/Version |
| Message ID | 32 bit | Anti-replay, ordering |
| Length | 32 bit | The total length |

An example IPsec site-to-site configuration using strongSwan (`/etc/swanctl/swanctl.conf`):
```
connections {
   site-a-to-b {
      version = 2                       # IKEv2
      local_addrs  = 203.0.113.1
      remote_addrs = 198.51.100.1
      proposals = aes256gcm16-prfsha384-ecp384   # phase1 crypto
      local  { auth = psk; id = 203.0.113.1 }
      remote { auth = psk; id = 198.51.100.1 }
      children {
         net-net {
            local_ts  = 10.10.0.0/16    # internal subnet A (TS)
            remote_ts = 10.20.0.0/16    # internal subnet B
            esp_proposals = aes256gcm16  # phase2/ESP crypto, AEAD combining encryption+authentication
            mode = tunnel
            start_action = trap          # auto-establish the SA when traffic matching the TS appears
         }
      }
   }
}
secrets { ike-psk { id = 203.0.113.1; secret = "S3cretPSK!" } }
```
```bash
swanctl --load-all
swanctl --initiate --child net-net
swanctl --list-sas         # view the established SAs, SPI, algorithms, byte count
```
**Note:**
- A weak PSK is the break point (IKEv1 Aggressive mode leaks the PSK hash for offline cracking).
- Prefer digital certificates or EAP, AEAD (AES-GCM), and DH groups ≥ ecp256/Group 19.
- Enable PFS (Perfect Forward Secrecy) so each CHILD_SA has its own DH; leaking one key then does not leak past sessions.

### 11.5.2. OpenVPN — a TLS-based VPN

OpenVPN runs in user space, using TLS to exchange keys and a separate data channel. It runs over UDP/1194 (default) or TCP/443 (to traverse firewalls/proxies).

The dual-channel architecture:
- Control channel: TLS handshake (X.509 cert) → negotiates the session key.
- Data channel: packets are encrypted with the session key (AES-GCM/CBC + HMAC), wrapped in UDP.

```
[ IP_outer | UDP(1194) | OpenVPN hdr | (opcode/key-id) | encrypted{ IP_inner | TCP | Data } ]
```
OpenVPN creates a virtual `tun` interface (L3, IP routing) or `tap` (L2, Ethernet bridge).

Server configuration (`server.conf`):
```
port 1194
proto udp
dev tun                         # L3 tunnel
ca   ca.crt
cert server.crt
key  server.key                 # keep secret
dh   dh2048.pem
tls-auth ta.key 0               # HMAC on the control channel to defend against DoS/scanning
cipher AES-256-GCM              # data channel AEAD
auth  SHA256
server 10.8.0.0 255.255.255.0   # assign IPs to clients in this subnet
push "route 10.0.0.0 255.255.0.0"   # push the internal network route
push "dhcp-option DNS 10.0.0.53"
keepalive 10 120                # ping every 10s, restart after 120s of silence
persist-key
persist-tun
verb 3
```
Client (`client.ovpn`):
```
client
dev tun
proto udp
remote vpn.example.com 1194
ca ca.crt
cert client.crt
key client.key
tls-auth ta.key 1
cipher AES-256-GCM
remote-cert-tls server          # require the server cert to have the server EKU → anti-MITM
verb 3
```
```bash
openvpn --config server.conf      # start the server
openvpn --config client.ovpn      # the client connects
# Check: ip addr show tun0 ; ping 10.8.0.1
```
**Why** `tls-auth`/`tls-crypt`: adds an HMAC layer (or full encryption with tls-crypt) on the control channel → a packet without the correct HMAC is dropped before TLS is even processed → defends against port scans, DoS, and makes service fingerprinting harder. `remote-cert-tls server` prevents a client from being tricked into connecting to a rogue server.

### 11.5.3. WireGuard — a modern VPN, the Noise protocol

WireGuard is minimalist (~4000 lines of kernel code), runs in the kernel, and uses a fixed crypto suite (no negotiation):
- AEAD encryption: ChaCha20-Poly1305
- Key exchange: Curve25519 ECDH
- Hash: BLAKE2s
- Handshake framework: the Noise Protocol Framework (Noise_IK)

**Why** no algorithm negotiation: it eliminates the "downgrade attack" and the complexity of IKE. To change an algorithm → bump the protocol version, not negotiate at runtime.

#### The key model
Each peer has a Curve25519 key pair (private 32 bytes, public 32 bytes). "Cryptokey routing": each peer declares an `AllowedIPs` — a list of IPs that peer is allowed to send/receive. Public key ↔ AllowedIPs is the entirety of "routing + authentication".

#### Handshake (Noise IK) — 2 messages, 1-RTT
```
Initiator → Responder:  Handshake Initiation
   - contains: the ephemeral public, the static public (encrypted), a timestamp (TAI64N, anti-replay), a MAC
Responder → Initiator:  Handshake Response
   - contains: the ephemeral public, empty (encrypted), a MAC
→ after 2 messages: both sides have a symmetric session key. The key rotates after ~2 minutes (rekey).
```
The structure of the handshake initiation message (per the whitepaper — cross-check the spec when implementing):

| Field | Size | Meaning |
|---|---|---|
| message type | 1 byte | =1 (initiation) |
| reserved | 3 byte | 0 |
| sender index | 4 byte | the sender's session index |
| unencrypted ephemeral | 32 byte | ephemeral public key |
| encrypted static | 32+16 byte | static public + Poly1305 tag |
| encrypted timestamp | 12+16 byte | TAI64N + tag |
| mac1 | 16 byte | a MAC using the destination's public key (defends against junk packets) |
| mac2 | 16 byte | a MAC using a cookie (defends against DoS under overload) |

**Why** mac1/mac2 + cookie: WireGuard is "silent" — it does not respond to invalid packets (stealth, anti-scanning). mac1 proves the sender knows the destination's public key (defends against random floods). When under load, the responder issues a cookie; the initiator must compute the correct mac2 → defending against DoS amplification.

#### A practical configuration
Server (`/etc/wireguard/wg0.conf`):
```ini
[Interface]
Address = 10.9.0.1/24
ListenPort = 51820
PrivateKey = <server_private_key>      # generate: wg genkey
# (do not declare a PublicKey in Interface; it is derived from the private key)

[Peer]                                  # client 1
PublicKey = <client1_public_key>
AllowedIPs = 10.9.0.2/32                # only this IP is accepted from the peer
```
Client (`wg0.conf`):
```ini
[Interface]
Address = 10.9.0.2/24
PrivateKey = <client1_private_key>
DNS = 10.0.0.53

[Peer]
PublicKey = <server_public_key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0                  # full tunnel: route all traffic through the VPN
PersistentKeepalive = 25               # keep the NAT mapping (send a keepalive every 25s)
```
```bash
wg genkey | tee privatekey | wg pubkey > publickey   # generate the key pair
wg-quick up wg0          # bring up the interface + route per AllowedIPs
wg show                  # view peers, last handshake, transfer bytes
wg-quick down wg0
```
**Why** `PersistentKeepalive`: WireGuard sends nothing while idle → a NAT/firewall in between expires the mapping, and the server cannot reach the client back. A 25s keepalive keeps the NAT "hole" open.

A comparison of the three VPNs:

| Criterion | IPsec/IKEv2 | OpenVPN | WireGuard |
|---|---|---|---|
| Layer/deployment | Kernel (L3) | User-space (tun/tap) | Kernel (L3) |
| Key exchange | IKEv2 (negotiated) | TLS (X.509) | Noise IK (fixed) |
| Crypto agility | High (negotiated) | High | None (fixed, bump the version) |
| Default port | UDP 500/4500 | UDP 1194 / TCP 443 | UDP 51820 |
| Traversing restrictive firewalls | NAT-T | good (TCP/443 mimics HTTPS) | UDP, can be blocked |
| Codebase | large, complex | medium | very small (easy to audit) |
| Performance | high (kernel) | lower (user-space) | the highest |
| Roaming (changing IP) | MOBIKE | reconnect | seamless (by public key) |

**Note** (common to all three VPNs):
- Protect the private key (file permission 600), enable PFS/rekey.
- Pin the peer identity (cert/public key) and monitor for anomalous handshakes.
- WireGuard treats allowed-IPs as the trust boundary — a wrong AllowedIPs is a routing/spoofing hole.

---

## 11.6. Proxy and reverse proxy

| | Forward proxy | Reverse proxy |
|---|---|---|
| Acts on behalf of | The client (hides the client from the server) | The server (hides the server from the client) |
| Position | At the client edge (egress) | At the server edge (ingress) |
| Used for | Content filtering, egress cache, anonymity, outbound access control | TLS termination, load balancing, WAF, cache, hiding the backend |
| Example | Squid | NGINX, HAProxy, Envoy |

A reverse proxy is the ideal place to attach a WAF: it terminates TLS (reading plaintext), then applies ModSecurity, then forwards to the backend.

An example NGINX reverse proxy + ModSecurity:
```nginx
server {
    listen 443 ssl;
    server_name app.example.com;
    ssl_certificate     /etc/nginx/ssl/app.crt;
    ssl_certificate_key /etc/nginx/ssl/app.key;

    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;   # load CRS

    location / {
        proxy_pass http://10.0.0.10:8080;                 # the internal backend
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
**Why:** behind a reverse proxy, the backend sees the proxy's IP. The `X-Forwarded-For` header carries the real client IP for logging/rate-limiting.

**Note:**
- The backend should only trust XFF when it comes from a trusted proxy; otherwise a client can set a fake XFF and bypass an IP allowlist/rate-limit.
- A reverse proxy also helps hide the backend version (reducing the attack surface).
- It is also the place to defend against HTTP request smuggling, by strictly normalizing the `Content-Length`/`Transfer-Encoding` headers.

---

## 11.7. Zeek — behavior-based traffic analysis (network security monitor)

Zeek (formerly Bro) is DIFFERENT from Snort/Suricata: it does not primarily match signatures, but rather produces CONTEXT-RICH LOGS for every connection and protocol event, used for threat hunting and anomaly detection. It runs scripts on events (connection_established, dns_request, http_request).

The main logs (TSV, one line per event):
- `conn.log`: every L3/L4 connection.
- `dns.log`: DNS queries/responses.
- `http.log`: each HTTP request/response.
- `ssl.log`/`x509.log`: TLS handshakes, certs.
- `files.log`, `notice.log`, `weird.log`.

Typical fields in `conn.log`:

| Field | Meaning | Example |
|---|---|---|
| ts | timestamp | 1718780400.123 |
| uid | a unique connection ID (links logs together) | CwjjYf3 |
| id.orig_h / id.orig_p | source IP/port | 10.0.0.5 / 51234 |
| id.resp_h / id.resp_p | destination IP/port | 8.8.8.8 / 53 |
| proto | tcp/udp/icmp | udp |
| service | the identified L7 protocol | dns |
| duration | the duration | 0.034 |
| orig_bytes/resp_bytes | bytes per direction | 31 / 75 |
| conn_state | the state (S0, SF, REJ, RSTO...) | SF |

The `uid` is the key: the same `uid` appearing in `conn.log`, `dns.log`, `http.log` → pivot across the entire activity of one connection.

Running Zeek offline on a pcap and querying:
```bash
zeek -r capture.pcap                  # generates conn.log, dns.log, http.log...
zeek-cut id.orig_h id.resp_h id.resp_p service < conn.log | sort | uniq -c | sort -rn
# Find DNS exfil: very long queries / many random subdomains
zeek-cut query < dns.log | awk '{ if (length($1) > 50) print }'
```
A Zeek script detecting connections to an unusual port (an illustrative example):
```zeek
event connection_established(c: connection) {
    if (c$id$resp_p == 4444/tcp)
        NOTICE([$note=Weird::Activity,
                $msg=fmt("Possible reverse shell to %s:%s", c$id$resp_h, c$id$resp_p),
                $conn=c]);
}
```
**Why** Zeek complements Suricata: Suricata answers "did a signature match?"; Zeek answers "what happened on the network" — enabling hunting for threats that have no signature yet (regular beaconing, DNS tunneling, anomalous TLS JA3 fingerprints). Combined: Suricata for fast alerts, Zeek for investigative context, feeding both into the SIEM.

---

## 11.8. Putting the defense architecture together and operational notes

A typical organizational layout:
```
Internet
  │
[ pfSense / NGFW ]  ── L3/L4 stateful filter, NAT, anti-DDoS, VPN termination (IPsec/WG/OVPN)
  │  (SPAN/TAP) ───────────────► [ Suricata IDS ]  +  [ Zeek ]  ──► SIEM
  │
[ Reverse proxy + ModSecurity/CRS ]  ── L7 WAF, TLS termination
  │
[ App servers ]  ── HIDS (Wazuh/auditd), prepared statements (the root is still secure code)
```

The core operational principles:
1. Tune first, enforce later: IDS alert-only and WAF DetectionOnly during the baseline phase; measure false positives before going inline/On.
2. The right layer for the job: block L3/L4 at the firewall (cheap), L7 at the WAF; do not use a WAF to fight floods or a firewall to fight SQLi.
3. Defense in depth: WAF/IDS are compensating controls; they do not replace secure code, patching, and least-privilege.
4. The availability of the defensive device: an inline IPS/WAF is a potential point of failure / chokepoint — design fail-open/fail-close deliberately, HA, and limit regex/ReDoS.
5. Encryption blinds the NIDS: consider TLS inspection at the reverse proxy (where the keys already are) instead of decrypting mid-path.
6. Protect the VPN keys and peer identities: private key permission 600, PFS/rekey, pin the cert/public key, monitor handshakes.
7. Correlate multiple sources: NIDS (Suricata) + NSM (Zeek) + HIDS (Wazuh) + WAF audit logs → SIEM to see the full attack chain instead of disjointed alerts.
