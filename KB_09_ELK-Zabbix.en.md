# Chapter 9 — Observability & Infrastructure Monitoring

## Overview

I started paying attention to this after getting asked more than once "since when has the load been this high" and having nothing to check but a guess — no log, no graph. Serious infrastructure monitoring needs two separate things: logs tell you what happened, metrics tell you whether the system is healthy right now. This chapter walks through four tools that answer those two questions — the evidence of an attack lives in the logs, while infrastructure incidents often start from an anomalous metric, so both matter to security.

The first half of the chapter is the **ELK Stack** — Elasticsearch, Logstash, Kibana, plus the **Beats** family of agents (Filebeat, Metricbeat, Winlogbeat...) collecting logs at the source. A log by itself is just a scattered event record on one machine; ELK solves the problem of gathering those logs in one place and making them searchable: Elasticsearch uses an inverted index to do full-text lookups at a scale relational databases can't touch, Logstash sits in between parsing and normalizing raw logs into clean data, and Kibana turns that indexed data into charts and dashboards — spotting anomalies far faster than reading raw logs ever could.

The second half covers metrics, represented by two tools solving the same problem with different philosophies. **Zabbix** continuously measures CPU, RAM, disk, and service status, alerting automatically through triggers once a threshold is breached — classic monitoring, configured through a GUI/templates. **Prometheus** is the cloud-native generation: the server actively pulls (scrapes) values through the `/metrics` endpoint each **exporter** exposes on a host, stores them in its own TSDB, queries them with PromQL, and hands alerting off to Alertmanager. **Grafana** sits above both, collecting nothing itself — just drawing dashboards pulled from multiple datasources (Prometheus, Elasticsearch/OpenSearch...) in one place, instead of every tool having its own separate UI.

The chapter closes with a nod to SIEM, drawing a clean line: Zabbix and Prometheus watch infrastructure health, while detecting attacks through event correlation is SIEM's job — two layers that complement, not replace, each other.

## 9.0 Overview and Positioning of the Tools

The Overview above introduced each tool individually. This section does not repeat those definitions; instead it places the tool families side by side to show clearly where they differ — before we dive into each part. The chapter also goes down to the level of **wire format, on-disk record structure, every configuration field, and every processing step** — enough for a Blue Team/AppSec/DevSecOps engineer to operate, debug, and assess risk for real.

One fundamental distinction worth keeping in mind before reading on:

| Aspect | ELK Stack | Zabbix | Prometheus | SIEM (e.g., Wazuh, Splunk ES) |
|---|---|---|---|---|
| Unit of data | JSON document (full-text + structured) | Metric (numeric/string value over time) | Metric time-series (name + labels, float value) | Normalized security event + rule correlation |
| Storage model | Inverted index + doc values (Lucene) | Time-series in RDBMS/TSDB | Local TSDB (blocks + WAL) | Index + alert store |
| Collection model | Agents (Beats) push into a pipeline | Passive/active agents, SNMP, proxies | Server **pulls** (scrapes) the exporters' `/metrics` endpoints | Agents push events to a manager |
| Typical question | "Find every 5xx request containing string X in the last 15 minutes" | "Did host A's CPU exceed 90% over 5 minutes?" | "What is the fleet-wide CPU rate by mode over the last 5 minutes?" | "Is there any behavioral chain matching MITRE T1110?" |
| Alerting mechanism | Watcher/Kibana alerting/ElastAlert (add-on) | Trigger expression (core) | Alerting rules + Alertmanager (separated) | Correlation rules + decoder (core) |
| Essential nature | Search engine | Monitoring system | Monitoring system (TSDB + query engine) | Detection & response |

**Grafana** is deliberately absent from the table: it is not a place where data lives but a **display layer** on top of the systems above — a single Grafana dashboard can simultaneously draw panels from Prometheus (performance) and from Elasticsearch/OpenSearch (logs/security).

Remember: Elasticsearch **is a search engine**, not an RDBMS (relational database); Zabbix and Prometheus **are monitoring systems**, not log stores; Grafana **is a pane of glass**, not a data store. Most of the design decisions below can be traced back to these essential natures.

---

## 9.1 Elasticsearch — The Storage and Search Core

### 9.1.1 The Inverted Index — Why, and Its Internal Structure

Elasticsearch is built on the **Apache Lucene** library. Its central data structure is the **inverted index**. In an RDBMS, you go from row → column → value (forward). The inverted index reverses this: it goes from **term (word) → list of documents containing that term**. This is why full-text search across billions of documents still runs at millisecond latency: instead of a linear scan, you look up the term and then union/intersect the posting lists.

The process of indexing a text field:

```
Original text:  "The Quick Brown Fox"
   │
   ▼ (1) Character filter   — e.g., strip HTML tags, normalize characters
   │
   ▼ (2) Tokenizer          — e.g., the standard tokenizer splits on word boundaries
   │      → ["The", "Quick", "Brown", "Fox"]
   │
   ▼ (3) Token filter       — e.g., lowercase, stop words, stemming
   │      → ["quick", "brown", "fox"]   ("the" removed as a stop word)
   │
   ▼ Terms are written into the inverted index
```

The inverted index structure (simplified) for 3 documents:

```
doc1 = "quick brown fox"
doc2 = "quick brown dog"
doc3 = "lazy fox"

Term      | Doc Freq | Posting list (docId : positions)
----------|----------|----------------------------------
brown     |    2     | doc1:[1], doc2:[1]
dog       |    1     | doc2:[2]
fox       |    2     | doc1:[2], doc3:[1]
lazy      |    1     | doc3:[0]
quick     |    2     | doc1:[0], doc2:[0]
```

The Lucene components stored on disk for each segment (the actual files in the `index/.../<segment>` directory):

| Component | File extension | Contents | Purpose |
|---|---|---|---|
| Term dictionary | `.tim`, `.tip` | Sorted list of terms + an FST index into it | Term lookup in O(log) |
| Postings | `.doc`, `.pos`, `.pay` | docId, position, payload | Return documents, support phrase queries |
| Stored fields | `.fdt`, `.fdx` | Original document (`_source`) | Return the full document |
| Doc values | `.dvd`, `.dvm` | Column of values by docId | Sort, aggregation, scripting |
| Norms | `.nvd`, `.nvm` | Field-length normalization | Compute relevance score (BM25) |

**Why separate out `doc values`?** The inverted index is optimized for "term → docs" but poor at "docId → value" (which is needed for sort/aggregation). Doc values are a **columnar** structure stored by column, compress well, and read sequentially fast. This is why a `text` field (which only has an inverted index) cannot be sorted or aggregated, while a `keyword` field (which has doc values) can.

The default relevance score is **BM25** (Best Matching 25), which replaced the older TF-IDF. The simplified formula for each term:

```
score(D,q) = IDF(q) · ( f(q,D) · (k1 + 1) ) / ( f(q,D) + k1 · (1 - b + b · |D|/avgdl) )

IDF(q) = ln( 1 + (N - n(q) + 0.5) / (n(q) + 0.5) )
```

- `f(q,D)`: frequency of term q in document D
- `|D|`: document length; `avgdl`: average document length
- `k1` (default 1.2): term-frequency saturation; `b` (default 0.75): the influence of length
- `N`: total number of documents; `n(q)`: number of documents containing q

**Why BM25?** TF-IDF increases the score linearly with frequency, making it easy to manipulate by keyword stuffing. BM25 has a saturation coefficient `k1` that makes the score converge — repeating a word 100 times is not much better than 10 times.

### 9.1.2 Document, Index, Mapping

A **Document** is the basic unit of data, a JSON object. Each document has metadata:

```json
{
  "_index": "logs-nginx-2026.06.19",
  "_id": "kJ3xY4cBz1aQ",
  "_version": 1,
  "_seq_no": 42,
  "_primary_term": 1,
  "_source": {
    "@timestamp": "2026-06-19T08:15:30.123Z",
    "clientip": "203.0.113.45",
    "method": "GET",
    "request": "/login",
    "status": 401,
    "bytes": 512
  }
}
```

| Meta field | Type | Meaning | Example |
|---|---|---|---|
| `_index` | string | The index containing the document | `logs-nginx-2026.06.19` |
| `_id` | string | Unique identifier within the index (auto-generated if not provided) | `kJ3xY4cBz1aQ` |
| `_version` | long | Number of times the document has been overwritten | `1` |
| `_seq_no` | long | Operation sequence number on the shard (used for optimistic concurrency) | `42` |
| `_primary_term` | long | The "term" of the primary shard, incremented on failover | `1` |
| `_source` | object | The user's original data | (JSON) |

**Optimistic concurrency control**: conditional writes via `if_seq_no` + `if_primary_term`. If the values do not match (someone wrote first), the operation returns `409 Conflict`. This mechanism replaces locks — why? Because locking is not feasible in a distributed system with network latency.

**Mapping** defines the data type of each field. Create an index with an explicit mapping (always recommended in production, to avoid dynamic mapping guessing wrong):

```bash
curl -X PUT "https://es:9200/logs-nginx-2026.06.19" \
  -u elastic:$PASS --cacert ca.crt \
  -H 'Content-Type: application/json' -d '{
  "settings": {
    "number_of_shards": 3,
    "number_of_replicas": 1,
    "refresh_interval": "5s"
  },
  "mappings": {
    "dynamic": "strict",
    "properties": {
      "@timestamp": { "type": "date" },
      "clientip":   { "type": "ip" },
      "method":     { "type": "keyword" },
      "request":    {
        "type": "text",
        "fields": { "raw": { "type": "keyword", "ignore_above": 256 } }
      },
      "status":     { "type": "short" },
      "bytes":      { "type": "long" },
      "user_agent": { "type": "text" },
      "geo":        { "type": "geo_point" }
    }
  }
}'
```

A table of important data types:

| Type | Storage size | Inverted index | Doc values | Used for |
|---|---|---|---|---|
| `text` | variable (analyzed) | Yes | No | Full-text search |
| `keyword` | verbatim | Yes (not analyzed) | Yes | Filter, sort, aggregate, exact match |
| `byte` | 8-bit signed | — | Yes | -128..127 |
| `short` | 16-bit signed | — | Yes | -32768..32767 |
| `integer` | 32-bit signed | — | Yes | integers |
| `long` | 64-bit signed | — | Yes | large numbers, epoch ms |
| `float` | 32-bit IEEE 754 | — | Yes | floating point |
| `double` | 64-bit IEEE 754 | — | Yes | high-precision floating point |
| `date` | long (epoch ms) internally | — | Yes | time |
| `ip` | IPv4 (32-bit) / IPv6 (128-bit) | Yes | Yes | IP addresses, supports CIDR |
| `boolean` | true/false | — | Yes | flags |
| `geo_point` | lat/lon | — | Yes | coordinates, geo queries |

The `—` in the Inverted index column means that type is not stored in a term-based inverted index; instead Lucene indexes it with a point/BKD-tree structure optimized for range queries over numbers, dates, IPs, and coordinates.

**Why is the `request` field both `text` and given a `raw` sub-field of type `keyword`?** This is the classic multi-field pattern: the `text` version allows full-text search ("find requests containing /admin"), while the `keyword` version allows exact aggregation ("top 10 most-called URLs"). One piece of data, two ways to use it.

**Security note**: `dynamic: "strict"` rejects documents with unknown fields → preventing **mapping explosion** (an attacker sends logs with thousands of random keys to bloat the mapping, causing a heap-memory DoS). `ignore_above: 256` prevents an overly long keyword term from corrupting the index.

### 9.1.3 Shard, Replica, Segment

An index is divided into **shards**. Each shard is a **complete, independent Lucene index**. There are two kinds:

- **Primary shard**: the original copy, which receives writes first.
- **Replica shard**: a copy of the primary, serving reads and providing HA.

```
Index "logs" : 3 primaries, 1 replica  → 6 shards total

      Node A            Node B            Node C
  ┌───────────┐    ┌───────────┐    ┌───────────┐
  │  P0       │    │  P1       │    │  P2       │
  │  R2       │    │  R0       │    │  R1       │
  └───────────┘    └───────────┘    └───────────┘

Rule: a replica is NEVER placed on the same node as its primary
      (losing 1 node still leaves enough data)
```

The write flow for a single document:

```
1. Client sends an index request to the coordinating node
2. The coordinating node hashes the routing:  shard = hash(_routing) % number_of_primary_shards
   (by default _routing = _id) → determines the primary shard
3. Write to the primary shard:
   a. Write into the in-memory buffer
   b. Append to the translog (write-ahead log, fsync by default per request)
4. The primary forwards in parallel to every replica
5. Once enough replicas acknowledge → return 200 to the client
```

The lifecycle from buffer to segment:

```
in-memory buffer ──refresh (default 1s)──▶ new segment (searchable, in the filesystem cache)
                                              │
   many segments ──merge (background)──▶ a larger segment (purging deleted docs)
                                              │
   translog ──flush──▶ fsync the segment to disk, truncate the translog
```

| Parameter | Default | Meaning | Trade-off |
|---|---|---|---|
| `refresh_interval` | 1s | How often the buffer becomes a searchable segment | Smaller = more "near real-time" but costs CPU/IO |
| `number_of_shards` | (version-dependent) | Number of primaries, **fixed after creation** | Too many small shards = overhead; too few = won't scale |
| `number_of_replicas` | 1 | Number of copies, **dynamically changeable** | More replicas = faster reads, higher HA, more disk |
| `translog.durability` | request | `request` fsyncs every write; `async` periodically | `async` is faster but risks data loss on crash |

**Why is the number of primary shards fixed?** Because routing uses `% number_of_primary_shards`. Changing the shard count would change the routing destination of every existing document → requiring a full reindex. This is the most important design decision when creating an index.

**Why is there a translog?** A refresh creates a segment in RAM/cache but has not yet fsynced it to disk. If the node crashes between two flushes, the data in the un-fsynced segment is lost — the translog (which has been fsynced) allows replay to recover it.

### 9.1.4 Query DSL — Querying Down to Each Clause

The Query DSL distinguishes between **query context** (computes a relevance score, "how well does it match") and **filter context** (true/false, cached, "does it match"). Filters are faster because they do not compute a score and are cached as bitsets.

**match** (full-text, analyzed):

```json
GET /logs-nginx-*/_search
{ "query": { "match": { "user_agent": "curl python" } } }
```
→ analyzes "curl python" into the terms `curl`, `python`; defaults to OR; returns documents containing at least one term, scored with BM25.

**term** (exact, NOT analyzed — used for keyword/numeric/ip):

```json
{ "query": { "term": { "status": 401 } } }
```
→ Note the classic mistake: using `term` on a `text` field usually does not match, because the value was lowercased/tokenized at index time, but the term query is not analyzed.

**range**:

```json
{ "query": { "range": { "@timestamp": { "gte": "now-15m", "lte": "now" } } } }
```

**bool** (composition — the backbone of every real query):

```json
GET /logs-nginx-*/_search
{
  "query": {
    "bool": {
      "must":     [ { "match": { "request": "login" } } ],
      "filter":   [
        { "term":  { "status": 401 } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ],
      "should":   [ { "term": { "method": "POST" } } ],
      "must_not": [ { "term": { "clientip": "10.0.0.5" } } ],
      "minimum_should_match": 0
    }
  },
  "size": 20,
  "sort": [ { "@timestamp": "desc" } ],
  "aggs": {
    "by_ip": { "terms": { "field": "clientip", "size": 10 } }
  }
}
```

| Clause | Context | Affects score | Semantics |
|---|---|---|---|
| `must` | query | Yes | AND, contributes to score |
| `filter` | filter | No (cached) | AND, filter only |
| `should` | query | Yes | soft OR, boosts score |
| `must_not` | filter | No | NOT |

The query above (read with security semantics): "Find up to 20 login requests (full-text 'login') with status 401, in the last hour, not originating from 10.0.0.5, prioritizing POST higher in the display, and at the same time aggregate the top 10 IPs." This is exactly the shape of brute-force hunting.

**Query security note**: avoid `script` queries/aggregations with untrusted input (Painless runs in a sandbox but still has a history of script-related CVEs). Set `search.max_buckets` to block aggregation explosions that cause OOM. Limit `size` and use `search_after`/PIT instead of deep pagination with a large `from`.

### 9.1.5 Node, Cluster, Roles, and Security

A **cluster** consists of multiple **nodes**, each of which can take on a role:

| Role | Symbol | Responsibility |
|---|---|---|
| master-eligible | `m` | Elects the master, manages cluster state (mapping, shard allocation) |
| data | `d` (`data_hot`, `data_warm`, `data_cold`, `data_frozen`) | Stores shards, handles CRUD/search |
| ingest | `i` | Runs ingest pipelines (preprocessing before indexing) |
| coordinating | (every node) | Receives requests, distributes them, gathers results |
| ml | `l` | Machine learning jobs |

**Master election & quorum**: a cluster needs `(number of master-eligible / 2) + 1` nodes to elect a master (to avoid **split-brain**). With 3 master-eligible nodes, the quorum is 2. Why always use an odd number of master-eligible nodes (3, 5)? To have a clear quorum during a network partition.

A minimal `elasticsearch.yml` for production with security:

```yaml
cluster.name: prod-siem
node.name: es-data-01
node.roles: [ data_hot, ingest ]
network.host: 0.0.0.0
discovery.seed_hosts: ["es-master-01", "es-master-02", "es-master-03"]
cluster.initial_master_nodes: ["es-master-01", "es-master-02", "es-master-03"]

xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/transport.p12
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: certs/http.p12
```

**Security notes (critically important)**:
- Elasticsearch has a history of massive data leaks because it ran **without authentication, bound to 0.0.0.0, with port 9200 open to the Internet**. Always enable `xpack.security.enabled: true`, TLS for both transport (9300) and HTTP (9200), and RBAC.
- Separate the two TLS layers: **transport (9300)** is internal node-to-node (cluster) communication; **HTTP (9200)** is the client API. Both must be encrypted.
- Use role-based access: create a role that can only read a specific index, and assign it to an API key instead of using the `elastic` superuser.

```bash
# Create a role that can only read logs-* indices
curl -X POST "https://es:9200/_security/role/log_reader" -u elastic:$PASS --cacert ca.crt \
 -H 'Content-Type: application/json' -d '{
   "indices":[{"names":["logs-*"],"privileges":["read","view_index_metadata"]}]
 }'
```

---

## 9.2 Logstash — The Data Processing Pipeline

### 9.2.1 The input → filter → output Pipeline Architecture

Logstash processes data through a 3-stage pipeline, where each event is an object with `@timestamp`, `@version`, `@metadata`, and fields:

```
            ┌──────────────────────── Logstash Pipeline ────────────────────────┐
  source ──▶│  INPUT  ──▶  [queue]  ──▶  FILTER (worker threads)  ──▶  OUTPUT   │──▶ destination
            └────────────────────────────────────────────────────────────────────┘
   beats        beats     in-memory      grok → date → mutate         elasticsearch
   syslog       plugin    or             → geoip → ...                stdout
   kafka                  persistent                                  kafka
```

| Stage | Role | Example plugins |
|---|---|---|
| input | Receive data | `beats`, `tcp`, `udp`, `syslog`, `kafka`, `file`, `http` |
| filter | Transform, enrich, parse | `grok`, `date`, `mutate`, `geoip`, `kv`, `json`, `dissect`, `useragent` |
| output | Send onward | `elasticsearch`, `stdout`, `kafka`, `file`, `s3` |

**Persistent queue**: by default the queue is in RAM (events are lost on crash). Enable `queue.type: persisted` to write events to disk (with ACK) — important for security logs that must not be lost.

### 9.2.2 GROK — Parsing Unstructured Logs

**GROK** translates free-form log strings into fields using named patterns; it is essentially regex with aliases. Syntax: `%{PATTERN:field_name}` or `%{PATTERN:field_name:type}`.

Some built-in patterns (defined in `grok-patterns`):

| Pattern | Equivalent regex (simplified) | Matches |
|---|---|---|
| `IPV4` | `(?:[0-9]{1,3}\.){3}[0-9]{1,3}` | `203.0.113.45` |
| `NUMBER` | `(?:-?\d+(\.\d+)?)` | `512`, `-3.14` |
| `WORD` | `\b\w+\b` | `GET` |
| `DATA` | `.*?` (lazy) | anything, shortest |
| `GREEDYDATA` | `.*` (greedy) | the remainder |
| `QS` | a quoted string | `"GET /x HTTP/1.1"` |
| `HTTPDATE` | Apache date format | `19/Jun/2026:08:15:30 +0700` |
| `COMBINEDAPACHELOG` | composite Nginx/Apache pattern | the whole line |

**Example of parsing an Nginx log line (combined format):**

The actual line:
```
203.0.113.45 - alice [19/Jun/2026:08:15:30 +0700] "POST /login HTTP/1.1" 401 512 "https://app/" "Mozilla/5.0"
```

The GROK pattern:
```
%{IPV4:clientip} - %{DATA:auth} \[%{HTTPDATE:timestamp}\] "%{WORD:method} %{DATA:request} HTTP/%{NUMBER:httpversion}" %{NUMBER:status:int} %{NUMBER:bytes:int} %{QS:referrer} %{QS:agent}
```

The extracted fields:

| Field | Value | Type |
|---|---|---|
| `clientip` | `203.0.113.45` | string→ip |
| `auth` | `alice` | string |
| `timestamp` | `19/Jun/2026:08:15:30 +0700` | string |
| `method` | `POST` | string |
| `request` | `/login` | string |
| `httpversion` | `1.1` | string |
| `status` | `401` | int |
| `bytes` | `512` | int |
| `referrer` | `"https://app/"` | string |
| `agent` | `"Mozilla/5.0"` | string |

**Why use `DATA` (lazy) vs `GREEDYDATA` (greedy)?** `DATA` (`.*?`) matches the shortest span, stopping as soon as it meets the next delimiter character (space, bracket). `GREEDYDATA` (`.*`) swallows as much as possible — use it only at the end of a line. Placing it in the wrong spot causes a `_grokparsefailure`.

**Example of parsing an SSH log (auth.log) to hunt brute-force:**

The actual line:
```
Jun 19 08:15:30 web01 sshd[2451]: Failed password for invalid user admin from 203.0.113.45 port 51324 ssh2
```

The pattern:
```
%{SYSLOGTIMESTAMP:syslog_ts} %{HOSTNAME:host} %{WORD:program}\[%{NUMBER:pid}\]: Failed password for( invalid user)? %{USERNAME:ssh_user} from %{IP:src_ip} port %{NUMBER:src_port} ssh2
```

### 9.2.3 mutate, date, geoip

**date filter** — converts a timestamp string into the standard `@timestamp` (why this matters: without it, Kibana uses the ingest time rather than the event time, distorting the investigation timeline):

```
date {
  match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
  target => "@timestamp"
  timezone => "Asia/Ho_Chi_Minh"
}
```

**mutate filter** — transforms fields:

```
mutate {
  convert    => { "status" => "integer" "bytes" => "integer" }
  lowercase  => [ "method" ]
  rename     => { "clientip" => "[source][ip]" }
  remove_field => [ "timestamp", "host" ]
  gsub       => [ "referrer", "[\"]", "" ]
}
```

**geoip filter** — enriches an IP into coordinates/country (based on the MaxMind GeoLite2 DB):

```
geoip {
  source => "[source][ip]"
  target => "[source][geo]"
}
```
→ adds `[source][geo][country_name]`, `[source][geo][location]` (geo_point) → draw a map of attacking IPs in Kibana.

### 9.2.4 A Complete logstash.conf (runnable)

```ruby
input {
  beats {
    port => 5044
    ssl_enabled => true
    ssl_certificate => "/etc/logstash/certs/logstash.crt"
    ssl_key => "/etc/logstash/certs/logstash.key"
  }
}

filter {
  if [event][module] == "nginx" {
    grok {
      match => { "message" => "%{IPV4:clientip} - %{DATA:auth} \[%{HTTPDATE:timestamp}\] \"%{WORD:method} %{DATA:request} HTTP/%{NUMBER:httpversion}\" %{NUMBER:status:int} %{NUMBER:bytes:int} %{QS:referrer} %{QS:agent}" }
      tag_on_failure => ["_grokparsefailure_nginx"]
    }
    date {
      match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
      target => "@timestamp"
    }
    mutate {
      convert => { "status" => "integer" }
      lowercase => [ "method" ]
      remove_field => [ "timestamp" ]
    }
    geoip { source => "clientip" target => "geo" }
    useragent { source => "agent" target => "ua" }

    if [status] >= 400 and [status] < 500 {
      mutate { add_tag => ["client_error"] }
    }
  }
}

output {
  if "_grokparsefailure_nginx" in [tags] {
    file { path => "/var/log/logstash/failed_nginx.log" }
  } else {
    elasticsearch {
      hosts => ["https://es-01:9200"]
      index => "logs-nginx-%{+YYYY.MM.dd}"
      user => "logstash_writer"
      password => "${LS_ES_PASS}"
      ssl_enabled => true
      cacert => "/etc/logstash/certs/ca.crt"
    }
  }
}
```

Explanation of the decisions:
- `index => "logs-nginx-%{+YYYY.MM.dd}"`: a daily index → makes it easy to apply **ILM** (deletion/rollover) and to limit shard size.
- Splitting the output for parse-failure events → no "silent swallowing" of malformed data, so it remains investigable.
- `useragent` parses the user-agent into OS/browser → useful for detecting automated tools (curl, sqlmap, nikto).

**Logstash security notes**:
- Use a dedicated ES user `logstash_writer` with only `create_index`/`write` privileges on `logs-*` indices, not the `elastic` user.
- Pass the password via a **keystore** (`logstash-keystore add LS_ES_PASS`), do not hardcode it.
- GROK with greedy/backtracking regex on hostile input can cause **ReDoS** (100% CPU). Prefer `dissect` (no regex) for logs with a fixed structure; set `timeout_millis` for grok.

---

## 9.3 Kibana — Visualization and Querying

### 9.3.1 Index Pattern / Data View

Kibana does not store data; it queries Elasticsearch. An **Index pattern** (new name: **Data view**) declares the group of indices Kibana is allowed to query, e.g., `logs-nginx-*`, and specifies the **time field** (`@timestamp`) so the time picker works.

### 9.3.2 Discover and KQL

**Discover** is the screen for browsing raw logs. The default query language is **KQL (Kibana Query Language)** — simpler than the Query DSL, and it compiles implicitly into DSL.

| Purpose | KQL | DSL equivalent |
|---|---|---|
| Match a value | `status: 401` | `term` |
| AND | `status: 401 and method: post` | `bool.must` |
| OR | `status: 401 or status: 403` | `should` |
| NOT | `not clientip: "10.0.0.5"` | `must_not` |
| Range | `bytes > 1000` | `range` |
| Wildcard | `request: *admin*` | `wildcard` |
| Field exists | `geo.country_name: *` | `exists` |

Example of brute-force hunting in Discover:
```
event.module: "nginx" and status: 401 and request: "/login"
```
Combine with the "Last 1 hour" time picker → count the frequency by IP.

### 9.3.3 Visualization, Dashboard

- **Visualization** (Lens): draws a single chart from an aggregation — e.g., "Bar chart: count by `clientip` (terms agg), filtered on status 401" to reveal brute-forcing IPs.
- **Dashboard**: combines multiple visualizations + a shared filter + a shared time range. A typical SOC dashboard: a geo map of IPs, top failed-login IPs, a status-code-over-time chart, and a table of anomalous user-agents.

**Kibana security notes**:
- Kibana has **RBAC by space and index**: create an analyst role that can only read dashboards and `logs-*` indices, without cluster administration.
- Enable TLS between Kibana ↔ Elasticsearch and browser ↔ Kibana.
- Be wary of features that allow scripting/embedding — restrict who can create visualizations that use scripts.

---

## 9.4 Beats — Collecting Data at the Source

**Beats** is a family of lightweight agents (written in Go, statically compiled) placed on source hosts. Each beat specializes in one type of data.

| Beat | Data | Mechanism |
|---|---|---|
| Filebeat | Log files, container logs | A harvester reads the file, tracking offsets |
| Metricbeat | System/service metrics | Modules poll periodically |
| Winlogbeat | Windows Event Log | Reads via the Windows Event Log API |
| Packetbeat | Network protocols (on-the-wire decoding) | Sniffs the network |
| Auditbeat | Linux audit framework (auditd) | Reads audit events |

### 9.4.1 Filebeat — Harvester and Registry

The core mechanism:

```
filebeat.inputs path: /var/log/nginx/*.log
        │
        ▼
  One HARVESTER per open file
   - reads from the last offset (stored in the registry)
   - each line → one event
        │
        ▼
  REGISTRY (/var/lib/filebeat/registry)
   - stores {inode, offset, device} for each file
   - why by inode? to identify a file even if it is renamed (logrotate)
        │
        ▼
  SPOOLER/QUEUE → publishes to the output (Logstash/ES/Kafka)
   - at-least-once delivery: only updates the offset after the output ACKs
```

**Why at-least-once?** Filebeat advances the offset in the registry only after receiving an ACK from the destination. A crash mid-way → it resends from the old offset → may produce duplicates but **does not lose** logs. Duplicates are handled in ES via a deterministic `_id` (fingerprint).

**Module**: Filebeat ships with pre-packaged parsing configurations for common services (nginx, system, apache, auditd). A module consists of: default input paths + an ingest pipeline (parsing) + an index template + dashboards.

```bash
filebeat modules enable nginx system
filebeat setup --pipelines --modules nginx     # install the ingest pipeline into ES
filebeat setup --dashboards                     # load the Kibana dashboards
```

**Example of a complete filebeat.yml (shipping via Logstash, with TLS):**

```yaml
filebeat.inputs:
  - type: filestream
    id: nginx-access
    enabled: true
    paths:
      - /var/log/nginx/access.log
    fields:
      event.module: nginx
    fields_under_root: true
    parsers:
      - multiline:
          type: pattern
          pattern: '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
          negate: true
          match: after

filebeat.registry.path: /var/lib/filebeat/registry

processors:
  - add_host_metadata: ~
  - drop_fields:
      fields: ["agent.ephemeral_id", "ecs.version"]

output.logstash:
  hosts: ["logstash-01:5044"]
  ssl.enabled: true
  ssl.certificate_authorities: ["/etc/filebeat/certs/ca.crt"]
  ssl.certificate: "/etc/filebeat/certs/filebeat.crt"
  ssl.key: "/etc/filebeat/certs/filebeat.key"

logging.level: info
```

Explanation:
- `type: filestream` (replacing the old `log`): tracks files more reliably with logrotate.
- `multiline`: merges continuation lines (e.g., a stack trace) into a single event; the pattern is "a line starting with an IP is a new line", and other lines are appended to the previous one.
- `add_host_metadata`: attaches hostname, OS, IP → identifies the source during investigation.

### 9.4.2 Metricbeat

Collects metrics via **modules** that poll on a `period`:

```yaml
metricbeat.modules:
  - module: system
    metricsets: [cpu, memory, network, filesystem, process]
    period: 10s
    processes: ['.*']
  - module: nginx
    metricsets: [stubstatus]
    period: 10s
    hosts: ["http://127.0.0.1/nginx_status"]

output.elasticsearch:
  hosts: ["https://es-01:9200"]
  username: "metricbeat_writer"
  password: "${MB_PASS}"
  ssl.certificate_authorities: ["/etc/metricbeat/certs/ca.crt"]
```

`system.cpu.utilization` (Metricbeat) is similar in concept to `system.cpu.util` on the Zabbix side — but this is a metric for analysis, without a trigger/threshold engine like Zabbix. Metricbeat's role is also equivalent to **node_exporter** in the Prometheus world (see 9.6) — the difference is the direction of data flow: Metricbeat **pushes** to Elasticsearch, while node_exporter merely **exposes** metrics for Prometheus to pull.

### 9.4.3 Winlogbeat

Reads the Windows Event Log (Security, System, Sysmon) — a goldmine for the Blue Team:

```yaml
winlogbeat.event_logs:
  - name: Security
    event_id: 4624, 4625, 4672, 4688   # successful/failed logon, special privileges, process creation
  - name: Microsoft-Windows-Sysmon/Operational

output.logstash:
  hosts: ["logstash-01:5044"]
  ssl.enabled: true
  ssl.certificate_authorities: ["C:\\ProgramData\\winlogbeat\\ca.crt"]
```

| Event ID | Meaning | Investigative value |
|---|---|---|
| 4624 | Successful logon | Track logon type (10=RDP), source IP |
| 4625 | Failed logon | Hunt brute-force, password spraying |
| 4672 | Special privileges assigned | Detect admin logons |
| 4688 | New process created | Hunt malicious commands (requires command-line auditing enabled) |

### 9.4.4 The Overall Data Flow

```
[Source host]                [Pipeline]            [Storage/Search]      [Display]
 Filebeat ───┐
 Metricbeat ─┼──TLS:5044──▶ Logstash ──TLS:9200──▶ Elasticsearch ◀──── Kibana
 Winlogbeat ─┘             (grok/date/geoip)       (index, shard)      (Discover,
                                                                        Dashboard, KQL)

Variant: Beats ──▶ Elasticsearch directly (using an ingest pipeline instead of Logstash)
         when complex transformation is not needed (lighter, fewer components).
```

**When to drop Logstash?** If you only need simple parsing, use an **ingest pipeline** in Elasticsearch (running on an ingest node) → one fewer component. Keep Logstash when you need a large buffer (persistent queue), many non-Beats sources (syslog, kafka), or heavy transformation.

---

## 9.5 Zabbix — Infrastructure and Performance Monitoring

### 9.5.1 The Server / Agent / Proxy Architecture

```
   ┌──────────────────────────────────────────────────────────────┐
   │                      ZABBIX SERVER                             │
   │  - collects, evaluates triggers, generates events, runs actions│
   │  - writes to the DB (MySQL/PostgreSQL/TimescaleDB)             │
   └───────▲───────────────────▲────────────────────▲──────────────┘
           │ TCP 10051         │                    │
   ┌───────┴───────┐   ┌───────┴───────┐    ┌───────┴────────┐
   │ Zabbix Proxy  │   │ Zabbix Agent  │    │  SNMP / IPMI   │
   │ (one zone)    │   │ (on the host) │    │  agentless     │
   └───────▲───────┘   └───────────────┘    └────────────────┘
           │ TCP 10050
   ┌───────┴───────┐
   │ Zabbix Agent  │
   └───────────────┘

   Frontend (PHP) + Zabbix DB  → web interface, configuration, dashboards
```

| Component | Default port | Role |
|---|---|---|
| Zabbix Server | listens on 10051 | Processing core, evaluates triggers, runs actions |
| Zabbix Agent (passive) | listens on 10050 | The server asks, the agent returns item values |
| Zabbix Agent (active) | connects to 10051 | The agent proactively pushes data to the server |
| Zabbix Proxy | listens on 10051 | Collects on behalf of the server for a zone/DMZ, buffers when disconnected |
| Frontend | 80/443 | Web UI (PHP) |

**Passive vs Active agent** — the core difference:

| | Passive | Active |
|---|---|---|
| Who initiates the connection | Server → Agent (10050) | Agent → Server (10051) |
| Best suited for | Networks where the server can see the agent | Agents behind NAT/firewall, many hosts |
| Server load | Higher (the server polls each item) | Lower (the agent pushes in batches) |
| Item configuration | Asked each time | The agent fetches the item list, then collects on its own |

**Why have a Proxy?** In an environment with many sites/DMZs, the proxy collects locally and then sends the data aggregated to the server (only one connection through the firewall). The proxy also **buffers data** in its local DB when the connection to the server is lost → no metrics are lost.

### 9.5.2 The Zabbix On-the-Wire Protocol Format (Zabbix protocol)

This is the "down to the byte" part. All agent/server communication uses a fixed binary header:

```
Offset  Size        Field           Value/meaning
------  ----------  --------------  --------------------------------------------
  0      4 bytes    Protocol magic  ASCII "ZBXD"  = 0x5A 0x42 0x58 0x44
  4      1 byte     Flags           bit0=0x01 Zabbix communications protocol
                                    bit1=0x02 compression (zlib)
                                    bit2=0x04 large packet (uses 8-byte length)
  5      4 bytes    Data length     uint32 little-endian = payload length (compressed if applicable)
  9      4 bytes    Reserved        if compressed: uint32 LE = payload length after decompression
                                    if not compressed: 0x00000000
 13      N bytes    Payload         JSON (UTF-8)
```

Note: when the large-packet flag (0x04) is set, both length fields use 8 bytes each (a longer header). Verify with an actual packet capture if you need absolute accuracy for a given version.

An ASCII diagram of a real packet (uncompressed, not large packet):

```
+------+------+------+------+------+   +------+------+------+------+   +-------------+
|  Z   |  B   |  X   |  D   | flag |   |  len (4B LE)            |   | reserved(4B)| JSON...
| 5A   | 42   | 58   | 44   | 01   |   | xx   xx   xx   xx       |   | 00 00 00 00 |
+------+------+------+------+------+   +------+------+------+------+   +-------------+
   0     1      2      3      4         5                    8         9        12   13...
```

An example JSON payload when an active agent sends data:
```json
{
  "request": "agent data",
  "session": "f3...",
  "data": [
    { "host": "web01", "key": "system.cpu.util", "value": "12.50",
      "clock": 1750300530, "ns": 123456789 }
  ],
  "clock": 1750300530
}
```

| JSON field | Meaning | Example |
|---|---|---|
| `request` | Request type | `agent data`, `active checks`, `sender data` |
| `host` | Host name in Zabbix | `web01` |
| `key` | Item key | `system.cpu.util` |
| `value` | The collected value | `12.50` |
| `clock` | Epoch seconds of the measurement time | `1750300530` |
| `ns` | Nanoseconds for additional precision | `123456789` |

**Why have the "ZBXD" magic + an explicit length?** TCP is a stream with no message boundaries. The magic helps identify the protocol, and the length field tells how many payload bytes to read → cleanly framing the message. The large-packet flag allows very large payloads by using an 8-byte length.

Capture packets to verify:
```bash
tcpdump -i any -n -A 'tcp port 10051' -c 20
# or test a single item with zabbix_get (see 9.5.4)
```

### 9.5.3 Item — The Unit of Measurement

An **Item** defines "what to measure and how." Each item is tied to a **key**.

| Item component | Meaning | Example |
|---|---|---|
| Key | The measurement identifier, may have parameters | `system.cpu.util[,user]` |
| Type | How it is collected | Zabbix agent / Zabbix agent (active) / SNMP / Calculated / Dependent / HTTP / Trapper |
| Value type | Value kind | Numeric (unsigned/float), Character, Log, Text |
| Update interval | Collection frequency | `1m`, `30s` |
| History | How long to keep raw values | `7d` |
| Trends | Keep hourly statistics (min/avg/max) | `365d` |
| Preprocessing | Transform before storing | regex, JSONPath, change-per-second, throttling |

Commonly encountered item keys:

| Key | Measures |
|---|---|
| `system.cpu.util` | % CPU usage |
| `system.cpu.load[all,avg1]` | 1-minute load average |
| `vm.memory.size[available]` | Available RAM (bytes) |
| `vfs.fs.size[/,pfree]` | % free space on `/` |
| `net.if.in[eth0]` | Bytes received on eth0 (counter) |
| `net.tcp.service[ssh,,22]` | Check the SSH service (1=up, 0=down) |
| `proc.num[nginx]` | Number of nginx processes |
| `agent.ping` | Agent is alive (1) |
| `vfs.file.contents[/etc/passwd]` | (dangerous — see the note) |

**Why separate History and Trends?** History (the raw value from each measurement) grows very fast — it cannot be kept for long. Trends aggregate by the hour (min/avg/max), take up very little space, and can be kept for years to view long-term trends. This is the core strategy against DB bloat.

**Preprocessing with counters**: `net.if.in` is an increasing counter (cumulative bytes). Use the **"Change per second"** preprocessing to derive throughput in bytes/second — this is exactly the mechanism for computing rates from a counter (similar to SNMP).

### 9.5.4 A Practical Item-Collection Example

`zabbix_agentd.conf` (passive + active):
```ini
Server=10.0.0.10                 # server allowed to poll (passive), CSV
ServerActive=10.0.0.10:10051     # server for the agent to push active checks
Hostname=web01                   # must match the host name in Zabbix
ListenPort=10050
TLSConnect=psk
TLSAccept=psk
TLSPSKIdentity=PSK web01
TLSPSKFile=/etc/zabbix/zabbix_agentd.psk
```

A custom item (UserParameter) — e.g., counting the number of ESTABLISHED connections:
```ini
UserParameter=net.tcp.established,ss -ant state established | wc -l
```

Fetch a value from the server using `zabbix_get` (to verify a passive item):
```bash
zabbix_get -s 10.0.0.20 -p 10050 -k "system.cpu.util"
# Sample output:
12.5026
zabbix_get -s 10.0.0.20 -k "net.tcp.established"
47
```

Push a value manually using `zabbix_sender` (for the Trapper item type):
```bash
zabbix_sender -z 10.0.0.10 -s "web01" -k "app.queue.depth" -o 128
# Output:
# info from server: "processed: 1; failed: 0; total: 1; seconds spent: 0.000123"
# sent: 1; skipped: 0; total: 1
```

### 9.5.5 Trigger — Evaluating Conditions

A **Trigger** is a boolean expression over item data; when it is true → the state changes to **PROBLEM**, and when it is false → **OK**. This is the part that replaces a "rule" — but it is based on metric thresholds rather than security patterns.

Function syntax (Zabbix 5.4+): `function(/host/key, parameter)`.

Example real trigger expressions:

```
# 5-minute average CPU > 90%
avg(/web01/system.cpu.util,5m) > 90

# Free space on / drops below 10%
last(/web01/vfs.fs.size[/,pfree]) < 10

# Agent unresponsive for 5 minutes (no data)
nodata(/web01/agent.ping,5m) = 1

# More than 20 failed SSH logins in 5 minutes (log item counting)
sum(/web01/log.ssh.failed,5m) > 20

# A trigger with a separate recovery (hysteresis to avoid flapping):
#   Problem:  min(/web01/system.cpu.util,5m) > 90
#   Recovery: max(/web01/system.cpu.util,5m) < 80
```

| Function | Meaning |
|---|---|
| `last()` | The most recent value |
| `avg(,5m)` | Average over 5 minutes |
| `min()/max()` | Minimum/maximum over the interval |
| `count(,5m,"gt",90)` | Number of times the condition is satisfied |
| `nodata(,5m)` | =1 if there is no data in the last 5 minutes |
| `change()` | The difference from the previous value |

**Severity** of a trigger: Not classified, Information, Warning, Average, High, Disaster — it determines the alert level and color.

**Why is hysteresis (a separate recovery expression) needed?** If you only use `>90` to enter and `<=90` to leave, CPU fluctuating around 90% will generate a barrage of problem/ok events ("flapping"). Setting the entry threshold (90) higher than the exit threshold (80) → stable alerts.

### 9.5.6 Template, Host, Host Group

- **Host**: the monitored entity (server, switch, application). It has interfaces (Agent/SNMP/IPMI/JMX).
- **Host group**: a group of hosts for applying permissions and bulk operations.
- **Template**: a reusable collection of items + triggers + graphs + macros. Attaching a template to a host → the host inherits all items/triggers. For example, the `Linux by Zabbix agent` template provides dozens of CPU/RAM/disk/net items out of the box.

**Macros** enable parameterization: in a trigger, use `{$CPU.UTIL.CRIT}` instead of hardcoding 90; override the macro at the host level for exceptions. Why? One template is applied to 500 hosts, but a few DB hosts need a different threshold → you only override the macro on those hosts.

### 9.5.7 Action, Operation, Media

When a trigger generates an **event**, an **Action** decides the response:

```
Event (trigger PROBLEM)
   │
   ▼ Action conditions  (e.g.: severity >= High AND host group = Production)
   │
   ▼ Operations
       - send a message via Media (Email/Telegram/Slack/Webhook)
       - run a remote command (e.g., restart a service) — use caution
   │
   ▼ Recovery operations  (send an OK notification)
   │
   ▼ Escalation (repeat/escalate if no one has acted after X minutes)
```

- **Media type**: the delivery channel (Email SMTP, Telegram bot, Slack, custom webhook script).
- **User media**: assigns a channel to a user along with their on-call schedule and the severities they care about.

Example webhook media (JavaScript) sending an alert — a Zabbix webhook media type receives macros via parameters, e.g., `{ALERT.MESSAGE}`, `{EVENT.SEVERITY}`:
```javascript
var params = JSON.parse(value);
var req = new HttpRequest();
req.addHeader('Content-Type: application/json');
var resp = req.post('https://hooks.example/alert',
  JSON.stringify({ text: params.message, severity: params.severity }));
return resp;
```

**Action security note**: a **Remote command** allows Zabbix to run commands on the agent — if `EnableRemoteCommands`/`AllowKey=system.run[*]` is enabled carelessly, a compromised server = RCE across the entire fleet. It should be disabled by default; if enabled, restrict `AllowKey`/`DenyKey` and the specific commands.

### 9.5.8 Dashboard and Latest Data

- **Latest data**: a table of the most recent item values by host — used for a quick check.
- **Graph**: plots a time series from history/trends.
- **Dashboard**: widgets (graph, problem list, topology map, gauge) — e.g., a NOC view: a host map (green=OK, red=problem), top CPU, a list of open problems.

### 9.5.9 Overall Zabbix Security Notes

- **TLS/PSK**: by default the agent↔server channel is **unencrypted**. Enable `TLSConnect`/`TLSAccept` with PSK or certificates. Not enabling it = anyone who can sniff will see the metrics and may spoof the trapper.
- **Dangerous items**: `system.run[...]`, `vfs.file.contents[...]` can read sensitive files/run commands. Use `AllowKey`/`DenyKey` in the agent config to whitelist.
  ```ini
  DenyKey=system.run[*]
  AllowKey=vfs.file.contents[/var/log/app/*]
  ```
- **PHP frontend**: it has had numerous SQLi/XSS CVEs. Place it behind a reverse proxy, use HTTPS, restrict IP access, and apply patches promptly.
- **DB credentials** in `zabbix_server.conf` — set file permissions to 600, and grant the DB user minimal privileges.

---

## 9.6 Prometheus — Pull-Model Metric Monitoring

### 9.6.1 What Prometheus Is and What Problem It Solves

**Prometheus** is an open-source metric-monitoring system, originally from SoundCloud and the second project to "graduate" from the CNCF (after Kubernetes). It solves the same problem as Zabbix — "is the system healthy, which metric breached its threshold" — but with a different philosophy:

- **Pull model**: the Prometheus server **actively pulls** (scrapes) metrics from each target's HTTP `/metrics` endpoint, on a configured interval. The target pushes nothing — it merely *exposes* its current state as text.
- **Metrics are labeled time-series**: each series is identified by a metric name + a set of key=value pairs (labels). Slicing data by label is a first-class operation; there is no need to pre-declare each "item" as in Zabbix.
- **Configuration as files** (YAML + rule files): the entire scrape config and all alert rules live in text files → they go into Git and get reviewed like code (matching the GitOps spirit of chapter 7). Zabbix is the opposite: configuration lives in the DB and is manipulated through the GUI.
- **Local TSDB**: Prometheus stores data on its own disk (2-hour blocks + WAL), needing no external DB. The default retention is 15 days (`--storage.tsdb.retention.time`) — long-term storage requires an add-on (Thanos, Mimir, VictoriaMetrics — verify the choices at the time of reading).

**Why pull instead of push?** Three pragmatic reasons: (1) the server controls the collection pace — adding 100 targets cannot flood the server with unplanned data; (2) dead targets are detected immediately — a failed scrape makes the metric `up == 0`, giving you a "host missing" alert for free without a separate heartbeat mechanism (equivalent to Zabbix's `nodata()` but more natural); (3) debugging is easy — open a browser at `http://target:9100/metrics` and you see exactly what the server sees. The downsides: the server must be able to *reach* the target (inbound NAT/firewall is a real problem); short-lived jobs (batch/cron) die before they can be scraped — solved with the **Pushgateway** (the job pushes its result there, and Prometheus scrapes the Pushgateway).

### 9.6.2 Architecture: Server, Exporter, Scrape

```
   ┌─────────────────────────────────────────────────────────┐
   │                  PROMETHEUS SERVER                       │
   │  Retrieval (scrape) ──▶ TSDB (blocks + WAL on disk)      │
   │        │                    │                            │
   │        │              HTTP API /api/v1/query  ◀── Grafana│
   │        ▼                    │                            │
   │  Rule evaluation ───────────┼──▶ FIRING alerts           │
   └────────┬────────────────────┼────────────┬───────────────┘
            │ HTTP GET /metrics  │            │ HTTP POST
            ▼ (every 15-60s)     │            ▼
   ┌────────────────┐   ┌────────────────┐  ┌──────────────┐
   │ node_exporter  │   │ app exposing   │  │ ALERTMANAGER │
   │ :9100 (host)   │   │ /metrics (SDK) │  │ group/route/ │
   └────────────────┘   └────────────────┘  │ notify       │
                                            └──────────────┘
```

| Component | Default port | Role |
|---|---|---|
| Prometheus server | 9090 | Scrapes, stores the TSDB, runs PromQL, evaluates alerting rules |
| node_exporter | 9100 | Exposes the host's Linux OS metrics |
| Alertmanager | 9093 | Receives alerts from the server, groups, routes, sends notifications |
| Pushgateway | 9091 | Intermediary for short-lived batch jobs |
| Other exporters | 9xxx | blackbox (HTTP/ICMP probing), mysqld, nginx, redis... one exporter per service |

The **exporter** is the architectural difference from the Zabbix agent: instead of one universal agent answering every item key, the Prometheus world uses many small exporters — each translating the state of one system (kernel, MySQL, nginx) into the `/metrics` text format. Applications you write yourself embed a client library (Go/Python/Java...) to expose business metrics directly.

A minimal runnable `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s          # default pull interval
  evaluation_interval: 15s      # rule evaluation interval

rule_files:
  - "rules/*.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets: ["alertmanager:9093"]

scrape_configs:
  - job_name: "prometheus"      # monitor itself
    static_configs:
      - targets: ["localhost:9090"]

  - job_name: "node"
    static_configs:
      - targets:
          - "10.0.0.20:9100"
          - "10.0.0.21:9100"
        labels:
          env: "prod"
```

Every scraped target automatically gets two identifying labels: `job` (the job name) and `instance` (host:port). In dynamic environments (Kubernetes, cloud), replace `static_configs` with **service discovery** (`kubernetes_sd_configs`, `ec2_sd_configs`...) — targets that appear and disappear are discovered automatically, and nobody has to "register hosts" by hand.

The text format an exporter exposes (run `curl http://10.0.0.20:9100/metrics` to see it):

```
# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode.
# TYPE node_cpu_seconds_total counter
node_cpu_seconds_total{cpu="0",mode="idle"} 8.5230889e+06
node_cpu_seconds_total{cpu="0",mode="iowait"} 12043.02
node_cpu_seconds_total{cpu="0",mode="steal"} 3894.77
node_cpu_seconds_total{cpu="0",mode="user"} 118920.31
node_memory_MemAvailable_bytes 6.442450944e+09
```

### 9.6.3 The Data Model — Metric Name, Labels, and the 4 Metric Types

A time-series = **metric name + label set**; each sample = (millisecond timestamp, float64 value). For example, `node_cpu_seconds_total{cpu="0",mode="idle",instance="10.0.0.20:9100",job="node"}` is *one* series; change any label and it is *another* series. The important consequence: **label cardinality** determines cost — a label with unbounded values (user ID, full URL, client IP) will spawn millions of series and kill the server (analogous to mapping explosion in Elasticsearch, see 9.1.2).

The four metric types:

| Type | Nature | Example | Correct usage |
|---|---|---|---|
| **Counter** | Only increases (resets to 0 on process restart) | `node_cpu_seconds_total`, `http_requests_total` | Never read the raw value; always go through `rate()`/`increase()` |
| **Gauge** | Goes up and down freely | `node_memory_MemAvailable_bytes`, `node_load1` | Read directly, `avg_over_time()` |
| **Histogram** | Counts observations into `le` buckets (with `_sum`, `_count`) | `http_request_duration_seconds_bucket` | `histogram_quantile(0.95, ...)` computes percentiles server-side |
| **Summary** | Percentiles precomputed client-side | `..._{quantile="0.99"}` | Read directly, but cannot be aggregated across instances |

**Why do counters only increase?** To tolerate lost samples: between two scrapes, even if a few samples are lost, the difference between two counter values still tells exactly how much it grew in that window. `rate()` also handles counter resets automatically (a value dropping = process restart → it compensates). This is why the `_total` naming convention exists, along with the mantra "a raw counter is meaningless; the rate of a counter is meaningful" — equivalent to the "Change per second" preprocessing in Zabbix (9.5.3).

**Histogram vs Summary**: a histogram computes percentiles at *query* time, so it can be aggregated fleet-wide ("p95 of the whole cluster"); a summary is precomputed at the *client*, so it is more accurate for a single instance but cannot be merged. In practice most people choose histograms.

### 9.6.4 node_exporter — The System Metrics Most Worth Watching

node_exporter reads `/proc` and `/sys` and exposes a few thousand series. The groups I use daily:

| Group | Metric | Type | Operational meaning |
|---|---|---|---|
| CPU | `node_cpu_seconds_total{mode=...}` | counter | CPU seconds by mode: `user`, `system`, `iowait`, `steal`, `idle`... Reading by *mode* is what makes diagnosis possible: high `iowait` = a disk bottleneck, not a CPU shortage; high `steal` = the hypervisor throttling the VM (a noisy neighbor in the cloud) |
| Memory | `node_memory_MemAvailable_bytes`, `node_memory_MemTotal_bytes` | gauge | Look at **available**, not "used" — Linux uses free RAM as page cache, so used is always high |
| PSI | `node_pressure_memory_waiting_seconds_total`, `node_pressure_cpu_waiting_seconds_total`, `node_pressure_io_waiting_seconds_total` | counter | **Pressure Stall Information** (kernel ≥ 4.20): total time some process had to *stall waiting* for a resource. Its `rate()` = the fraction of time spent starved — a more honest "truly short of it" signal than any % used number |
| Filesystem | `node_filesystem_avail_bytes`, `node_filesystem_files_free` | gauge | Free space and free **inodes** (running out of inodes also means "disk full" even with GBs left) |
| Disk I/O | `node_disk_io_time_seconds_total`, `node_disk_read_bytes_total`, `node_disk_written_bytes_total` | counter | `rate(io_time)` ≈ `iostat`'s %util; read/write throughput |
| Network | `node_network_receive_bytes_total`, `node_network_receive_drop_total`, `node_network_receive_errs_total` | counter | Network alerts should watch **drops/errors**, not % bandwidth |
| Load/Procs | `node_load1`, `node_procs_blocked` | gauge | `procs_blocked` = processes in state D (stuck on I/O) — high load + high blocked = a disk bottleneck, not a CPU shortage |

How to read these same signals with *commands* on the machine itself (mpstat, PSI, iostat, ss...) is in chapter 2 (Linux) — the dashboard and the commands are two halves of the same runbook.

### 9.6.5 Basic PromQL — Queries Used for Real

PromQL operates on two main value kinds: an **instant vector** (one value per series at one point in time — `node_load1`) and a **range vector** (a run of samples per series within a time window — `node_cpu_seconds_total[5m]`). Functions like `rate()` take a range vector and return an instant vector.

```promql
# 1. CPU usage % per machine (the classic trick: 100% minus the idle share)
100 * (1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])))

# 2. CPU split by mode — the "CPU by mode" panel is exactly this query
sum by (mode) (rate(node_cpu_seconds_total{instance="10.0.0.20:9100"}[5m]))

# 3. % RAM available (watch available, not used)
100 * node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes

# 4. Real memory pressure (PSI) — fraction of time processes stalled waiting for RAM
rate(node_pressure_memory_waiting_seconds_total[5m])

# 5. % free disk on the / mount
100 * node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}

# 6. Forecast: at the last 6 hours' pace, will / be full in 24 hours? (negative = it will)
predict_linear(node_filesystem_avail_bytes{mountpoint="/"}[6h], 24*3600) < 0

# 7. Packet drops on every interface (excluding loopback)
rate(node_network_receive_drop_total{device!="lo"}[5m])

# 8. Which machines have gone missing (scrape failing)
up == 0
```

Common stumbling points:

- `rate()` needs a window ≥ 2× the `scrape_interval` (the usual convention is ≥ 4×, e.g., a 15s interval → a minimum 1m window) — too short a window produces a gappy graph.
- `sum(node_cpu_seconds_total)` without `rate()` is meaningless (it adds up counters accumulated since boot).
- `by (label)` keeps a label for grouping, `without (label)` drops it — `sum by (mode)` merges all CPUs/instances but keeps the mode.
- `predict_linear` is a linear regression over a range vector — "the disk *will* be full within 24h" is worth far more than "the disk *is* above 90%": it alerts while there is still time to act, and it does not cry wolf about a machine sitting stable at 91%.

### 9.6.6 Alerting Rules and Alertmanager

Prometheus splits alerting in two: the **server** evaluates rules and fires alerts; **Alertmanager** receives them and then groups, deduplicates, routes, and delivers. Why the split? So that multiple Prometheus servers can share one notification-management point, and so the logic of "who gets told, when, grouped how" does not mix with the logic of "what is abnormal".

A rule file (`rules/node.yml`):

```yaml
groups:
  - name: node-health
    rules:
      - alert: HostDiskWillFillIn24h
        expr: predict_linear(node_filesystem_avail_bytes{mountpoint="/"}[6h], 24*3600) < 0
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "Disk / on {{ $labels.instance }} will fill in ~24h"

      - alert: HostHighCpu
        expr: 100 * (1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m]))) > 90
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "CPU on {{ $labels.instance }} > 90% for 15 minutes"

      - alert: HostDown
        expr: up{job="node"} == 0
        for: 3m
        labels:
          severity: critical
        annotations:
          summary: "{{ $labels.instance }} unscrapeable for 3 minutes"
```

The **`for`** field is the noise gate: the expression must hold *continuously* for that duration before the alert moves from `pending` to `firing` — the same role as Zabbix trigger hysteresis (9.5.5): a 30-second CPU spike is not worth waking anyone up.

`alertmanager.yml` — routes form a tree, receivers are delivery targets:

```yaml
route:
  receiver: ops-default            # default branch
  group_by: [alertname, instance]  # merge same-kind alerts into 1 notification
  group_wait: 30s                  # wait to gather more alerts of the same group
  repeat_interval: 4h              # re-notify if nobody has acted
  routes:
    - matchers: [ severity="critical" ]
      receiver: ops-oncall         # critical takes its own path

receivers:
  - name: ops-default
    webhook_configs:
      - url: "https://hooks.example/ops-channel"
  - name: ops-oncall
    webhook_configs:
      - url: "https://hooks.example/oncall"
```

Beyond routing, Alertmanager has **silences** (mute by matcher during maintenance windows, created via UI/API) and **inhibition** (a big alert suppresses smaller ones: once a host is `HostDown`, do not also send 15 CPU/RAM alerts for that same host).

**Prometheus security notes**:

- `/metrics` leaks plenty of reconnaissance material (kernel version, mount points, interface names, sometimes application paths). node_exporter has **no authentication** — bind it to internal networks only and firewall ports 9100/9090/9093 away from the Internet.
- Prometheus/Alertmanager themselves support TLS + basic auth for the web/API (since Prometheus 2.24 — needs verification); before that, and often still today, they are placed behind a reverse proxy for access control.
- The Prometheus UI allows arbitrary PromQL over all data — treat it as an admin tool, do not expose it publicly.

### 9.6.7 Prometheus vs Zabbix — When to Choose Which

| Criterion | Zabbix | Prometheus |
|---|---|---|
| Collection model | Push (active) / per-item poll (passive), SNMP/IPMI | Pull-scrapes HTTP endpoints |
| Configuration | GUI + templates, stored in the DB | YAML + rule files → Git/reviewable |
| Data model | Flat item keys per host | Multi-dimensional metric + labels, slice at will |
| Query language | Trigger functions over single items | PromQL — computes over the whole fleet in one expression |
| Dynamic targets (containers, autoscaling) | Weaker (host registration, LLD) | Very strong (service discovery) |
| Network devices (SNMP), physical servers | Very strong, templates included | Via snmp_exporter, more painful |
| Long-term storage | History/Trends in the DB, kept for years | Local TSDB ~weeks; long-term needs Thanos/Mimir/remote write |
| Alerting | Trigger + action + escalation in one system | Rules (server) + Alertmanager (routing) split in two |

My rule of thumb: a **static** infrastructure with **many SNMP network devices and a formal on-call escalation process** → Zabbix is still excellent. A **cloud/container** infrastructure with targets constantly appearing and dying, and a team already used to IaC → Prometheus + Grafana is the ecosystem default (Kubernetes exposes metrics in the Prometheus format natively). On the systems I operate, I use Prometheus + node_exporter + Grafana for all server metrics; Zabbix is something I studied to understand the traditional monitoring model — and because many companies in Vietnam still run it.

---

## 9.7 Grafana — A Single Pane of Glass for Many Data Sources

### 9.7.1 What Grafana Is and What Problem It Solves

**Grafana** is an open-source dashboard platform. It **stores no metrics or logs at all** — every time it draws something, it takes the query to a **datasource** (Prometheus, Elasticsearch/OpenSearch, Loki, MySQL, CloudWatch...) and renders the result. The problem it solves is very mundane: every tool has its own UI (Prometheus has a bare-bones UI, Kibana only sees Elasticsearch, Zabbix has its own frontend) — and in real operations nobody wants to open 4 tabs to answer "is the system OK". Grafana lets **one dashboard mix panels from multiple sources**: a CPU panel reading from Prometheus sits right next to an alert-count panel reading from the Wazuh index.

For security people, this is the killer feature: **the security dashboard and the performance dashboard live in the same place**. The Wazuh indexer is OpenSearch under the hood (see 9.9), so pointing a Grafana datasource at it lets you query `wazuh-alerts-*` like any other data — I built my SOC dashboard in Grafana without touching the Wazuh dashboard at all.

### 9.7.2 Datasources

| Datasource | Data kind | Query language in the panel |
|---|---|---|
| Prometheus | Metric time-series | PromQL |
| Elasticsearch / OpenSearch | Documents/logs | Lucene query string + aggregations configured in the panel |
| Loki | Logs (Prometheus-style labels) | LogQL |
| MySQL/PostgreSQL | Relational tables | SQL |
| CloudWatch, Azure Monitor... | Cloud metrics | Their own query builders |

Each datasource declares a URL + credentials (kept server-side in Grafana, encrypted in its DB). The least-privilege principle applies exactly as in 9.1.5: the user Grafana uses to read Elasticsearch/OpenSearch needs only `read` on exactly the indices being drawn (`wazuh-alerts-*`, `logs-*`) — never admin.

### 9.7.3 Dashboard, Panel, Variable

- **Panel**: one display tile = one (or a few) queries + one visualization type (time series, gauge, stat, table, bar chart, heatmap). Color thresholds (green/yellow/red) are set right in the panel — "the panel went red" becomes the whole team's shared language.
- **Dashboard**: a grid of panels sharing a time range and filters. An entire dashboard is **one JSON file** — exportable, importable, committable to Git (GitOps again).
- **Variable**: a dropdown at the top of the dashboard, e.g., `instance` populated dynamically with `label_values(node_uname_info, instance)` — every panel uses `$instance` in its query. That is how **one** dashboard serves the whole fleet instead of one copy per machine.
- **Community dashboards**: grafana.com hosts a library of dashboards with IDs for direct import (e.g., "Node Exporter Full" for node_exporter). My experience: import them to learn how people write the queries, then **build a leaner one yourself** — a 40-panel dashboard shows everything and says nothing; my own 7-8 panels of exactly what I need are what actually get used daily.

### 9.7.4 Grafana Alerting vs Alertmanager

Grafana has its own alerting system (unified alerting, since Grafana 8): rules defined on any datasource, evaluated on a schedule, delivered via contact points (email/webhook/chat), optionally forwarded to an external Alertmanager. So does it overlap with Prometheus's Alertmanager? How I divide the roles:

| | Prometheus rules + Alertmanager | Grafana alerting |
|---|---|---|
| Where rules live | YAML files next to the server, reviewed via Git | Grafana's DB, created via the UI |
| Proximity to data | Right at the TSDB, no extra hop | One more layer (Grafana queries the datasource) |
| Multi-datasource | Prometheus only | Any datasource (including Elasticsearch) |
| Best for | Standardized infrastructure alerts, large fleets | Alerts that mix sources, or teams that prefer the UI |

The principle I follow: **core infrastructure alerts belong at the lowest layer possible** (Prometheus rules + Alertmanager) — they keep running even if Grafana dies; Grafana alerting is for the nice-to-have alerts on data Alertmanager cannot reach (e.g., count thresholds on a log index).

### 9.7.5 Field Experience: The Two Dashboards I Use Every Day

**The "SOC Analyst View" dashboard** — self-built, with the `wazuh-alerts-*` index on the Wazuh indexer (OpenSearch) as its datasource:

| Panel | Query/aggregation | Question it answers |
|---|---|---|
| Alerts over time, split by severity | date histogram + terms on `rule.level` | Is there an alert "storm" today, and when did it start |
| Top triggered rules | terms on `rule.id` / `rule.description` | Which event type is dominating |
| **Top source IPs** | terms on `data.srcip` | Which IP is paying us the most "attention" |
| Top targeted agents | terms on `agent.name` | Which machine is taking the most hits |
| Latest high-level alerts table | filter `rule.level >= 10`, sorted by time | What needs opening Wazuh for right now |

The Top source IPs panel has earned its keep the most: on one morning glance, I saw an unfamiliar IP shoot to the top of the list with hundreds of alerts packed into a few hours — pulling the thread revealed a foreign VPS running a methodical path-traversal scan against a dev machine. Without that panel, each individual medium-level alert would have drifted by as background noise; grouped by IP, the *campaign* took shape. The deep-dive investigation (aggregation queries directly on the index, reading `full_log`) is in chapter 8 (Wazuh); the nginx-side response (rate limiting, blocking sensitive filenames) is in chapter 11.

**The node metrics dashboard** — one row per resource group, with a `$instance` variable to pick the machine:

- **CPU by mode** (query no. 2 in 9.6.5): the colors are the diagnosis — `iowait` swelling = disk, `steal` swelling = hypervisor, `user` swelling = the app.
- **Memory available + Memory PSI**: two panels side by side, and PSI is the deciding one (see My notes at the end of the chapter).
- **Root FS** + the `predict_linear` result: how much is left, and how long until full.
- **Disk I/O** (`rate(node_disk_io_time_seconds_total)`) + **I/O PSI**.
- **Network** (throughput + drops/errors).
- **Procs blocked** (`node_procs_blocked`): an overlooked but extremely sensitive indicator of I/O congestion.

The philosophy of use: **the dashboard tells you where it is high; SSH + commands tell you which process caused it.** A panel only answers "CPU is high" or "memory PSI has stayed positive" — finding *which process* means logging into the machine and running `htop`, `mpstat -P ALL`, `ps aux --sort=-%mem`, reading `/proc/pressure/*`... The per-panel command set lives in chapter 2 (Linux) as a "panel goes red → run this first" runbook. The two are a pair: a dashboard without a runbook is just something to stare at, and a runbook without a dashboard gives you nowhere to start.

**Grafana security notes**:

- Change the default `admin/admin` account immediately; enable HTTPS; put it behind a reverse proxy if exposed.
- Grafana has had serious CVEs exploited in the wild (notably the CVE-2021-43798 path traversal reading arbitrary files via a plugin URL) — patch it like the genuinely public web application it is.
- Use org/team/folder permissions: viewers see dashboards but cannot edit datasources. Remember that anyone who can edit a panel can *run arbitrary queries* with the server's datasource credentials — editor rights are a form of data-read rights.
- Never embed secrets in queries/annotations; dashboard JSON gets shared publicly all the time — scrub it before posting (internal hostnames, IPs, index names).

---

## 9.8 Zabbix/Prometheus vs SIEM — A Fundamental Distinction

This is a frequently confused point. **Monitoring (Zabbix, Prometheus) watches "infrastructure state/performance"**, while **SIEM analyzes "security events"**. They differ in their data model and detection engine.

| Criterion | Monitoring (Zabbix / Prometheus) | SIEM (Wazuh / Elastic Security / Splunk ES) |
|---|---|---|
| Data | Numeric metrics over time (CPU, RAM, disk, up/down) | Normalized logs/events from many sources |
| Detection | Threshold triggers/alerting rules on metrics | Decoder + rule + behavioral correlation |
| Question | "Is the system healthy?" | "Is anyone attacking?" |
| Multi-source correlation | Limited (mostly by host/metric) | Strong (correlation across logs, MITRE ATT&CK) |
| Storage | RDBMS/TSDB, history+trends | Full-text index (Elasticsearch/Lucene) |
| Ideal for | Ops/SRE, availability, capacity | SOC, threat detection, IR, compliance |

A "disk full" incident is a Zabbix/Prometheus job. A chain of "1000 failed logins followed by 1 success from an unfamiliar IP" is the SIEM's job. The two domains **complement** rather than replace each other. That said, metrics still carry indirect security value: CPU spiking abnormally at 3 a.m. (a cryptominer), network egress surging (exfiltration) — the performance dashboard is sometimes the first messenger, but confirmation always goes back to the logs/SIEM.

---

## 9.9 When to Use ELK vs Wazuh vs Zabbix vs Prometheus/Grafana

| Need | Suitable tool | Reason |
|---|---|---|
| Centralize and full-text search high-volume logs, build custom investigation dashboards | **ELK** | A powerful search engine, flexible mapping/query DSL |
| Ready-to-use threat detection: HIDS, FIM, rootcheck, MITRE rules, compliance (PCI, CIS), cross-platform agents | **Wazuh** | An open-source SIEM/XDR with built-in decoders+rules, typically built on Elasticsearch/OpenSearch itself for storage/display |
| Traditional infrastructure monitoring, SNMP/IPMI network devices, formal on-call escalation processes | **Zabbix** | A trigger engine + templates + distributed proxies, agentless SNMP/IPMI |
| Metric monitoring for cloud/container infrastructure, dynamic targets, alerts as code | **Prometheus** | Pull model + service discovery + PromQL + Alertmanager; file-based configuration fits GitOps |
| One shared dashboard for both metrics and logs/security, across multiple data sources | **Grafana** | Multi-system datasources (Prometheus, Elasticsearch/OpenSearch...), panels/variables/alerting unified in a single pane of glass |

The technical relationships to grasp:
- **Wazuh uses the Elastic Stack/OpenSearch as its storage/display foundation** (the Wazuh indexer is based on OpenSearch ~ Elasticsearch; the Wazuh dashboard ~ Kibana). That is, ELK is the **data infrastructure foundation**, and Wazuh adds a **security detection layer** (decoders, rules, agents, FIM) on top.
- **Pure ELK** can also serve as a SIEM if you use Elastic Security (detection rules, the ECS schema), but you must build/apply the rules yourself; Wazuh provides far more out of the box.
- **Zabbix and Prometheus** both stand in the monitoring domain; they do not compete with ELK/Wazuh but run alongside them. Between the two, choose by the problem (see 9.6.7) — you rarely need both.
- **Grafana reads both domains**: point a datasource at Prometheus and you have a performance dashboard; point one at the Wazuh indexer (OpenSearch) and you have a security dashboard — in the same place. Kibana/Wazuh dashboard remain stronger for *interactive investigation* (Discover, Dev Tools); Grafana wins for the *daily watch screen*.

A reference architecture within an organization (the stack I operate):
```
   Infrastructure/performance ──▶ node_exporter ──▶ Prometheus ──▶ Alertmanager (ops alerts)
                                                        │
   Logs & security events ──▶ agents ──▶ Wazuh ─────────┼──▶ Wazuh indexer (OpenSearch)
                                                        │            │
                                                        └────────────┴──▶ GRAFANA (one pane:
                                                                          node metrics dashboard
                                                                          + SOC dashboard)
   Traditional variant: Zabbix instead of Prometheus; Beats/Logstash ──▶ Elasticsearch ──▶ Kibana
```

---

## 9.10 Summary of the Core Design Decisions

| Decision | Why |
|---|---|
| Inverted index + BM25 | Fast full-text search across billions of docs; saturated scoring resists keyword stuffing |
| Separating doc values from the inverted index | Sort/aggregate need columnar access by docId |
| Fixed number of primary shards | Routing uses `% n_shards`; changing it = a full reindex |
| Translog | Recover un-fsynced segments after a crash |
| `dynamic: strict` mapping | Prevents mapping explosion (heap DoS) |
| Filebeat at-least-once + registry inode | No log loss across logrotate/crash |
| Zabbix History vs Trends | History bloats fast → keep short; Trends aggregate by hour → keep long |
| Trigger hysteresis / `for` in alerting rules | Prevents alert flapping; short spikes are not worth waking anyone up |
| "ZBXD" magic + length header | Frames messages over a TCP stream |
| Prometheus pull model | The server controls the pace; `up == 0` detects dead targets for free; debug with a browser |
| Ever-increasing counters + `rate()` | Tolerates lost samples, handles resets; the raw value is meaningless, the rate of change is meaningful |
| Metric name + labels instead of flat item keys | Multi-dimensional slicing (`sum by (mode)`) — but cardinality must be controlled |
| Alertmanager separated from the Prometheus server | "What is abnormal" (rules) split from "who to tell and how to group" (routing) |
| Grafana stores no data | A multi-datasource pane of glass: metrics + logs/security in one dashboard |
| Zabbix TLS/PSK, ES xpack.security, internal-only `/metrics` | Unencrypted/unauthenticated by default = data leak/spoofing |
| Monitoring ≠ SIEM | Metric/threshold vs event/correlation — they complement each other |


---

## My notes

> *Personal notes: points I previously misunderstood, areas I'm still exploring, or lessons from hands-on practice — updated over time.*

- **Studied Zabbix, operate Prometheus** — I studied Zabbix quite thoroughly (triggers, templates, the wire protocol), but the systems I actually operate run Prometheus + Grafana, and the two feel completely different. Zabbix feels like "administration software": everything through the GUI, configuration living in a DB, and afterwards I can't remember what I clicked. With Prometheus everything is a file — changing an alert rule is a commit, and reading the diff later tells you who changed what and why. Learning Zabbix wasn't wasted: it taught me what triggers/hysteresis/escalation are before I met `for`/routes/inhibition, and plenty of companies here still run Zabbix for real.
- **PSI is more trustworthy than %RAM used** — a lesson I paid for with a few small heart attacks. The memory-used panel would glow red; I'd SSH in and the machine was perfectly fine: "used" RAM is high because Linux exploits free RAM as page cache and apps (especially anything with a big JVM/heap) reserve memory up front. Since adding the PSI panel (`rate(node_pressure_memory_waiting_seconds_total[5m])`), I barely look at % used anymore: if PSI is zero, whatever "used" says, I don't care; PSI staying positive is what real memory shortage looks like — and at that point `vmstat` will show si/so and `dmesg` will be circling around an OOM kill.
- **%steal — a metric I didn't know existed.** One machine in a system I operate would show a high CPU panel while `htop` showed no process eating anything. It turned out to be `steal`: a cloud VM being throttled by the hypervisor (noisy neighbor). Since then my CPU panel always splits by mode instead of drawing one "CPU %" line — the same "CPU is high" can be `user`, `iowait`, or `steal`: three different diseases with three different treatments (and steal, in particular, is not your machine's fault).
- **The Top source IPs panel is the cheapest panel that has earned the most.** It is just a terms aggregation by source IP over the Wazuh alert index, but it is what let me catch a path-traversal scanning campaign early: an unfamiliar IP sitting at the top of the list with hundreds of alerts packed into a few hours. Individually, each medium-level alert would have drowned in the noise; grouped by IP, the *deliberate* behavior surfaced immediately. The bigger lesson: a security dashboard doesn't need to be impressive, it needs to ask the few questions I genuinely want answered every morning.
- **The dashboard tells you where it's high; the commands tell you which process caused it.** Early on I would sit staring at Grafana waiting for it to "name" the culprit — it can't, because node_exporter doesn't expose per-process metrics. So I wrote an actual runbook: for each panel that goes red, which commands to run first after SSH-ing in (it lives in chapter 2). Since pairing the dashboard with the runbook, the time from "saw red" to "know why" has dropped noticeably.
- **Still exploring**: recording rules (precomputing heavy queries), long-term metric storage (Thanos/Mimir — only read about them, haven't deployed), and Loki as a lightweight log companion to Prometheus, to see whether it can replace part of the ELK use case for small systems.
