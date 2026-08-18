# Chương 9 — Observability & Giám sát hạ tầng

## Tổng quan

Mình bắt đầu để ý mảng này sau vài lần bị hỏi "server load cao từ lúc nào vậy" mà chẳng có gì để tra ngoài cảm giác — không log, không biểu đồ, chỉ đoán. Theo dõi hạ tầng nghiêm túc cần tách bạch hai thứ: log kể lại chuyện gì đã xảy ra, còn metric cho biết hệ thống có đang khỏe không tại một thời điểm. Chương này đi qua bốn công cụ trả lời cho hai câu hỏi đó — dấu vết tấn công nằm trong log, còn sự cố hạ tầng thường khởi đầu từ một chỉ số bất thường, nên cả hai đều thiết yếu với an toàn thông tin.

Nửa đầu chương là **ELK Stack** — Elasticsearch, Logstash, Kibana, cộng họ agent **Beats** (Filebeat, Metricbeat, Winlogbeat...) thu log tại nguồn. Log tự nó chỉ là bản ghi sự kiện rời rạc trên từng máy; ELK giải bài toán gom log phân tán về một chỗ rồi làm cho nó tìm được: Elasticsearch dùng inverted index để tra full-text ở quy mô tỷ bản ghi mà RDBMS không kham nổi, Logstash đứng giữa parse và chuẩn hóa log thô thành dữ liệu sạch, còn Kibana biến dữ liệu đã lập chỉ mục đó thành biểu đồ và dashboard — nhìn ra bất thường nhanh hơn đọc log tay nhiều.

Nửa sau là mảng metric, đại diện bởi hai công cụ giải cùng bài toán nhưng khác triết lý. **Zabbix** đo liên tục CPU, RAM, đĩa, tình trạng dịch vụ và tự cảnh báo qua cơ chế trigger khi vượt ngưỡng — kiểu monitoring truyền thống, cấu hình qua GUI/template. **Prometheus** là thế hệ cloud-native: server chủ động kéo (scrape) số liệu qua endpoint `/metrics` mà mỗi **exporter** phơi ra trên host, lưu vào TSDB riêng, truy vấn bằng PromQL, cảnh báo giao cho Alertmanager. **Grafana** đứng trên cả hai, không tự thu thập gì — chỉ vẽ dashboard từ nhiều datasource (Prometheus, Elasticsearch/OpenSearch...) lại một chỗ, thay vì mỗi công cụ một giao diện riêng.

Cuối chương có nhắc tới SIEM để phân định rạch ròi: Zabbix và Prometheus lo sức khỏe hạ tầng, còn phát hiện tấn công qua tương quan sự kiện là việc của SIEM — hai lớp bổ trợ, không thay nhau.

## 9.0 Bảng định vị công cụ

Phần Tổng quan ở trên đã giới thiệu từng công cụ. Mục này không lặp lại các định nghĩa đó, mà đặt các họ công cụ cạnh nhau để thấy rõ chúng khác nhau ở đâu — trước khi đi sâu vào từng phần. Cách trình bày của chương cũng đi tới mức **định dạng dữ liệu trên dây (wire format), cấu trúc bản ghi trên đĩa, từng trường cấu hình và từng bước xử lý** — đủ để một kỹ sư Blue Team/AppSec/DevSecOps vận hành, gỡ lỗi và đánh giá rủi ro trong thực tế.

Một điểm phân định bản chất nên ghi nhớ trước khi đọc tiếp:

| Khía cạnh | ELK Stack | Zabbix | Prometheus | SIEM (vd Wazuh, Splunk ES) |
|---|---|---|---|---|
| Đơn vị dữ liệu | Document JSON (full-text + structured) | Metric (giá trị số/chuỗi theo thời gian) | Metric time-series (tên + label, giá trị float) | Security event đã chuẩn hóa + rule correlation |
| Mô hình lưu trữ | Inverted index + doc values (Lucene) | Time-series trong RDBMS/TSDB | TSDB cục bộ (block + WAL) | Index + alert store |
| Cách thu thập | Agent (Beats) đẩy về pipeline | Agent passive/active, SNMP, proxy | Server **pull** (scrape) endpoint `/metrics` của exporter | Agent đẩy event về manager |
| Câu hỏi điển hình | "Tìm mọi request 5xx chứa chuỗi X trong 15 phút" | "CPU host A có vượt 90% trong 5 phút không?" | "rate CPU theo mode của cả fleet 5 phút qua là bao nhiêu?" | "Có chuỗi hành vi nào khớp MITRE T1110 không?" |
| Cơ chế cảnh báo | Watcher/Kibana alerting/ElastAlert (bổ sung) | Trigger expression (lõi) | Alerting rule + Alertmanager (tách riêng) | Correlation rules + decoder (lõi) |
| Bản chất | Search engine | Monitoring system | Monitoring system (TSDB + query engine) | Detection & response |

**Grafana** cố tình không có mặt trong bảng: nó không phải nơi lưu dữ liệu mà là **lớp hiển thị** đứng trên các hệ ở trên — một dashboard Grafana có thể vẽ đồng thời panel từ Prometheus (hiệu năng) và panel từ Elasticsearch/OpenSearch (log/an ninh).

Ghi nhớ: Elasticsearch **là một search engine** chứ không phải RDBMS (CSDL quan hệ); Zabbix và Prometheus **là monitoring system** chứ không phải log store; Grafana **là mặt kính** chứ không phải kho dữ liệu. Phần lớn các quyết định thiết kế bên dưới đều có thể truy ngược về các bản chất này.

---

## 9.1 Elasticsearch — Lõi lưu trữ và tìm kiếm

### 9.1.1 Inverted index — Vì sao và cấu trúc bên trong

Elasticsearch dựng trên thư viện **Apache Lucene**. Cấu trúc dữ liệu trung tâm là **inverted index** (chỉ mục đảo). Trong RDBMS, ta đi từ hàng → cột → giá trị (forward). Inverted index đảo ngược: đi từ **term (từ) → danh sách document chứa term đó**. Đây là lý do tìm full-text trên hàng tỷ document vẫn ở mức mili-giây: thay vì quét tuyến tính, ta tra cứu term rồi hợp/giao các posting list.

Quy trình đánh chỉ mục một trường text:

```
Văn bản gốc:  "The Quick Brown Fox"
   │
   ▼ (1) Character filter   — vd bỏ thẻ HTML, chuẩn hóa ký tự
   │
   ▼ (2) Tokenizer          — vd standard tokenizer tách theo ranh giới từ
   │      → ["The", "Quick", "Brown", "Fox"]
   │
   ▼ (3) Token filter       — vd lowercase, stop words, stemming
   │      → ["quick", "brown", "fox"]   (the bị loại như stop word)
   │
   ▼ Term được ghi vào inverted index
```

Cấu trúc inverted index (đơn giản hóa) cho 3 document:

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

Các thành phần Lucene lưu trên đĩa cho mỗi segment (file thực tế trong thư mục `index/.../<segment>`):

| Thành phần | Đuôi file | Nội dung | Mục đích |
|---|---|---|---|
| Term dictionary | `.tim`, `.tip` | Danh sách term đã sắp xếp + chỉ mục FST vào nó | Tra cứu term O(log) |
| Postings | `.doc`, `.pos`, `.pay` | docId, position, payload | Trả về document, hỗ trợ phrase query |
| Stored fields | `.fdt`, `.fdx` | Document gốc (`_source`) | Trả lại document đầy đủ |
| Doc values | `.dvd`, `.dvm` | Cột giá trị theo docId | Sort, aggregation, script |
| Norms | `.nvd`, `.nvm` | Chuẩn hóa độ dài trường | Tính điểm relevance (BM25) |

**Vì sao tách `doc values`?** Inverted index tối ưu cho "term → docs" nhưng tệ cho "docId → giá trị" (cần cho sort/aggregation). Doc values là cấu trúc **columnar** lưu theo cột, nén tốt, đọc tuần tự nhanh. Đó là lý do trường `text` (chỉ có inverted index) không sort/aggregate được, còn `keyword` (có doc values) thì được.

Điểm relevance mặc định là **BM25** (Best Matching 25), thay cho TF-IDF cũ. Công thức rút gọn cho mỗi term:

```
score(D,q) = IDF(q) · ( f(q,D) · (k1 + 1) ) / ( f(q,D) + k1 · (1 - b + b · |D|/avgdl) )

IDF(q) = ln( 1 + (N - n(q) + 0.5) / (n(q) + 0.5) )
```

- `f(q,D)`: tần suất term q trong document D
- `|D|`: độ dài document; `avgdl`: độ dài trung bình
- `k1` (mặc định 1.2): độ bão hòa tần suất; `b` (mặc định 0.75): mức ảnh hưởng của độ dài
- `N`: tổng số document; `n(q)`: số document chứa q

**Vì sao BM25?** TF-IDF tăng điểm tuyến tính theo tần suất, dễ bị thao túng bằng nhồi từ. BM25 có hệ số bão hòa `k1` làm điểm hội tụ — lặp một từ 100 lần không tốt hơn nhiều so với 10 lần.

### 9.1.2 Document, Index, Mapping

**Document** là đơn vị dữ liệu cơ bản, là một đối tượng JSON. Mỗi document có metadata:

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

| Trường meta | Kiểu | Ý nghĩa | Ví dụ |
|---|---|---|---|
| `_index` | string | Index chứa document | `logs-nginx-2026.06.19` |
| `_id` | string | Định danh duy nhất trong index (tự sinh nếu không cấp) | `kJ3xY4cBz1aQ` |
| `_version` | long | Số lần document bị ghi đè | `1` |
| `_seq_no` | long | Số thứ tự thao tác trên shard (dùng cho optimistic concurrency) | `42` |
| `_primary_term` | long | "Nhiệm kỳ" của primary shard, tăng khi failover | `1` |
| `_source` | object | Dữ liệu gốc người dùng | (JSON) |

**Optimistic concurrency control**: ghi có điều kiện qua `if_seq_no` + `if_primary_term`. Nếu giá trị không khớp (ai đó đã ghi trước), thao tác trả về `409 Conflict`. Cơ chế này thay cho lock — vì sao? Vì lock không khả thi trong hệ phân tán có độ trễ mạng.

**Mapping** định nghĩa kiểu dữ liệu mỗi trường. Tạo index với mapping tường minh (luôn nên làm trong production, tránh dynamic mapping đoán sai):

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

Bảng data type quan trọng:

| Type | Kích thước lưu trữ | Inverted index | Doc values | Dùng cho |
|---|---|---|---|---|
| `text` | thay đổi (đã analyze) | Có | Không | Full-text search |
| `keyword` | nguyên văn | Có (không analyze) | Có | Filter, sort, aggregate, exact match |
| `byte` | 8-bit signed | — | Có | -128..127 |
| `short` | 16-bit signed | — | Có | -32768..32767 |
| `integer` | 32-bit signed | — | Có | số nguyên |
| `long` | 64-bit signed | — | Có | số lớn, epoch ms |
| `float` | 32-bit IEEE 754 | — | Có | số thực |
| `double` | 64-bit IEEE 754 | — | Có | số thực chính xác cao |
| `date` | long (epoch ms) bên trong | — | Có | thời gian |
| `ip` | IPv4 (32-bit) / IPv6 (128-bit) | Có | Có | địa chỉ IP, hỗ trợ CIDR |
| `boolean` | true/false | — | Có | cờ |
| `geo_point` | lat/lon | — | Có | tọa độ, geo query |

Dấu `—` ở cột Inverted index nghĩa là kiểu đó không nằm trong inverted index dạng term; thay vào đó Lucene đánh chỉ mục bằng cấu trúc point/BKD-tree để tối ưu cho range query trên số, ngày, IP và tọa độ.

**Vì sao trường `request` vừa là `text` vừa có sub-field `raw` kiểu `keyword`?** Đây là pattern multi-field kinh điển: bản `text` cho phép tìm full-text ("tìm request chứa /admin"), bản `keyword` cho phép aggregate chính xác ("top 10 URL gọi nhiều nhất"). Một dữ liệu, hai cách dùng.

**Lưu ý bảo mật**: `dynamic: "strict"` từ chối document có trường lạ → ngăn **mapping explosion** (kẻ tấn công gửi log với hàng nghìn key ngẫu nhiên làm phình mapping, gây DoS bộ nhớ heap). `ignore_above: 256` ngăn term keyword quá dài làm hỏng index.

### 9.1.3 Shard, Replica, Segment

Một index được chia thành **shard**. Mỗi shard là một **chỉ mục Lucene độc lập hoàn chỉnh**. Có hai loại:

- **Primary shard**: bản gốc, nhận ghi trước.
- **Replica shard**: bản sao của primary, phục vụ đọc và đảm bảo HA.

```
Index "logs" : 3 primary, 1 replica  → tổng 6 shard

      Node A            Node B            Node C
  ┌───────────┐    ┌───────────┐    ┌───────────┐
  │  P0       │    │  P1       │    │  P2       │
  │  R2       │    │  R0       │    │  R1       │
  └───────────┘    └───────────┘    └───────────┘

Quy tắc: replica KHÔNG BAO GIỜ nằm cùng node với primary của nó
         (mất 1 node vẫn còn đủ dữ liệu)
```

Luồng ghi một document:

```
1. Client gửi index request tới coordinating node
2. Coordinating node băm routing:  shard = hash(_routing) % number_of_primary_shards
   (mặc định _routing = _id) → xác định primary shard
3. Ghi vào primary shard:
   a. Ghi vào in-memory buffer
   b. Append vào translog (write-ahead log, fsync mặc định mỗi request)
4. Primary chuyển song song tới mọi replica
5. Khi đủ replica xác nhận → trả 200 cho client
```

Vòng đời từ buffer ra segment:

```
in-memory buffer ──refresh (mặc định 1s)──▶ segment mới (searchable, nằm trong filesystem cache)
                                              │
   nhiều segment ──merge (nền)──▶ segment lớn hơn (xóa doc đã delete)
                                              │
   translog ──flush──▶ fsync segment xuống đĩa, cắt translog
```

| Tham số | Mặc định | Ý nghĩa | Đánh đổi |
|---|---|---|---|
| `refresh_interval` | 1s | Tần suất buffer thành segment tìm được | Nhỏ = "near real-time" hơn nhưng tốn CPU/IO |
| `number_of_shards` | (tùy version) | Số primary, **cố định sau khi tạo** | Quá nhiều shard nhỏ = overhead; quá ít = không scale |
| `number_of_replicas` | 1 | Số bản sao, **thay đổi động được** | Nhiều replica = đọc nhanh, HA cao, tốn đĩa |
| `translog.durability` | request | `request` fsync mỗi ghi; `async` định kỳ | `async` nhanh hơn, rủi ro mất dữ liệu khi crash |

**Vì sao số primary shard cố định?** Vì routing dùng `% number_of_primary_shards`. Đổi số shard sẽ đổi đích routing của mọi document cũ → phải reindex toàn bộ. Đây là quyết định thiết kế quan trọng nhất khi tạo index.

**Vì sao có translog?** Refresh tạo segment trong RAM/cache nhưng chưa fsync xuống đĩa. Nếu node crash giữa hai lần flush, dữ liệu trong segment chưa fsync sẽ mất — translog (đã fsync) cho phép replay để khôi phục.

### 9.1.4 Query DSL — Truy vấn tới mức từng mệnh đề

Query DSL phân biệt **query context** (tính điểm relevance, "khớp tốt đến đâu") và **filter context** (đúng/sai, có cache, "có khớp không"). Filter nhanh hơn vì không tính điểm và được cache bitset.

**match** (full-text, có analyze):

```json
GET /logs-nginx-*/_search
{ "query": { "match": { "user_agent": "curl python" } } }
```
→ analyze "curl python" thành term `curl`, `python`; mặc định OR; trả document chứa ít nhất một term, tính điểm BM25.

**term** (exact, KHÔNG analyze — dùng cho keyword/số/ip):

```json
{ "query": { "term": { "status": 401 } } }
```
→ Lưu ý lỗi kinh điển: dùng `term` trên trường `text` thường không khớp vì giá trị đã bị lowercase/tách khi index nhưng term query không analyze.

**range**:

```json
{ "query": { "range": { "@timestamp": { "gte": "now-15m", "lte": "now" } } } }
```

**bool** (tổ hợp — xương sống mọi query thật):

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

| Mệnh đề | Context | Ảnh hưởng điểm | Ngữ nghĩa |
|---|---|---|---|
| `must` | query | Có | AND, đóng góp điểm |
| `filter` | filter | Không (cache) | AND, chỉ lọc |
| `should` | query | Có | OR mềm, tăng điểm |
| `must_not` | filter | Không | NOT |

Truy vấn trên (đọc ngữ nghĩa bảo mật): "Tìm tối đa 20 request đăng nhập (full-text 'login') có status 401, trong 1 giờ qua, không đến từ 10.0.0.5, ưu tiên hiển thị POST cao hơn, đồng thời gom top 10 IP." Đây chính là dạng săn brute-force.

**Lưu ý bảo mật query**: tránh `script` query/aggregation với input không tin cậy (Painless chạy trong sandbox nhưng vẫn có lịch sử CVE liên quan script). Đặt `search.max_buckets` để chặn aggregation bùng nổ gây OOM. Giới hạn `size` và dùng `search_after`/PIT thay vì deep pagination `from` lớn.

### 9.1.5 Node, Cluster, Roles và bảo mật

Một **cluster** gồm nhiều **node**, mỗi node có thể đảm nhận vai trò:

| Role | Ký hiệu | Nhiệm vụ |
|---|---|---|
| master-eligible | `m` | Bầu master, quản lý cluster state (mapping, shard allocation) |
| data | `d` (`data_hot`, `data_warm`, `data_cold`, `data_frozen`) | Lưu shard, xử lý CRUD/search |
| ingest | `i` | Chạy ingest pipeline (tiền xử lý trước khi index) |
| coordinating | (mọi node) | Nhận request, phân tán, gom kết quả |
| ml | `l` | Machine learning jobs |

**Bầu master & quorum**: cluster cần `(số master-eligible / 2) + 1` node để bầu master (tránh **split-brain**). Với 3 master-eligible, quorum = 2. Vì sao luôn dùng số lẻ master-eligible (3, 5)? Để có quorum rõ ràng khi network partition.

`elasticsearch.yml` tối thiểu cho production có bảo mật:

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

**Lưu ý bảo mật (cực kỳ quan trọng)**:
- Lịch sử Elasticsearch bị lộ dữ liệu khổng lồ vì chạy **không xác thực, bind 0.0.0.0, mở cổng 9200 ra Internet**. Luôn bật `xpack.security.enabled: true`, TLS cho cả transport (9300) lẫn HTTP (9200), và RBAC.
- Tách hai lớp TLS: **transport (9300)** là giao tiếp nội bộ giữa node (cluster); **HTTP (9200)** là API client. Cả hai phải mã hóa.
- Dùng role-based access: tạo role chỉ đọc index cụ thể, gán cho API key thay vì dùng superuser `elastic`.

```bash
# Tạo role chỉ đọc index logs-*
curl -X POST "https://es:9200/_security/role/log_reader" -u elastic:$PASS --cacert ca.crt \
 -H 'Content-Type: application/json' -d '{
   "indices":[{"names":["logs-*"],"privileges":["read","view_index_metadata"]}]
 }'
```

---

## 9.2 Logstash — Pipeline xử lý dữ liệu

### 9.2.1 Kiến trúc pipeline input → filter → output

Logstash xử lý dữ liệu theo pipeline 3 giai đoạn, mỗi event là một đối tượng có `@timestamp`, `@version`, `@metadata` và các field:

```
            ┌──────────────────────── Logstash Pipeline ────────────────────────┐
   nguồn ──▶│  INPUT  ──▶  [queue]  ──▶  FILTER (worker threads)  ──▶  OUTPUT   │──▶ đích
            └────────────────────────────────────────────────────────────────────┘
   beats        beats     in-memory      grok → date → mutate         elasticsearch
   syslog       plugin    hoặc           → geoip → ...                stdout
   kafka                  persistent                                  kafka
```

| Giai đoạn | Vai trò | Plugin ví dụ |
|---|---|---|
| input | Nhận dữ liệu | `beats`, `tcp`, `udp`, `syslog`, `kafka`, `file`, `http` |
| filter | Biến đổi, làm giàu, parse | `grok`, `date`, `mutate`, `geoip`, `kv`, `json`, `dissect`, `useragent` |
| output | Gửi đi | `elasticsearch`, `stdout`, `kafka`, `file`, `s3` |

**Persistent queue**: mặc định queue trong RAM (mất event khi crash). Bật `queue.type: persisted` để ghi event xuống đĩa (có ACK) — quan trọng cho log bảo mật không được mất.

### 9.2.2 GROK — Parse log phi cấu trúc

**GROK** dịch chuỗi log dạng tự do thành field bằng các pattern đặt tên, bản chất là regex có alias. Cú pháp: `%{PATTERN:field_name}` hoặc `%{PATTERN:field_name:type}`.

Một số pattern dựng sẵn (định nghĩa trong `grok-patterns`):

| Pattern | Regex tương đương (rút gọn) | Khớp |
|---|---|---|
| `IPV4` | `(?:[0-9]{1,3}\.){3}[0-9]{1,3}` | `203.0.113.45` |
| `NUMBER` | `(?:-?\d+(\.\d+)?)` | `512`, `-3.14` |
| `WORD` | `\b\w+\b` | `GET` |
| `DATA` | `.*?` (lười) | bất kỳ, ngắn nhất |
| `GREEDYDATA` | `.*` (tham) | phần còn lại |
| `QS` | chuỗi trong dấu nháy | `"GET /x HTTP/1.1"` |
| `HTTPDATE` | định dạng ngày Apache | `19/Jun/2026:08:15:30 +0700` |
| `COMBINEDAPACHELOG` | pattern tổng hợp Nginx/Apache | cả dòng |

**Ví dụ parse một dòng log Nginx (combined format):**

Dòng thật:
```
203.0.113.45 - alice [19/Jun/2026:08:15:30 +0700] "POST /login HTTP/1.1" 401 512 "https://app/" "Mozilla/5.0"
```

Pattern GROK:
```
%{IPV4:clientip} - %{DATA:auth} \[%{HTTPDATE:timestamp}\] "%{WORD:method} %{DATA:request} HTTP/%{NUMBER:httpversion}" %{NUMBER:status:int} %{NUMBER:bytes:int} %{QS:referrer} %{QS:agent}
```

Kết quả field được trích:

| Field | Giá trị | Kiểu |
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

**Vì sao dùng `DATA` (lười) vs `GREEDYDATA` (tham)?** `DATA` (`.*?`) khớp ngắn nhất, dừng ngay khi gặp ký tự phân định kế tiếp (dấu cách, ngoặc). `GREEDYDATA` (`.*`) nuốt tối đa — chỉ dùng ở cuối dòng. Đặt sai chỗ sẽ gây `_grokparsefailure`.

**Ví dụ parse log SSH (auth.log) săn brute-force:**

Dòng thật:
```
Jun 19 08:15:30 web01 sshd[2451]: Failed password for invalid user admin from 203.0.113.45 port 51324 ssh2
```

Pattern:
```
%{SYSLOGTIMESTAMP:syslog_ts} %{HOSTNAME:host} %{WORD:program}\[%{NUMBER:pid}\]: Failed password for( invalid user)? %{USERNAME:ssh_user} from %{IP:src_ip} port %{NUMBER:src_port} ssh2
```

### 9.2.3 mutate, date, geoip

**date filter** — chuyển chuỗi timestamp thành `@timestamp` chuẩn (vì sao quan trọng: nếu không, Kibana dùng thời điểm ingest chứ không phải thời điểm sự kiện, làm sai timeline điều tra):

```
date {
  match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
  target => "@timestamp"
  timezone => "Asia/Ho_Chi_Minh"
}
```

**mutate filter** — biến đổi field:

```
mutate {
  convert    => { "status" => "integer" "bytes" => "integer" }
  lowercase  => [ "method" ]
  rename     => { "clientip" => "[source][ip]" }
  remove_field => [ "timestamp", "host" ]
  gsub       => [ "referrer", "[\"]", "" ]
}
```

**geoip filter** — làm giàu IP thành tọa độ/quốc gia (dựa MaxMind GeoLite2 DB):

```
geoip {
  source => "[source][ip]"
  target => "[source][geo]"
}
```
→ thêm `[source][geo][country_name]`, `[source][geo][location]` (geo_point) → vẽ map IP tấn công trong Kibana.

### 9.2.4 File logstash.conf đầy đủ (chạy được)

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

Giải thích các quyết định:
- `index => "logs-nginx-%{+YYYY.MM.dd}"`: index theo ngày → dễ áp **ILM** (xóa/rollover) và giới hạn kích thước shard.
- Tách output cho event lỗi parse → không "nuốt im lặng" dữ liệu sai, vẫn điều tra được.
- `useragent` tách user-agent thành OS/browser → hữu ích phát hiện công cụ tự động (curl, sqlmap, nikto).

**Lưu ý bảo mật Logstash**:
- Dùng user ES riêng `logstash_writer` chỉ có quyền `create_index`/`write` index `logs-*`, không dùng `elastic`.
- Mật khẩu qua **keystore** (`logstash-keystore add LS_ES_PASS`), không hardcode.
- GROK với regex tham lam/backtracking trên input thù địch có thể gây **ReDoS** (CPU 100%). Ưu tiên `dissect` (không regex) cho log có cấu trúc cố định; đặt `timeout_millis` cho grok.

---

## 9.3 Kibana — Trực quan hóa và truy vấn

### 9.3.1 Index pattern / Data view

Kibana không lưu dữ liệu; nó hỏi Elasticsearch. **Index pattern** (tên mới: **Data view**) khai báo nhóm index Kibana được phép truy vấn, ví dụ `logs-nginx-*`, và chỉ định **time field** (`@timestamp`) để bộ chọn thời gian hoạt động.

### 9.3.2 Discover và KQL

**Discover** là màn hình duyệt log thô. Ngôn ngữ truy vấn mặc định là **KQL (Kibana Query Language)** — đơn giản hơn Query DSL, biên dịch ngầm sang DSL.

| Mục đích | KQL | Tương đương DSL |
|---|---|---|
| Khớp giá trị | `status: 401` | `term` |
| AND | `status: 401 and method: post` | `bool.must` |
| OR | `status: 401 or status: 403` | `should` |
| NOT | `not clientip: "10.0.0.5"` | `must_not` |
| Khoảng | `bytes > 1000` | `range` |
| Wildcard | `request: *admin*` | `wildcard` |
| Tồn tại field | `geo.country_name: *` | `exists` |

Ví dụ săn brute-force trong Discover:
```
event.module: "nginx" and status: 401 and request: "/login"
```
Kết hợp time picker "Last 1 hour" → đếm tần suất theo IP.

### 9.3.3 Visualization, Dashboard

- **Visualization** (Lens): vẽ một biểu đồ từ aggregation — ví dụ "Bar chart: count theo `clientip` (terms agg), lọc status 401" để thấy IP brute-force.
- **Dashboard**: ghép nhiều visualization + filter chung + time range chung. Một dashboard SOC điển hình: bản đồ geo IP, top failed-login IP, biểu đồ status code theo thời gian, bảng top user-agent bất thường.

**Lưu ý bảo mật Kibana**:
- Kibana có **RBAC theo space và index**: tạo role analyst chỉ đọc dashboard và index `logs-*`, không cho quản trị cluster.
- Bật TLS giữa Kibana ↔ Elasticsearch và browser ↔ Kibana.
- Cảnh giác với chức năng cho phép script/embedded — giới hạn ai được tạo visualization dùng script.

---

## 9.4 Beats — Thu thập dữ liệu tại nguồn

**Beats** là họ agent nhẹ (viết bằng Go, biên dịch tĩnh) đặt trên host nguồn. Mỗi beat chuyên một loại dữ liệu.

| Beat | Dữ liệu | Cơ chế |
|---|---|---|
| Filebeat | Log file, container log | Harvester đọc file, theo dõi offset |
| Metricbeat | Metric hệ thống/dịch vụ | Module poll định kỳ |
| Winlogbeat | Windows Event Log | Đọc qua Windows Event Log API |
| Packetbeat | Giao thức mạng (decode trên dây) | Sniff network |
| Auditbeat | Audit framework Linux (auditd) | Đọc audit events |

### 9.4.1 Filebeat — Harvester và registry

Cơ chế cốt lõi:

```
filebeat.inputs path: /var/log/nginx/*.log
        │
        ▼
  Một HARVESTER cho mỗi file đang mở
   - đọc từ offset cuối cùng (lưu trong registry)
   - mỗi dòng → một event
        │
        ▼
  REGISTRY (/var/lib/filebeat/registry)
   - lưu {inode, offset, device} cho mỗi file
   - vì sao theo inode? để nhận diện file dù bị đổi tên (logrotate)
        │
        ▼
  SPOOLER/QUEUE → publish tới output (Logstash/ES/Kafka)
   - at-least-once delivery: chỉ cập nhật offset sau khi output ACK
```

**Vì sao at-least-once?** Filebeat chỉ advance offset trong registry sau khi nhận ACK từ đích. Crash giữa chừng → gửi lại từ offset cũ → có thể trùng nhưng **không mất** log. Trùng được xử lý ở ES bằng `_id` xác định (fingerprint).

**Module**: Filebeat đóng gói sẵn cấu hình parse cho dịch vụ phổ biến (nginx, system, apache, auditd). Module gồm: input path mặc định + ingest pipeline (parse) + index template + dashboard.

```bash
filebeat modules enable nginx system
filebeat setup --pipelines --modules nginx     # cài ingest pipeline vào ES
filebeat setup --dashboards                     # nạp dashboard Kibana
```

**Ví dụ filebeat.yml đầy đủ (gửi qua Logstash, có TLS):**

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

Giải thích:
- `type: filestream` (thay cho `log` cũ): theo dõi file ổn định hơn với logrotate.
- `multiline`: gộp dòng tiếp nối (vd stack trace) vào một event; pattern "dòng bắt đầu bằng IP là dòng mới", các dòng khác nối vào trước.
- `add_host_metadata`: gắn hostname, OS, IP → định danh nguồn khi điều tra.

### 9.4.2 Metricbeat

Thu metric qua **module** poll theo `period`:

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

`system.cpu.utilization` (Metricbeat) tương tự khái niệm `system.cpu.util` bên Zabbix — nhưng đây là metric phục vụ phân tích, không có trigger/threshold engine như Zabbix. Vai trò của Metricbeat cũng tương đương **node_exporter** bên hệ Prometheus (xem 9.6) — khác ở chiều dữ liệu: Metricbeat **đẩy** về Elasticsearch, còn node_exporter chỉ **phơi** metric ra để Prometheus kéo.

### 9.4.3 Winlogbeat

Đọc Windows Event Log (Security, System, Sysmon) — nguồn vàng cho Blue Team:

```yaml
winlogbeat.event_logs:
  - name: Security
    event_id: 4624, 4625, 4672, 4688   # logon thành công/thất bại, quyền đặc biệt, tạo process
  - name: Microsoft-Windows-Sysmon/Operational

output.logstash:
  hosts: ["logstash-01:5044"]
  ssl.enabled: true
  ssl.certificate_authorities: ["C:\\ProgramData\\winlogbeat\\ca.crt"]
```

| Event ID | Ý nghĩa | Giá trị điều tra |
|---|---|---|
| 4624 | Logon thành công | Theo dõi logon type (10=RDP), nguồn IP |
| 4625 | Logon thất bại | Săn brute-force, password spraying |
| 4672 | Gán quyền đặc biệt | Phát hiện logon admin |
| 4688 | Tạo process mới | Săn lệnh độc hại (cần bật command-line auditing) |

### 9.4.4 Luồng dữ liệu tổng thể

```
[Host nguồn]                 [Pipeline]            [Lưu trữ/Tìm]        [Hiển thị]
 Filebeat ───┐
 Metricbeat ─┼──TLS:5044──▶ Logstash ──TLS:9200──▶ Elasticsearch ◀──── Kibana
 Winlogbeat ─┘             (grok/date/geoip)       (index, shard)      (Discover,
                                                                        Dashboard, KQL)

Biến thể: Beats ──▶ Elasticsearch trực tiếp (dùng ingest pipeline thay Logstash)
          khi không cần biến đổi phức tạp (nhẹ hơn, ít thành phần hơn).
```

**Khi nào bỏ Logstash?** Nếu chỉ cần parse đơn giản, dùng **ingest pipeline** trong Elasticsearch (chạy trên ingest node) → bớt một thành phần. Giữ Logstash khi cần buffer lớn (persistent queue), nhiều nguồn không phải Beats (syslog, kafka), hoặc biến đổi nặng.

---

## 9.5 Zabbix — Giám sát hạ tầng và hiệu năng

### 9.5.1 Kiến trúc Server / Agent / Proxy

```
   ┌──────────────────────────────────────────────────────────────┐
   │                      ZABBIX SERVER                             │
   │  - thu thập, đánh giá trigger, sinh event, chạy action        │
   │  - ghi vào DB (MySQL/PostgreSQL/TimescaleDB)                   │
   └───────▲───────────────────▲────────────────────▲──────────────┘
           │ TCP 10051         │                    │
   ┌───────┴───────┐   ┌───────┴───────┐    ┌───────┴────────┐
   │ Zabbix Proxy  │   │ Zabbix Agent  │    │  SNMP / IPMI   │
   │ (gom 1 vùng)  │   │ (trên host)   │    │  agentless     │
   └───────▲───────┘   └───────────────┘    └────────────────┘
           │ TCP 10050
   ┌───────┴───────┐
   │ Zabbix Agent  │
   └───────────────┘

   Frontend (PHP) + Zabbix DB  → giao diện web, cấu hình, dashboard
```

| Thành phần | Cổng mặc định | Vai trò |
|---|---|---|
| Zabbix Server | nghe 10051 | Lõi xử lý, đánh giá trigger, chạy action |
| Zabbix Agent (passive) | nghe 10050 | Server hỏi, agent trả về giá trị item |
| Zabbix Agent (active) | kết nối 10051 | Agent chủ động đẩy dữ liệu lên server |
| Zabbix Proxy | nghe 10051 | Thu thập thay server cho một vùng/DMZ, đệm khi mất kết nối |
| Frontend | 80/443 | Web UI (PHP) |

**Passive vs Active agent** — khác biệt cốt lõi:

| | Passive | Active |
|---|---|---|
| Ai khởi tạo kết nối | Server → Agent (10050) | Agent → Server (10051) |
| Phù hợp | Mạng server thấy được agent | Agent sau NAT/firewall, nhiều host |
| Tải server | Cao hơn (server poll từng item) | Thấp hơn (agent đẩy theo batch) |
| Cấu hình item | Hỏi từng lần | Agent lấy danh sách item rồi tự thu |

**Vì sao có Proxy?** Trong môi trường nhiều site/DMZ, proxy thu thập cục bộ rồi gửi gộp lên server (chỉ một kết nối qua firewall). Proxy còn **đệm dữ liệu** trong DB cục bộ khi mất kết nối tới server → không mất metric.

### 9.5.2 Định dạng giao thức Zabbix trên dây (Zabbix protocol)

Đây là phần "đào tới byte". Mọi giao tiếp agent/server dùng một header nhị phân cố định:

```
Offset  Kích thước  Trường          Giá trị/ý nghĩa
------  ----------  --------------  --------------------------------------------
  0      4 bytes    Protocol magic  ASCII "ZBXD"  = 0x5A 0x42 0x58 0x44
  4      1 byte     Flags           bit0=0x01 Zabbix communications protocol
                                    bit1=0x02 compression (zlib)
                                    bit2=0x04 large packet (dùng 8-byte length)
  5      4 bytes    Data length     uint32 little-endian = độ dài payload (đã nén nếu có)
  9      4 bytes    Reserved        nếu nén: uint32 LE = độ dài payload sau giải nén
                                    nếu không nén: 0x00000000
 13      N bytes    Payload         JSON (UTF-8)
```

Ghi chú: khi flag large packet (0x04) được bật, hai trường length dùng 8 byte mỗi trường (header dài hơn). Nên kiểm chứng bằng bắt gói thực tế nếu cần độ chính xác tuyệt đối theo version.

Sơ đồ ASCII một gói thật (không nén, không large packet):

```
+------+------+------+------+------+   +------+------+------+------+   +-------------+
|  Z   |  B   |  X   |  D   | flag |   |  len (4B LE)            |   | reserved(4B)| JSON...
| 5A   | 42   | 58   | 44   | 01   |   | xx   xx   xx   xx       |   | 00 00 00 00 |
+------+------+------+------+------+   +------+------+------+------+   +-------------+
   0     1      2      3      4         5                    8         9        12   13...
```

Ví dụ payload JSON khi agent active gửi dữ liệu:
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

| Trường JSON | Ý nghĩa | Ví dụ |
|---|---|---|
| `request` | Loại request | `agent data`, `active checks`, `sender data` |
| `host` | Tên host trong Zabbix | `web01` |
| `key` | Item key | `system.cpu.util` |
| `value` | Giá trị thu được | `12.50` |
| `clock` | Epoch giây thời điểm đo | `1750300530` |
| `ns` | Nano-giây bổ sung độ chính xác | `123456789` |

**Vì sao có magic "ZBXD" + length tường minh?** TCP là stream không có ranh giới message. Magic giúp nhận diện protocol, trường length cho biết đọc bao nhiêu byte payload → tách message chính xác. Flag large packet cho phép payload rất lớn bằng cách dùng length 8 byte.

Bắt gói để kiểm chứng:
```bash
tcpdump -i any -n -A 'tcp port 10051' -c 20
# hoặc test một item bằng zabbix_get (xem 9.5.4)
```

### 9.5.3 Item — Đơn vị đo

**Item** định nghĩa "đo cái gì, bằng cách nào". Mỗi item gắn một **key**.

| Thành phần item | Ý nghĩa | Ví dụ |
|---|---|---|
| Key | Định danh phép đo, có thể có tham số | `system.cpu.util[,user]` |
| Type | Cách thu thập | Zabbix agent / Zabbix agent (active) / SNMP / Calculated / Dependent / HTTP / Trapper |
| Value type | Kiểu giá trị | Numeric (unsigned/float), Character, Log, Text |
| Update interval | Tần suất thu | `1m`, `30s` |
| History | Giữ giá trị thô bao lâu | `7d` |
| Trends | Giữ thống kê giờ (min/avg/max) | `365d` |
| Preprocessing | Biến đổi trước khi lưu | regex, JSONPath, change-per-second, throttling |

Các item key thường gặp:

| Key | Đo gì |
|---|---|
| `system.cpu.util` | % CPU sử dụng |
| `system.cpu.load[all,avg1]` | Load average 1 phút |
| `vm.memory.size[available]` | RAM khả dụng (byte) |
| `vfs.fs.size[/,pfree]` | % dung lượng trống của `/` |
| `net.if.in[eth0]` | Byte nhận trên eth0 (counter) |
| `net.tcp.service[ssh,,22]` | Kiểm tra dịch vụ SSH (1=up,0=down) |
| `proc.num[nginx]` | Số tiến trình nginx |
| `agent.ping` | Agent còn sống (1) |
| `vfs.file.contents[/etc/passwd]` | (nguy hiểm — xem lưu ý) |

**Vì sao tách History và Trends?** History (giá trị thô từng lần đo) phình rất nhanh — không thể giữ lâu. Trends gộp theo giờ (min/avg/max) chiếm rất ít chỗ, giữ được hàng năm để xem xu hướng dài hạn. Đây là chiến lược chống phình DB cốt lõi.

**Preprocessing với counter**: `net.if.in` là bộ đếm tăng dần (byte tích lũy). Dùng preprocessing **"Change per second"** để ra throughput byte/giây — chính là cơ chế tính tốc độ từ counter (tương tự SNMP).

### 9.5.4 Ví dụ thực tế thu thập item

`zabbix_agentd.conf` (passive + active):
```ini
Server=10.0.0.10                 # server được phép poll (passive), CSV
ServerActive=10.0.0.10:10051     # server để agent đẩy active checks
Hostname=web01                   # phải khớp host name trong Zabbix
ListenPort=10050
TLSConnect=psk
TLSAccept=psk
TLSPSKIdentity=PSK web01
TLSPSKFile=/etc/zabbix/zabbix_agentd.psk
```

Tự định nghĩa item (UserParameter) — ví dụ đếm số kết nối ESTABLISHED:
```ini
UserParameter=net.tcp.established,ss -ant state established | wc -l
```

Lấy thử giá trị từ server bằng `zabbix_get` (kiểm chứng item passive):
```bash
zabbix_get -s 10.0.0.20 -p 10050 -k "system.cpu.util"
# Output mẫu:
12.5026
zabbix_get -s 10.0.0.20 -k "net.tcp.established"
47
```

Đẩy giá trị thủ công bằng `zabbix_sender` (cho item type Trapper):
```bash
zabbix_sender -z 10.0.0.10 -s "web01" -k "app.queue.depth" -o 128
# Output:
# info from server: "processed: 1; failed: 0; total: 1; seconds spent: 0.000123"
# sent: 1; skipped: 0; total: 1
```

### 9.5.5 Trigger — Đánh giá điều kiện

**Trigger** là biểu thức boolean trên dữ liệu item; khi đúng → chuyển trạng thái sang **PROBLEM**, khi sai → **OK**. Đây là phần thay thế cho "rule" — nhưng dựa trên ngưỡng metric chứ không phải pattern bảo mật.

Cú pháp hàm (Zabbix 5.4+): `function(/host/key, parameter)`.

Ví dụ trigger expression thực tế:

```
# CPU trung bình 5 phút > 90%
avg(/web01/system.cpu.util,5m) > 90

# Dung lượng / còn dưới 10%
last(/web01/vfs.fs.size[/,pfree]) < 10

# Agent không phản hồi 5 phút (no data)
nodata(/web01/agent.ping,5m) = 1

# Quá 20 lần đăng nhập SSH thất bại trong 5 phút (item log đếm)
sum(/web01/log.ssh.failed,5m) > 20

# Trigger có recovery riêng (hysteresis tránh flapping):
#   Problem:  min(/web01/system.cpu.util,5m) > 90
#   Recovery: max(/web01/system.cpu.util,5m) < 80
```

| Hàm | Ý nghĩa |
|---|---|
| `last()` | Giá trị mới nhất |
| `avg(,5m)` | Trung bình trong 5 phút |
| `min()/max()` | Cực tiểu/cực đại trong khoảng |
| `count(,5m,"gt",90)` | Số lần thỏa điều kiện |
| `nodata(,5m)` | =1 nếu không có dữ liệu trong 5 phút |
| `change()` | Chênh lệch so với giá trị trước |

**Severity** của trigger: Not classified, Information, Warning, Average, High, Disaster — quyết định mức cảnh báo và màu sắc.

**Vì sao cần hysteresis (recovery expression riêng)?** Nếu chỉ dùng `>90` để vào và `<=90` để ra, CPU dao động quanh 90% sẽ tạo hàng loạt sự kiện problem/ok ("flapping"). Đặt ngưỡng vào (90) cao hơn ngưỡng ra (80) → cảnh báo ổn định.

### 9.5.6 Template, Host, Host group

- **Host**: thực thể được giám sát (server, switch, ứng dụng). Có interface (Agent/SNMP/IPMI/JMX).
- **Host group**: nhóm host để áp quyền và áp dụng hàng loạt.
- **Template**: tập hợp item + trigger + graph + macro tái sử dụng. Gắn template vào host → host thừa hưởng toàn bộ item/trigger. Ví dụ template `Linux by Zabbix agent` cung cấp sẵn hàng chục item CPU/RAM/disk/net.

**Macro** giúp tham số hóa: trong trigger dùng `{$CPU.UTIL.CRIT}` thay vì hardcode 90; override macro ở cấp host cho ngoại lệ. Vì sao? Một template áp cho 500 host, nhưng vài host DB cần ngưỡng khác → chỉ cần override macro trên host đó.

### 9.5.7 Action, Operation, Media

Khi trigger sinh **event**, **Action** quyết định phản ứng:

```
Event (trigger PROBLEM)
   │
   ▼ Action conditions  (vd: severity >= High AND host group = Production)
   │
   ▼ Operations
       - gửi message qua Media (Email/Telegram/Slack/Webhook)
       - chạy remote command (vd restart service) — cẩn trọng
   │
   ▼ Recovery operations  (gửi thông báo đã OK)
   │
   ▼ Escalation (lặp lại/leo thang nếu chưa ai xử lý sau X phút)
```

- **Media type**: kênh gửi (Email SMTP, Telegram bot, Slack, custom webhook script).
- **User media**: gán kênh cho user kèm lịch trực và severity quan tâm.

Ví dụ webhook media (JavaScript) gửi cảnh báo — Zabbix media type webhook nhận macro qua tham số, ví dụ `{ALERT.MESSAGE}`, `{EVENT.SEVERITY}`:
```javascript
var params = JSON.parse(value);
var req = new HttpRequest();
req.addHeader('Content-Type: application/json');
var resp = req.post('https://hooks.example/alert',
  JSON.stringify({ text: params.message, severity: params.severity }));
return resp;
```

**Lưu ý bảo mật action**: **Remote command** cho phép Zabbix chạy lệnh trên agent — nếu bật `EnableRemoteCommands`/`AllowKey=system.run[*]` bừa bãi, server bị chiếm = RCE toàn fleet. Mặc định nên tắt; nếu bật, giới hạn `AllowKey`/`DenyKey` và lệnh cụ thể.

### 9.5.8 Dashboard và Latest data

- **Latest data**: bảng giá trị item mới nhất theo host — dùng kiểm tra nhanh.
- **Graph**: vẽ chuỗi thời gian từ history/trends.
- **Dashboard**: widget (graph, problem list, map topology, gauge) — ví dụ NOC: bản đồ host (xanh=OK, đỏ=problem), top CPU, danh sách problem đang mở.

### 9.5.9 Lưu ý bảo mật Zabbix tổng thể

- **TLS/PSK**: mặc định kênh agent↔server **không mã hóa**. Bật `TLSConnect`/`TLSAccept` với PSK hoặc cert. Không bật = ai sniff được sẽ thấy metric và có thể giả mạo trapper.
- **Item nguy hiểm**: `system.run[...]`, `vfs.file.contents[...]` có thể đọc file nhạy cảm/chạy lệnh. Dùng `AllowKey`/`DenyKey` trong agent conf để whitelist.
  ```ini
  DenyKey=system.run[*]
  AllowKey=vfs.file.contents[/var/log/app/*]
  ```
- **Frontend PHP**: từng có nhiều CVE SQLi/XSS. Đặt sau reverse proxy, HTTPS, hạn chế IP truy cập, cập nhật bản vá kịp thời.
- **DB credential** trong `zabbix_server.conf` — phân quyền file 600, user DB tối thiểu quyền.

---

## 9.6 Prometheus — Giám sát metric theo mô hình pull

### 9.6.1 Prometheus là gì, giải quyết vấn đề gì

**Prometheus** là hệ giám sát metric mã nguồn mở, khởi nguồn từ SoundCloud và là dự án thứ hai "tốt nghiệp" CNCF (sau Kubernetes). Nó giải quyết cùng bài toán với Zabbix — "hệ thống có khỏe không, chỉ số nào vượt ngưỡng" — nhưng theo triết lý khác:

- **Pull model**: Prometheus server **chủ động kéo** (scrape) metric từ endpoint HTTP `/metrics` của từng target, theo chu kỳ cấu hình. Target không đẩy gì cả — nó chỉ *phơi* trạng thái hiện tại ra dạng text.
- **Metric là time-series có label**: mỗi chuỗi được định danh bằng tên metric + tập cặp key=value (label). Cắt lát dữ liệu theo label là thao tác hạng nhất, không cần khai báo trước từng "item" như Zabbix.
- **Cấu hình bằng file** (YAML + rule file): toàn bộ scrape config và alert rule nằm trong file text → đưa vào Git, review như code (khớp tinh thần GitOps ở chương 7). Zabbix ngược lại: cấu hình sống trong DB, thao tác qua GUI.
- **TSDB cục bộ**: Prometheus tự lưu dữ liệu trên đĩa của chính nó (block 2 giờ + WAL), không cần DB ngoài. Mặc định giữ 15 ngày (`--storage.tsdb.retention.time`) — lưu dài hạn cần giải pháp bổ sung (Thanos, Mimir, VictoriaMetrics — cần kiểm chứng lựa chọn theo thời điểm).

**Vì sao pull thay vì push?** Ba lý do thực dụng: (1) server kiểm soát nhịp thu — thêm 100 target không sợ server bị dội dữ liệu ngoài ý muốn; (2) biết ngay target chết — scrape thất bại thì metric `up == 0`, có ngay alert "host mất tích" mà không cần cơ chế heartbeat riêng (tương đương `nodata()` của Zabbix nhưng tự nhiên hơn); (3) debug dễ — mở trình duyệt vào `http://target:9100/metrics` là thấy đúng thứ server thấy. Nhược điểm: server phải *tới được* target (mạng NAT/firewall chiều vào là bài toán); job ngắn hạn (batch/cron) chạy xong đã chết trước khi bị scrape — giải bằng **Pushgateway** (job đẩy kết quả lên đó, Prometheus scrape Pushgateway).

### 9.6.2 Kiến trúc: server, exporter, scrape

```
   ┌─────────────────────────────────────────────────────────┐
   │                  PROMETHEUS SERVER                       │
   │  Retrieval (scrape) ──▶ TSDB (block + WAL trên đĩa)      │
   │        │                    │                            │
   │        │              HTTP API /api/v1/query  ◀── Grafana│
   │        ▼                    │                            │
   │  Rule evaluation ───────────┼──▶ alert đang FIRING       │
   └────────┬────────────────────┼────────────┬───────────────┘
            │ HTTP GET /metrics  │            │ HTTP POST
            ▼ (chu kỳ 15-60s)    │            ▼
   ┌────────────────┐   ┌────────────────┐  ┌──────────────┐
   │ node_exporter  │   │ app tự phơi    │  │ ALERTMANAGER │
   │ :9100 (host)   │   │ /metrics (SDK) │  │ group/route/ │
   └────────────────┘   └────────────────┘  │ notify       │
                                            └──────────────┘
```

| Thành phần | Cổng mặc định | Vai trò |
|---|---|---|
| Prometheus server | 9090 | Scrape, lưu TSDB, chạy PromQL, đánh giá alerting rule |
| node_exporter | 9100 | Phơi metric hệ điều hành Linux của host |
| Alertmanager | 9093 | Nhận alert từ server, gom nhóm, định tuyến, gửi thông báo |
| Pushgateway | 9091 | Trung gian cho batch job ngắn hạn |
| Exporter khác | 9xxx | blackbox (probe HTTP/ICMP), mysqld, nginx, redis... mỗi dịch vụ một exporter |

**Exporter** là điểm khác biệt kiến trúc so với Zabbix agent: thay vì một agent vạn năng trả lời mọi item key, hệ Prometheus dùng nhiều exporter nhỏ — mỗi exporter dịch trạng thái của một hệ (kernel, MySQL, nginx) thành định dạng text `/metrics`. Ứng dụng tự viết thì nhúng client library (Go/Python/Java...) để phơi metric nghiệp vụ trực tiếp.

`prometheus.yml` tối thiểu chạy được:

```yaml
global:
  scrape_interval: 15s          # chu kỳ kéo mặc định
  evaluation_interval: 15s      # chu kỳ đánh giá rule

rule_files:
  - "rules/*.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets: ["alertmanager:9093"]

scrape_configs:
  - job_name: "prometheus"      # tự giám sát chính nó
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

Mỗi target scrape được tự gắn hai label định danh: `job` (tên job) và `instance` (host:port). Môi trường động (Kubernetes, cloud) thay `static_configs` bằng **service discovery** (`kubernetes_sd_configs`, `ec2_sd_configs`...) — target sinh/chết tự được phát hiện, không ai phải "khai host" thủ công.

Định dạng text mà exporter phơi ra (mở `curl http://10.0.0.20:9100/metrics` là thấy):

```
# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode.
# TYPE node_cpu_seconds_total counter
node_cpu_seconds_total{cpu="0",mode="idle"} 8.5230889e+06
node_cpu_seconds_total{cpu="0",mode="iowait"} 12043.02
node_cpu_seconds_total{cpu="0",mode="steal"} 3894.77
node_cpu_seconds_total{cpu="0",mode="user"} 118920.31
node_memory_MemAvailable_bytes 6.442450944e+09
```

### 9.6.3 Data model — tên metric, label và 4 kiểu metric

Một time-series = **tên metric + tập label**; mỗi mẫu (sample) = (timestamp mili-giây, giá trị float64). Ví dụ `node_cpu_seconds_total{cpu="0",mode="idle",instance="10.0.0.20:9100",job="node"}` là *một* chuỗi; đổi bất kỳ label nào là *một chuỗi khác*. Hệ quả quan trọng: **label cardinality** quyết định chi phí — label nhận giá trị không chặn (user ID, URL đầy đủ, IP client) sẽ sinh hàng triệu chuỗi và giết server (tương tự mapping explosion bên Elasticsearch, xem 9.1.2).

Bốn kiểu metric:

| Kiểu | Bản chất | Ví dụ | Cách dùng đúng |
|---|---|---|---|
| **Counter** | Chỉ tăng (reset về 0 khi process restart) | `node_cpu_seconds_total`, `http_requests_total` | Không đọc giá trị thô; luôn qua `rate()`/`increase()` |
| **Gauge** | Lên xuống tự do | `node_memory_MemAvailable_bytes`, `node_load1` | Đọc trực tiếp, `avg_over_time()` |
| **Histogram** | Đếm quan sát vào các bucket `le` (kèm `_sum`, `_count`) | `http_request_duration_seconds_bucket` | `histogram_quantile(0.95, ...)` tính percentile phía server |
| **Summary** | Percentile tính sẵn phía client | `..._{quantile="0.99"}` | Đọc trực tiếp nhưng không aggregate được giữa các instance |

**Vì sao counter chỉ tăng?** Để chịu được mất mẫu: giữa hai lần scrape, dù mất vài mẫu, hiệu số hai giá trị counter vẫn cho biết chính xác lượng tăng trong khoảng đó. `rate()` còn tự xử lý counter reset (giá trị tụt xuống = process restart → nó cộng bù). Đây là lý do quy ước đặt tên `_total` và câu thần chú "counter thô vô nghĩa, rate của counter mới có nghĩa" — tương đương preprocessing "Change per second" bên Zabbix (9.5.3).

**Histogram vs Summary**: histogram tính percentile lúc *truy vấn* nên aggregate được toàn fleet ("p95 của cả cụm"); summary tính sẵn ở *client* nên chính xác hơn cho một instance nhưng không gộp được. Thực tế đa số chọn histogram.

### 9.6.4 node_exporter — các metric hệ thống đáng nhìn nhất

node_exporter đọc `/proc`, `/sys` và phơi ra vài nghìn chuỗi. Những nhóm mình dùng hằng ngày:

| Nhóm | Metric | Kiểu | Ý nghĩa vận hành |
|---|---|---|---|
| CPU | `node_cpu_seconds_total{mode=...}` | counter | Giây CPU theo mode: `user`, `system`, `iowait`, `steal`, `idle`... Đọc theo *mode* mới chẩn đoán được: `iowait` cao = nghẽn đĩa chứ không phải thiếu CPU; `steal` cao = hypervisor bóp VM (noisy neighbor trên cloud) |
| Memory | `node_memory_MemAvailable_bytes`, `node_memory_MemTotal_bytes` | gauge | Nhìn **available**, đừng nhìn "used" — Linux tận dụng RAM trống làm page cache nên used luôn cao |
| PSI | `node_pressure_memory_waiting_seconds_total`, `node_pressure_cpu_waiting_seconds_total`, `node_pressure_io_waiting_seconds_total` | counter | **Pressure Stall Information** (kernel ≥ 4.20): tổng thời gian có process phải *dừng chờ* tài nguyên. `rate()` của nó = tỉ lệ thời gian bị nghẽn — tín hiệu "thiếu thật" trung thực hơn mọi con số % used |
| Filesystem | `node_filesystem_avail_bytes`, `node_filesystem_files_free` | gauge | Dung lượng còn trống và **inode** còn trống (hết inode cũng "đầy đĩa" dù còn GB) |
| Disk I/O | `node_disk_io_time_seconds_total`, `node_disk_read_bytes_total`, `node_disk_written_bytes_total` | counter | `rate(io_time)` ≈ %util của `iostat`; throughput đọc/ghi |
| Network | `node_network_receive_bytes_total`, `node_network_receive_drop_total`, `node_network_receive_errs_total` | counter | Cảnh báo mạng nên nhìn **drop/error**, không phải % băng thông |
| Load/Procs | `node_load1`, `node_procs_blocked` | gauge | `procs_blocked` = số process trạng thái D (kẹt I/O) — load cao + blocked cao = nghẽn đĩa, không phải thiếu CPU |

Cách đọc mấy chỉ số này bằng *lệnh* ngay trên máy (mpstat, PSI, iostat, ss...) nằm ở chương 2 (Linux) — dashboard và lệnh là hai nửa của cùng một runbook.

### 9.6.5 PromQL cơ bản — các truy vấn dùng thật

PromQL thao tác trên hai loại giá trị chính: **instant vector** (mỗi chuỗi một giá trị tại một thời điểm — `node_load1`) và **range vector** (mỗi chuỗi một dãy mẫu trong cửa sổ thời gian — `node_cpu_seconds_total[5m]`). Hàm như `rate()` nhận range vector, trả instant vector.

```promql
# 1. CPU usage % từng máy (mẹo kinh điển: 100% trừ đi phần idle)
100 * (1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])))

# 2. CPU tách theo mode — panel "CPU by mode" chính là truy vấn này
sum by (mode) (rate(node_cpu_seconds_total{instance="10.0.0.20:9100"}[5m]))

# 3. % RAM available (nhìn available, không nhìn used)
100 * node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes

# 4. Áp lực RAM thật (PSI) — tỉ lệ thời gian có process phải chờ vì thiếu RAM
rate(node_pressure_memory_waiting_seconds_total[5m])

# 5. % đĩa còn trống của mount /
100 * node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}

# 6. Dự báo: với đà 6 giờ qua, 24 giờ nữa / có đầy không? (âm = sẽ đầy)
predict_linear(node_filesystem_avail_bytes{mountpoint="/"}[6h], 24*3600) < 0

# 7. Packet drop trên mọi interface (bỏ loopback)
rate(node_network_receive_drop_total{device!="lo"}[5m])

# 8. Máy nào mất tích (scrape thất bại)
up == 0
```

Mấy điểm hay vấp:

- `rate()` cần cửa sổ ≥ 2 lần `scrape_interval` (thường quy ước ≥ 4×, ví dụ interval 15s → cửa sổ tối thiểu 1m) — cửa sổ quá ngắn sẽ ra đồ thị lỗ chỗ.
- `sum(node_cpu_seconds_total)` không có `rate()` là vô nghĩa (cộng các counter tích lũy từ lúc boot).
- `by (label)` giữ label để nhóm, `without (label)` bỏ label — `sum by (mode)` gộp mọi CPU/instance nhưng giữ mode.
- `predict_linear` là hồi quy tuyến tính trên range vector — câu "đĩa *sẽ* đầy trong 24h" đáng giá hơn nhiều câu "đĩa *đang* trên 90%": cảnh báo khi còn thời gian xử lý, và không kêu oan máy có đĩa 91% nhưng ổn định.

### 9.6.6 Alerting rule và Alertmanager

Prometheus tách đôi việc cảnh báo: **server** đánh giá rule và bắn alert; **Alertmanager** nhận alert rồi gom nhóm, khử trùng lặp, định tuyến, gửi đi. Vì sao tách? Để nhiều Prometheus server dùng chung một chỗ quản lý thông báo, và để logic "gửi cho ai, khi nào, gom thế nào" không trộn vào logic "cái gì là bất thường".

Rule file (`rules/node.yml`):

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
          summary: "Đĩa / của {{ $labels.instance }} sẽ đầy trong ~24h"

      - alert: HostHighCpu
        expr: 100 * (1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m]))) > 90
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "CPU {{ $labels.instance }} > 90% suốt 15 phút"

      - alert: HostDown
        expr: up{job="node"} == 0
        for: 3m
        labels:
          severity: critical
        annotations:
          summary: "{{ $labels.instance }} không scrape được 3 phút"
```

Trường **`for`** là chốt chống nhiễu: biểu thức phải đúng *liên tục* trong khoảng đó thì alert mới chuyển từ `pending` sang `firing` — vai trò tương tự hysteresis của Zabbix trigger (9.5.5): một cú spike CPU 30 giây không đáng đánh thức ai.

`alertmanager.yml` — route dạng cây, receiver là đích gửi:

```yaml
route:
  receiver: ops-default            # nhánh mặc định
  group_by: [alertname, instance]  # gom alert cùng loại thành 1 thông báo
  group_wait: 30s                  # đợi gom thêm alert cùng nhóm
  repeat_interval: 4h              # nhắc lại nếu chưa ai xử lý
  routes:
    - matchers: [ severity="critical" ]
      receiver: ops-oncall         # critical đi đường riêng

receivers:
  - name: ops-default
    webhook_configs:
      - url: "https://hooks.example/ops-channel"
  - name: ops-oncall
    webhook_configs:
      - url: "https://hooks.example/oncall"
```

Ngoài route, Alertmanager có **silence** (tắt tiếng theo matcher trong thời gian bảo trì, tạo qua UI/API) và **inhibition** (alert to đè alert nhỏ: host đã `HostDown` thì đừng gửi thêm 15 alert CPU/RAM của chính host đó).

**Lưu ý bảo mật Prometheus**:

- `/metrics` lộ nhiều thông tin trinh sát (phiên bản kernel, mount point, tên interface, đôi khi cả path ứng dụng). node_exporter **không có xác thực** — chỉ bind mạng nội bộ, chặn firewall cổng 9100/9090/9093 khỏi Internet.
- Bản thân Prometheus/Alertmanager hỗ trợ TLS + basic auth cho web/API (từ Prometheus 2.24 — cần kiểm chứng); trước đó và cả nay nhiều nơi vẫn đặt sau reverse proxy để kiểm soát truy cập.
- UI Prometheus cho chạy PromQL tùy ý trên toàn bộ dữ liệu — coi nó như công cụ quản trị, không phơi công khai.

### 9.6.7 Prometheus vs Zabbix — khi nào chọn gì

| Tiêu chí | Zabbix | Prometheus |
|---|---|---|
| Mô hình thu thập | Push (active) / poll từng item (passive), SNMP/IPMI | Pull scrape endpoint HTTP |
| Cấu hình | GUI + template, lưu trong DB | File YAML + rule file → Git/review được |
| Data model | Item key phẳng theo host | Metric + label đa chiều, cắt lát tùy ý |
| Ngôn ngữ truy vấn | Hàm trigger trên từng item | PromQL — tính toán trên cả fleet trong một biểu thức |
| Target động (container, autoscaling) | Yếu hơn (đăng ký host, LLD) | Rất mạnh (service discovery) |
| Thiết bị mạng (SNMP), server vật lý | Rất mạnh, có sẵn template | Phải qua snmp_exporter, cực hơn |
| Lưu dài hạn | History/Trends trong DB, giữ nhiều năm | TSDB cục bộ ~tuần; dài hạn cần Thanos/Mimir/remote write |
| Alert | Trigger + action + escalation trong một hệ | Rule (server) + Alertmanager (route) tách đôi |

Kinh nghiệm chọn: hạ tầng **tĩnh, nhiều thiết bị mạng, cần SNMP và escalation trực ca bài bản** → Zabbix vẫn rất tốt. Hạ tầng **cloud/container, target sinh diệt liên tục, đội đã quen IaC** → Prometheus + Grafana là mặc định của hệ sinh thái (Kubernetes phơi metric sẵn theo định dạng Prometheus). Bản thân mình dùng Prometheus + node_exporter + Grafana cho metric máy chủ; Zabbix thì học để hiểu mô hình monitoring truyền thống, và vì nhiều doanh nghiệp Việt Nam vẫn chạy nó.

---

## 9.7 Grafana — Một mặt kính cho nhiều nguồn dữ liệu

### 9.7.1 Grafana là gì, giải quyết vấn đề gì

**Grafana** là nền tảng dashboard mã nguồn mở. Nó **không lưu metric hay log nào cả** — mỗi lần vẽ, nó cầm câu truy vấn đi hỏi **datasource** (Prometheus, Elasticsearch/OpenSearch, Loki, MySQL, CloudWatch...) rồi hiển thị kết quả. Vấn đề nó giải quyết rất đời thường: mỗi công cụ có UI riêng (Prometheus có UI thô, Kibana chỉ nhìn được Elasticsearch, Zabbix có frontend riêng) — vận hành thật thì không ai muốn mở 4 tab để trả lời câu "hệ thống có ổn không". Grafana cho phép **một dashboard trộn panel từ nhiều nguồn**: panel CPU đọc từ Prometheus nằm ngay cạnh panel đếm alert đọc từ index Wazuh.

Với người làm bảo mật, đây là điểm ăn tiền: **dashboard an ninh và dashboard hiệu năng cùng một chỗ**. Wazuh indexer bản chất là OpenSearch (xem 9.9), nên Grafana trỏ datasource vào đó là truy vấn được `wazuh-alerts-*` như dữ liệu thường — mình dựng dashboard SOC trên Grafana mà không đụng tới Wazuh dashboard.

### 9.7.2 Datasource

| Datasource | Kiểu dữ liệu | Ngôn ngữ truy vấn trong panel |
|---|---|---|
| Prometheus | Metric time-series | PromQL |
| Elasticsearch / OpenSearch | Document/log | Lucene query string + aggregation cấu hình trong panel |
| Loki | Log (label như Prometheus) | LogQL |
| MySQL/PostgreSQL | Bảng quan hệ | SQL |
| CloudWatch, Azure Monitor... | Metric cloud | Query builder riêng |

Mỗi datasource khai báo URL + credential (lưu phía server Grafana, mã hóa trong DB của nó). Nguyên tắc quyền tối thiểu áp dụng y như 9.1.5: user mà Grafana dùng để đọc Elasticsearch/OpenSearch chỉ cần quyền `read` trên đúng index cần vẽ (`wazuh-alerts-*`, `logs-*`), tuyệt đối không cấp admin.

### 9.7.3 Dashboard, Panel, Variable

- **Panel**: một ô hiển thị = một (hoặc vài) truy vấn + một kiểu vẽ (time series, gauge, stat, table, bar chart, heatmap). Ngưỡng màu (xanh/vàng/đỏ) đặt ngay trong panel — "panel chuyển đỏ" là ngôn ngữ chung của cả team.
- **Dashboard**: lưới các panel, chia sẻ chung time range và bộ lọc. Toàn bộ dashboard là **một file JSON** — export/import được, commit vào Git được (lại GitOps).
- **Variable**: biến dropdown ở đầu dashboard, ví dụ `instance` lấy giá trị động bằng `label_values(node_uname_info, instance)` — mọi panel dùng `$instance` trong truy vấn. Nhờ đó **một** dashboard phục vụ cả fleet thay vì mỗi máy một bản sao.
- **Dashboard cộng đồng**: grafana.com có kho dashboard đánh số ID để import thẳng (ví dụ "Node Exporter Full" cho node_exporter). Kinh nghiệm của mình: import để học cách người ta viết truy vấn, rồi **tự dựng bản gọn hơn** — dashboard 40 panel nhìn mọi thứ nhưng không nói được điều gì; dashboard tự dựng 7-8 panel đúng thứ mình cần lại dùng được hằng ngày.

### 9.7.4 Grafana alerting vs Alertmanager

Grafana có hệ alerting riêng (unified alerting, từ Grafana 8): định nghĩa rule trên bất kỳ datasource nào, đánh giá theo chu kỳ, gửi qua contact point (email/webhook/chat), có thể trỏ tới Alertmanager ngoài. Vậy trùng với Alertmanager của Prometheus? Cách mình phân vai:

| | Prometheus rule + Alertmanager | Grafana alerting |
|---|---|---|
| Rule sống ở đâu | File YAML cạnh server, review qua Git | DB của Grafana, tạo qua UI |
| Gần dữ liệu | Sát TSDB, không thêm hop nào | Thêm một lớp (Grafana query datasource) |
| Đa datasource | Chỉ Prometheus | Bất kỳ datasource nào (kể cả Elasticsearch) |
| Hợp với | Alert hạ tầng chuẩn hóa, fleet lớn | Alert cần trộn nguồn, hoặc team muốn thao tác UI |

Nguyên tắc mình theo: **alert hạ tầng cốt lõi đặt ở tầng thấp nhất có thể** (Prometheus rule + Alertmanager) — nó vẫn chạy kể cả khi Grafana chết; Grafana alerting dùng cho những cảnh báo tiện-thì-làm trên dữ liệu mà Alertmanager không với tới (ví dụ ngưỡng đếm trên index log).

### 9.7.5 Kinh nghiệm thực tế: hai dashboard mình dùng hằng ngày

**Dashboard "SOC Analyst View"** — tự dựng, datasource là index `wazuh-alerts-*` trên Wazuh indexer (OpenSearch):

| Panel | Truy vấn/aggregation | Trả lời câu gì |
|---|---|---|
| Alerts theo thời gian, tách severity | date histogram + terms theo `rule.level` | Hôm nay có "bão" alert không, bắt đầu từ lúc nào |
| Top rule kích hoạt | terms theo `rule.id` / `rule.description` | Loại sự kiện nào đang trội |
| **Top source IPs** | terms theo `data.srcip` | IP nào đang "chăm" hệ thống nhất |
| Top agent bị nhắm | terms theo `agent.name` | Máy nào đang hứng nhiều nhất |
| Bảng alert level cao mới nhất | filter `rule.level >= 10`, sort theo thời gian | Cái gì cần mở Wazuh xem ngay |

Panel Top source IPs là panel có "công" nhất: một lần liếc buổi sáng, mình thấy một IP lạ vọt lên đầu bảng với hàng trăm alert trong vài giờ — kéo ra là một VPS nước ngoài đang quét path traversal có bài bản trên một máy dev. Không có panel đó, từng alert riêng lẻ mức trung bình sẽ trôi qua như nhiễu nền; gom theo IP thì *chiến dịch* mới hiện hình. Phần điều tra sâu (query aggregation trực tiếp trên index, đọc `full_log`) nằm ở chương 8 (Wazuh); phản ứng phía nginx (rate limit, chặn tên tệp nhạy cảm) ở chương 11.

**Dashboard node metrics** — mỗi hàng một nhóm tài nguyên, biến `$instance` chọn máy:

- **CPU by mode** (truy vấn số 2 ở 9.6.5): nhìn màu là biết bệnh — `iowait` phình = đĩa, `steal` phình = hypervisor, `user` phình = app.
- **Memory available + Memory PSI**: hai panel cạnh nhau, và PSI mới là panel quyết định (xem Ghi chú cuối chương).
- **Root FS** + kết quả `predict_linear`: còn bao nhiêu, bao lâu nữa đầy.
- **Disk I/O** (`rate(node_disk_io_time_seconds_total)`) + **I/O PSI**.
- **Network** (throughput + drop/error).
- **Procs blocked** (`node_procs_blocked`): chỉ số bị bỏ quên nhưng cực nhạy với nghẽn I/O.

Triết lý dùng: **dashboard cho biết cao ở đâu, SSH + lệnh cho biết con nào gây ra.** Panel chỉ trả lời "CPU cao", "PSI memory dương kéo dài" — còn *process nào* thì phải vào máy chạy `htop`, `mpstat -P ALL`, `ps aux --sort=-%mem`, đọc `/proc/pressure/*`... Bộ lệnh theo từng panel mình để ở chương 2 (Linux) dạng runbook "panel đỏ → chạy gì trước". Hai thứ này là một cặp: dashboard không có runbook thì chỉ để ngắm, runbook không có dashboard thì không biết bắt đầu từ đâu.

**Lưu ý bảo mật Grafana**:

- Đổi ngay tài khoản mặc định `admin/admin`; bật HTTPS; đặt sau reverse proxy nếu phơi ra ngoài.
- Grafana từng có CVE nghiêm trọng bị khai thác thực tế (điển hình path traversal CVE-2021-43798 đọc file tùy ý qua URL plugin) — cập nhật như một ứng dụng web công khai thực thụ.
- Phân quyền theo org/team/folder: viewer chỉ xem dashboard, không sửa datasource. Nhớ rằng ai sửa được panel là *chạy được truy vấn tùy ý* bằng credential datasource của server — quyền editor cũng là một dạng quyền đọc dữ liệu.
- Không nhúng secret vào truy vấn/annotation; dashboard JSON hay được chia sẻ công khai, soát trước khi đăng (tên host nội bộ, IP, tên index).

---

## 9.8 Zabbix/Prometheus vs SIEM — Phân định bản chất

Đây là điểm hay bị nhầm. **Monitoring (Zabbix, Prometheus) giám sát "trạng thái/hiệu năng hạ tầng"**, **SIEM phân tích "sự kiện bảo mật"**. Khác nhau ở mô hình dữ liệu và động cơ phát hiện.

| Tiêu chí | Monitoring (Zabbix / Prometheus) | SIEM (Wazuh / Elastic Security / Splunk ES) |
|---|---|---|
| Dữ liệu | Metric số theo thời gian (CPU, RAM, disk, up/down) | Log/event đa nguồn đã chuẩn hóa |
| Phát hiện | Trigger/alerting rule ngưỡng trên metric | Decoder + rule + correlation theo hành vi |
| Câu hỏi | "Hệ thống có khỏe không?" | "Có ai đang tấn công không?" |
| Tương quan đa nguồn | Hạn chế (chủ yếu theo host/metric) | Mạnh (correlation across logs, MITRE ATT&CK) |
| Lưu trữ | RDBMS/TSDB, history+trends | Index full-text (Elasticsearch/Lucene) |
| Lý tưởng cho | Ops/SRE, availability, capacity | SOC, threat detection, IR, compliance |

Một sự cố "đĩa đầy" là việc của Zabbix/Prometheus. Một chuỗi "1000 lần đăng nhập thất bại rồi 1 lần thành công từ IP lạ" là việc của SIEM. Hai miền này **bổ sung** chứ không thay thế nhau. Dù vậy, metric vẫn có giá trị an ninh gián tiếp: CPU vọt bất thường lúc 3 giờ sáng (cryptominer), network egress tăng đột biến (exfiltration) — dashboard hiệu năng đôi khi là người báo tin đầu tiên, còn xác nhận thì phải quay về log/SIEM.

---

## 9.9 Khi nào dùng ELK vs Wazuh vs Zabbix vs Prometheus/Grafana

| Nhu cầu | Công cụ phù hợp | Lý do |
|---|---|---|
| Tập trung, tìm kiếm full-text log khối lượng lớn, tự xây dashboard điều tra | **ELK** | Search engine mạnh, linh hoạt mapping/query DSL |
| Threat detection sẵn sàng dùng: HIDS, FIM, rootcheck, rule MITRE, compliance (PCI, CIS), agent đa nền tảng | **Wazuh** | Là SIEM/XDR mã nguồn mở, có decoder+rule sẵn, thường dựng trên chính Elasticsearch/OpenSearch để lưu/hiển thị |
| Giám sát hạ tầng truyền thống, thiết bị mạng SNMP/IPMI, quy trình trực ca escalation bài bản | **Zabbix** | Trigger engine + template + proxy phân tán, agentless SNMP/IPMI |
| Giám sát metric hạ tầng cloud/container, target động, alert as code | **Prometheus** | Pull model + service discovery + PromQL + Alertmanager; cấu hình dạng file hợp GitOps |
| Một dashboard chung cho cả metric lẫn log/an ninh, nhiều nguồn dữ liệu | **Grafana** | Datasource đa hệ (Prometheus, Elasticsearch/OpenSearch...), panel/variable/alerting hợp nhất một mặt kính |

Mối quan hệ kỹ thuật cần nắm:
- **Wazuh dùng nền lưu trữ/hiển thị của Elastic Stack/OpenSearch** (Wazuh indexer dựa trên OpenSearch ~ Elasticsearch; Wazuh dashboard ~ Kibana). Tức ELK là **nền hạ tầng dữ liệu**, Wazuh thêm **lớp phát hiện bảo mật** (decoder, rule, agent, FIM) lên trên.
- **ELK thuần** cũng có thể làm SIEM nếu dùng Elastic Security (detection rules, ECS schema), nhưng phải tự dựng/áp rule; Wazuh cho sẵn nhiều hơn out-of-the-box.
- **Zabbix và Prometheus** cùng đứng ở miền monitoring; không cạnh tranh với ELK/Wazuh mà chạy song song. Giữa hai công cụ này, chọn theo bài toán (xem 9.6.7) — hiếm khi cần cả hai.
- **Grafana đọc được cả hai miền**: trỏ datasource vào Prometheus là có dashboard hiệu năng, trỏ vào Wazuh indexer (OpenSearch) là có dashboard an ninh — cùng một chỗ. Kibana/Wazuh dashboard vẫn mạnh hơn cho *điều tra tương tác* (Discover, Dev Tools); Grafana thắng ở *màn hình theo dõi hằng ngày*.

Kiến trúc tham chiếu trong một tổ chức:
```
   Hạ tầng/hiệu năng ──▶ node_exporter ──▶ Prometheus ──▶ Alertmanager (alert ops)
                                              │
   Log & security event ──▶ agent ──▶ Wazuh ──┼──▶ Wazuh indexer (OpenSearch)
                                              │            │
                                              └────────────┴──▶ GRAFANA (một mặt kính:
                                                                dashboard node metrics
                                                                + dashboard SOC)
   Biến thể truyền thống: Zabbix thay Prometheus; Beats/Logstash ──▶ Elasticsearch ──▶ Kibana
```

---

## 9.10 Tóm tắt các quyết định thiết kế cốt lõi

| Quyết định | Vì sao |
|---|---|
| Inverted index + BM25 | Tìm full-text nhanh trên hàng tỷ doc; điểm số bão hòa chống nhồi từ |
| Tách doc values khỏi inverted index | Sort/aggregate cần truy cập columnar theo docId |
| Số primary shard cố định | Routing dùng `% n_shards`; đổi = reindex toàn bộ |
| Translog | Khôi phục segment chưa fsync sau crash |
| `dynamic: strict` mapping | Chống mapping explosion (DoS heap) |
| Filebeat at-least-once + registry inode | Không mất log qua logrotate/crash |
| Zabbix History vs Trends | History phình nhanh → giữ ngắn; Trends gộp giờ → giữ lâu |
| Trigger hysteresis / `for` trong alerting rule | Chống flapping cảnh báo; spike ngắn không đáng đánh thức ai |
| Magic "ZBXD" + length header | Tách message trên TCP stream |
| Prometheus pull model | Server kiểm soát nhịp thu; `up == 0` phát hiện target chết miễn phí; debug bằng trình duyệt |
| Counter chỉ tăng + `rate()` | Chịu mất mẫu, tự xử lý reset; giá trị thô vô nghĩa, tốc độ thay đổi mới có nghĩa |
| Metric name + label thay item key phẳng | Cắt lát đa chiều (`sum by (mode)`) — nhưng phải kiểm soát cardinality |
| Tách Alertmanager khỏi Prometheus server | "Cái gì bất thường" (rule) tách khỏi "báo cho ai, gom thế nào" (route) |
| Grafana không lưu dữ liệu | Mặt kính đa datasource: metric + log/an ninh cùng một dashboard |
| TLS/PSK Zabbix, xpack.security ES, bind nội bộ /metrics | Mặc định không mã hóa/không xác thực = lộ dữ liệu/giả mạo |
| Monitoring ≠ SIEM | Metric/threshold vs event/correlation — bổ sung nhau |


---

## Ghi chú của mình

> *Khu vực ghi chú cá nhân: những điểm từng hiểu sai, phần còn đang tìm hiểu, hoặc kinh nghiệm rút ra khi thực hành — cập nhật dần.*

- **Học Zabbix, vận hành Prometheus** — mình học Zabbix khá kỹ (trigger, template, protocol) nhưng khi vận hành thật thì lại là Prometheus + Grafana, và cảm nhận hai bên khác hẳn. Zabbix cho mình cảm giác "phần mềm quản trị": mọi thứ qua GUI, cấu hình sống trong DB, làm xong không nhớ mình đã bấm gì. Prometheus thì mọi thứ là file — sửa một alert rule là một commit, đọc lại diff là hiểu ai đổi gì vì sao. Học Zabbix không phí: nhờ nó mình hiểu trigger/hysteresis/escalation là gì trước khi gặp `for`/route/inhibition, và nhiều công ty ở đây vẫn chạy Zabbix thật.
- **PSI đáng tin hơn %RAM used** — bài học mình phải trả bằng vài lần hết hồn. Panel memory used đỏ rực, SSH vào thì máy chạy êm ru: RAM "used" cao vì Linux tận dụng page cache và app (nhất là mấy con chạy JVM/heap lớn) giữ chỗ sẵn. Từ ngày thêm panel PSI (`rate(node_pressure_memory_waiting_seconds_total[5m])`), mình gần như không nhìn % used nữa: PSI bằng 0 thì kệ used bao nhiêu; PSI dương kéo dài mới là thiếu RAM thật — và lúc đó `vmstat` sẽ thấy si/so, `dmesg` lảng vảng OOM.
- **%steal — chỉ số mình từng không biết tồn tại.** Có lúc panel CPU của một máy lên cao mà `htop` không thấy process nào ăn. Hóa ra là `steal`: VM cloud bị hypervisor bóp (noisy neighbor). Từ đó panel CPU của mình luôn tách theo mode chứ không vẽ một đường "CPU %" duy nhất — cùng là "CPU cao" nhưng `user`/`iowait`/`steal` là ba bệnh khác nhau, ba cách xử khác nhau (và riêng steal thì... không phải lỗi máy mình).
- **Panel Top source IPs là panel rẻ nhất mà được việc nhất.** Chỉ là một terms aggregation theo IP nguồn trên index alert của Wazuh, nhưng chính nó giúp mình phát hiện sớm một chiến dịch quét path traversal: một IP lạ đứng đầu bảng với hàng trăm alert dồn trong vài giờ. Từng alert lẻ mức trung bình sẽ chìm trong nhiễu; gom theo IP thì hành vi *có chủ đích* nổi lên ngay. Bài học lớn hơn: dashboard an ninh không cần hoành tráng, cần đúng vài câu hỏi mình thật sự muốn hỏi mỗi sáng.
- **Dashboard cho biết cao ở đâu, lệnh cho biết con nào gây ra.** Hồi đầu mình cứ ngồi nhìn Grafana đợi nó "nói" thủ phạm — nó không nói được, vì node_exporter không phơi metric theo process. Sau mình viết hẳn một runbook: panel nào đỏ thì SSH vào chạy bộ lệnh nào trước (để ở chương 2). Từ lúc có cặp dashboard + runbook, thời gian từ "thấy đỏ" đến "biết tại sao" ngắn hơn hẳn.
- **Đang tìm hiểu tiếp**: recording rules (tính sẵn truy vấn nặng), lưu metric dài hạn (Thanos/Mimir — mới đọc, chưa dựng), và Loki để log nhẹ đi cạnh Prometheus xem có thay được một phần use case ELK cho hệ nhỏ không.
