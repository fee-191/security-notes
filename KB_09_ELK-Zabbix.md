# Chương 9 — Observability & Giám sát hạ tầng

## Tổng quan

Chương trình bày hai họ công cụ nền tảng của **observability** và **giám sát hạ tầng**: **ELK/Elastic Stack** (thu thập, lưu trữ và truy vấn log) và **Zabbix** (giám sát trạng thái và hiệu năng hạ tầng theo mô hình metric/threshold). Hai họ này trả lời hai câu hỏi vận hành khác nhau và bổ sung cho nhau:

- **ELK** trả lời "chuyện gì đã xảy ra, ai làm gì, lúc nào" — dựa trên log/event.
- **Zabbix** trả lời "hệ thống có khỏe không, chỉ số nào vượt ngưỡng" — dựa trên metric theo thời gian.

Cả hai đều thiết yếu với an toàn thông tin: dấu vết tấn công nằm trong log, còn sự cố hạ tầng thường khởi đầu từ một chỉ số bất thường.

**Các khái niệm cốt lõi và vấn đề mà chúng giải quyết:**

- **Log**: bản ghi tuần tự các sự kiện do hệ thống sinh ra (truy cập, đăng nhập thất bại, lỗi phần mềm). Là nguồn bằng chứng chính khi điều tra sự cố bảo mật, nhưng chỉ hữu dụng khi được tập trung và cho phép tìm kiếm.
- **ELK Stack**: bộ ba **E**lasticsearch + **L**ogstash + **K**ibana (thường kèm Beats). Giải quyết bài toán log phân tán trên nhiều máy: gom về một nơi, đánh chỉ mục để tìm kiếm full-text và trực quan hóa phục vụ điều tra.
- **Elasticsearch**: **search engine** dựa trên Lucene, dùng **inverted index** để tra cứu full-text ở quy mô tỷ bản ghi với độ trễ mili-giây — điều CSDL quan hệ không đáp ứng được.
- **Logstash**: pipeline xử lý đặt giữa nguồn log và Elasticsearch; nhận log thô, parse, làm sạch và chuẩn hóa thành dữ liệu có cấu trúc. Dữ liệu sạch là điều kiện để tìm kiếm và thống kê chính xác.
- **Kibana**: lớp trực quan hóa và truy vấn trên Elasticsearch; biến dữ liệu thô thành biểu đồ, bảng và dashboard, giúp phát hiện bất thường nhanh hơn đọc log thô.
- **Beats**: họ agent nhẹ trên host nguồn — Filebeat (log file), Metricbeat (CPU/RAM), Winlogbeat (Windows Event Log). Thu thập dữ liệu tại chỗ và đẩy về Logstash/Elasticsearch.
- **Zabbix**: **monitoring system** đo liên tục các chỉ số hạ tầng (CPU, RAM, đĩa, tình trạng dịch vụ) và tự động cảnh báo khi vượt ngưỡng, giúp xử lý sự cố trước khi hệ thống sập.
- **Metric** và **Trigger**: **Metric** là giá trị đo tại một thời điểm (ví dụ CPU 87%); chuỗi metric theo thời gian cho thấy xu hướng. **Trigger** là biểu thức điều kiện ("nếu CPU trung bình 5 phút vượt 90% thì cảnh báo") — cơ chế giám sát tự động thay cho việc trực màn hình thủ công.
- **SIEM** (Wazuh, Splunk): hệ phát hiện tấn công, đọc log và tương quan sự kiện để nhận diện mẫu hành vi đáng ngờ. Phân định cốt lõi: **Zabbix giám sát sức khỏe hạ tầng, SIEM phát hiện an ninh** — hai hệ bổ sung, không thay thế nhau.

## 9.0 Tổng quan và định vị công cụ

Chương này đào sâu hai họ công cụ thường bị nhầm lẫn về vai trò trong môi trường vận hành: **ELK/Elastic Stack** (nền tảng thu thập, lưu trữ, truy vấn và trực quan hóa log/event ở quy mô lớn) và **Zabbix** (nền tảng giám sát hạ tầng và hiệu năng theo mô hình metric/threshold). Mục tiêu của chương không phải "giới thiệu sản phẩm" mà mô tả tới mức **định dạng dữ liệu trên dây (wire format), cấu trúc bản ghi trên đĩa, từng trường cấu hình và từng bước xử lý** — đủ để một kỹ sư Blue Team/AppSec/DevSecOps vận hành thật, gỡ lỗi thật và đánh giá rủi ro thật.

Một điểm phân định bản chất phải nắm ngay từ đầu:

| Khía cạnh | ELK Stack | Zabbix | SIEM (vd Wazuh, Splunk ES) |
|---|---|---|---|
| Đơn vị dữ liệu | Document JSON (full-text + structured) | Metric (giá trị số/chuỗi theo thời gian) | Security event đã chuẩn hóa + rule correlation |
| Mô hình lưu trữ | Inverted index + doc values (Lucene) | Time-series trong RDBMS/TSDB | Index + alert store |
| Câu hỏi điển hình | "Tìm mọi request 5xx chứa chuỗi X trong 15 phút" | "CPU host A có vượt 90% trong 5 phút không?" | "Có chuỗi hành vi nào khớp MITRE T1110 không?" |
| Cơ chế cảnh báo | Watcher/ElastAlert/Detection rules (bổ sung) | Trigger expression (lõi) | Correlation rules + decoder (lõi) |
| Bản chất | Search engine | Monitoring system | Detection & response |

Ghi nhớ: Elasticsearch **là một search engine** chứ không phải database quan hệ; Zabbix **là một monitoring system** chứ không phải log store. Mọi quyết định thiết kế bên dưới đều bắt nguồn từ hai bản chất này.

---

## 9.1 Elasticsearch — Lõi lưu trữ và tìm kiếm

### 9.1.1 Inverted index — Vì sao và cấu trúc bên trong

Elasticsearch dựng trên thư viện **Apache Lucene**. Cấu trúc dữ liệu trung tâm là **inverted index** (chỉ mục đảo). Trong CSDL quan hệ, ta đi từ hàng → cột → giá trị (forward). Inverted index đảo ngược: đi từ **term (từ) → danh sách document chứa term đó**. Đây là lý do tìm full-text trên hàng tỷ document vẫn ở mức mili-giây: thay vì quét tuyến tính, ta tra cứu term rồi hợp/giao các posting list.

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

`system.cpu.utilization` (Metricbeat) tương tự khái niệm `system.cpu.util` bên Zabbix — nhưng đây là metric phục vụ phân tích, không có trigger/threshold engine như Zabbix.

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
       - chạy remote command (vd restart service) — CẨN TRỌNG
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

## 9.6 Zabbix vs SIEM — Phân định bản chất

Đây là điểm hay bị nhầm. **Zabbix giám sát "trạng thái/hiệu năng hạ tầng"**, **SIEM phân tích "sự kiện bảo mật"**. Khác nhau ở mô hình dữ liệu và động cơ phát hiện.

| Tiêu chí | Zabbix (Monitoring) | SIEM (Wazuh / Elastic Security / Splunk ES) |
|---|---|---|
| Dữ liệu | Metric số theo thời gian (CPU, RAM, disk, up/down) | Log/event đa nguồn đã chuẩn hóa |
| Phát hiện | Trigger ngưỡng trên metric | Decoder + rule + correlation theo hành vi |
| Câu hỏi | "Hệ thống có khỏe không?" | "Có ai đang tấn công không?" |
| Tương quan đa nguồn | Hạn chế (chủ yếu theo host/item) | Mạnh (correlation across logs, MITRE ATT&CK) |
| Lưu trữ | RDBMS/TSDB, history+trends | Index full-text (Elasticsearch/Lucene) |
| Lý tưởng cho | Ops/SRE, availability, capacity | SOC, threat detection, IR, compliance |

Một sự cố "đĩa đầy" là việc của Zabbix. Một chuỗi "1000 lần đăng nhập thất bại rồi 1 lần thành công từ IP lạ" là việc của SIEM. Hai hệ này **bổ sung** chứ không thay thế nhau.

---

## 9.7 Khi nào dùng ELK vs Wazuh vs Zabbix

| Nhu cầu | Công cụ phù hợp | Lý do |
|---|---|---|
| Tập trung, tìm kiếm full-text log khối lượng lớn, tự xây dashboard điều tra | **ELK** | Search engine mạnh, linh hoạt mapping/query DSL |
| Threat detection sẵn sàng dùng: HIDS, FIM, rootcheck, rule MITRE, compliance (PCI, CIS), agent đa nền tảng | **Wazuh** | Là SIEM/XDR mã nguồn mở, có decoder+rule sẵn, thường dựng trên chính Elasticsearch/OpenSearch để lưu/hiển thị |
| Giám sát hạ tầng/hiệu năng, alert ngưỡng (CPU, RAM, disk, service up/down), SNMP thiết bị mạng | **Zabbix** | Trigger engine + template + proxy phân tán, agentless SNMP/IPMI |

Mối quan hệ kỹ thuật cần nắm:
- **Wazuh dùng nền lưu trữ/hiển thị của Elastic Stack/OpenSearch** (Wazuh indexer dựa trên OpenSearch ~ Elasticsearch; Wazuh dashboard ~ Kibana). Tức ELK là **nền hạ tầng dữ liệu**, Wazuh thêm **lớp phát hiện bảo mật** (decoder, rule, agent, FIM) lên trên.
- **ELK thuần** cũng có thể làm SIEM nếu dùng Elastic Security (detection rules, ECS schema), nhưng phải tự dựng/áp rule; Wazuh cho sẵn nhiều hơn out-of-the-box.
- **Zabbix** đứng riêng ở miền monitoring; không cạnh tranh trực tiếp với ELK/Wazuh mà chạy song song.

Kiến trúc tham chiếu trong một tổ chức:
```
   Hạ tầng/hiệu năng ──▶ Zabbix (alert ops, capacity)
   Log & security event ──▶ Beats/Logstash ──▶ Elasticsearch ──▶ {Kibana hiển thị,
                                                                   Wazuh/Elastic Security phát hiện}
```

---

## 9.8 Tóm tắt các quyết định thiết kế cốt lõi

| Quyết định | Vì sao |
|---|---|
| Inverted index + BM25 | Tìm full-text nhanh trên hàng tỷ doc; điểm số bão hòa chống nhồi từ |
| Tách doc values khỏi inverted index | Sort/aggregate cần truy cập columnar theo docId |
| Số primary shard cố định | Routing dùng `% n_shards`; đổi = reindex toàn bộ |
| Translog | Khôi phục segment chưa fsync sau crash |
| `dynamic: strict` mapping | Chống mapping explosion (DoS heap) |
| Filebeat at-least-once + registry inode | Không mất log qua logrotate/crash |
| Zabbix History vs Trends | History phình nhanh → giữ ngắn; Trends gộp giờ → giữ lâu |
| Trigger hysteresis | Chống flapping cảnh báo |
| Magic "ZBXD" + length header | Tách message trên TCP stream |
| TLS/PSK Zabbix, xpack.security ES | Mặc định không mã hóa = lộ dữ liệu/giả mạo |
| Zabbix ≠ SIEM | Metric/threshold vs event/correlation — bổ sung nhau |
