# Chương 13 — Bảo mật Đám mây

## Tổng quan

Mình học mảng cloud security này không phải vì tò mò lý thuyết, mà vì công việc thật: hạ tầng ngày nay hiếm khi nằm gọn trên một nhà cung cấp — AWS chỗ này, OCI chỗ kia, rồi sớm muộn cũng đụng GCP khi làm việc với đối tác. Đọc vài báo cáo lộ dữ liệu thực tế mới thấy một điểm chung đáng sợ: phần lớn không phải do nhà cung cấp bị hack, mà do chính khách hàng cấu hình sai — một bucket để public, một security group mở nhầm cổng quản trị, một IMDSv1 quên tắt. Nên câu hỏi mình cần trả lời trước tiên không phải "cloud có an toàn không", mà là "trong cả chồng hạ tầng này, đâu mới là phần việc của mình".

Chương bắt đầu từ đúng ranh giới đó: mô hình IaaS/PaaS/SaaS và Shared Responsibility Model, hai thứ chỉ ra ai vá lỗi tầng nào và dập tắt luôn ngộ nhận "lên cloud là nhà cung cấp lo hết". Từ đó chương đi vào các khối mình phải tự quản — IAM và least privilege, VPC cùng Security Group/Network ACL, những dịch vụ dễ gây sự cố nhất trong thực tế như S3 và KMS, lớp giám sát CloudTrail/CloudWatch/GuardDuty, và IMDS, thứ hay bị khai thác qua SSRF nếu còn chạy bản v1. Organizations và SCP khép lại phần này bằng vai trò chốt guardrail ở cấp tổ chức, không phụ thuộc từng tài khoản con có cẩn thận hay không.

Nửa sau chương bước ra ngoài AWS: trước là bảng ánh xạ dịch vụ sang GCP để học một nền tảng suy ra nền tảng kia, sau là hẳn một phần riêng cho OCI (13.14). Mình từng tưởng OCI chỉ đổi tên dịch vụ so với AWS, hoá ra nhiều khái niệm nền tảng thiết kế khác hẳn — cô lập bằng compartment thay vì account, policy viết dạng câu thay vì JSON, bucket private mặc định thay vì phải tự khoá lại. Đối chiếu xong cả ba nền tảng, chương khép bằng các đường tấn công cloud phổ biến, công cụ CSPM quét cấu hình sai liên tục, và Secret Manager để không phải hardcode bí mật trong code.

> Ví dụ trong chương là lệnh AWS CLI và OCI CLI thật kèm output mẫu; chỗ nào số liệu có thể đổi theo thời gian đều ghi "cần kiểm chứng".

---

## 13.1. Mô hình dịch vụ đám mây: IaaS / PaaS / SaaS

### 13.1.1. Là gì

Điện toán đám mây phân tầng theo "ai vận hành tầng nào" trong ngăn xếp hạ tầng. Ba mô hình chuẩn (định nghĩa gốc: NIST SP 800-145):

| Mô hình | Nhà cung cấp quản lý | Khách hàng quản lý | Ví dụ AWS | Ví dụ GCP |
|---|---|---|---|---|
| IaaS (Infrastructure) | Hypervisor, host OS, mạng vật lý, lưu trữ vật lý | Guest OS, runtime, app, data, cấu hình mạng ảo | EC2, EBS, VPC | Compute Engine, Persistent Disk |
| PaaS (Platform) | Cộng thêm: OS, runtime, patching | App code + data + cấu hình ứng dụng | Elastic Beanstalk, Lambda, RDS | App Engine, Cloud Functions, Cloud SQL |
| SaaS (Software) | Toàn bộ ngăn xếp | Chỉ dữ liệu người dùng + cấu hình trong app | WorkMail, QuickSight | Workspace |

### 13.1.2. Cơ chế bên trong: ranh giới tin cậy thay đổi theo tầng

Điểm cốt lõi về bảo mật: **bề mặt tấn công và nghĩa vụ vá lỗi dịch chuyển theo mô hình**.

```
                 IaaS            PaaS            SaaS
               +--------+      +--------+      +--------+
   App         |   KH   |      |   KH   |      |  NCC   |
   Data        |   KH   |      |   KH   |      |  KH*   |   *KH vẫn sở hữu/cấu hình truy cập dữ liệu
   Runtime     |   KH   |      |  NCC   |      |  NCC   |
   OS          |   KH   |      |  NCC   |      |  NCC   |
   Hypervisor  |  NCC   |      |  NCC   |      |  NCC   |
   Mạng vật lý  |  NCC   |      |  NCC   |      |  NCC   |
               +--------+      +--------+      +--------+
   KH = Khách hàng,  NCC = Nhà cung cấp
```

**Vì sao:** với IaaS, một lỗ hổng kernel chưa vá trên guest OS là trách nhiệm của bạn; với PaaS như Lambda, AWS vá runtime nhưng **một thư viện npm có lỗ hổng trong gói deploy vẫn là của bạn**. Hiểu sai ranh giới này là gốc rễ của hầu hết sự cố misconfiguration (cấu hình sai).

---

## 13.2. Shared Responsibility Model (Mô hình trách nhiệm chung)

### 13.2.1. Là gì

Khung phân định trách nhiệm bảo mật. AWS gọi tắt:

- **Security OF the cloud** — của AWS: phần cứng, region/AZ, mạng vật lý, hypervisor, dịch vụ nền.
- **Security IN the cloud** — của khách hàng: IAM, mã hóa dữ liệu, cấu hình Security Group, vá guest OS (với IaaS), phân loại dữ liệu.

GCP dùng cụm "Shared fate" (số phận chung) — nhấn mạnh Google chủ động cung cấp blueprint an toàn mặc định, nhưng phân định trách nhiệm về cơ bản tương đương.

Sơ đồ ranh giới trách nhiệm:

```
        ===== SECURITY IN THE CLOUD (Khách hàng) =====
        +-----------------------------------------------+
        |  Dữ liệu khách hàng + phân loại dữ liệu        |
        |  IAM / policy / quản lý danh tính & truy cập   |
        |  Cấu hình Security Group, NACL, firewall       |
        |  Mã hóa at-rest / in-transit (bật & cấu hình)  |
        |  Vá guest OS, runtime, ứng dụng (mức IaaS)     |
        +-----------------------------------------------+
                          | ranh giới phân định
        +-----------------------------------------------+
        |  Hypervisor / ảo hóa                           |
        |  Dịch vụ nền (compute, storage, DB engine)     |
        |  Mạng vật lý, region / AZ                       |
        |  Phần cứng, cơ sở vật lý (datacenter)          |
        +-----------------------------------------------+
        ===== SECURITY OF THE CLOUD (Nhà cung cấp) =====
```

Đường phân định dịch chuyển lên/xuống theo mô hình dịch vụ (IaaS đẩy ranh giới xuống thấp, SaaS đẩy lên cao), nhưng dữ liệu và cấu hình truy cập luôn thuộc trách nhiệm khách hàng. Đây là lý do hầu hết sự cố rò rỉ nằm ở nửa trên của sơ đồ.

### 13.2.2. Bảng phân định chi tiết theo dịch vụ

| Hạng mục | EC2 (IaaS) | RDS (PaaS) | S3 (lưu trữ quản lý) |
|---|---|---|---|
| Vá hypervisor | AWS | AWS | AWS |
| Vá OS | Khách hàng | AWS | N/A |
| Vá DB engine | Khách hàng | AWS | N/A |
| Mã hóa at-rest | Khách hàng bật | Khách hàng bật | Khách hàng bật/SSE |
| Mã hóa in-transit | Khách hàng cấu hình | Khách hàng (force SSL) | Khách hàng (policy `aws:SecureTransport`) |
| Cấu hình truy cập (IAM/policy) | Khách hàng | Khách hàng | Khách hàng |
| Phân loại dữ liệu | Khách hàng | Khách hàng | Khách hàng |

**Lưu ý:** gần như **toàn bộ sự cố rò rỉ dữ liệu đám mây nổi tiếng nằm ở phần "IN the cloud"** — tức lỗi của khách hàng (bucket public, key lộ trong git, IAM quá rộng). AWS/GCP hiếm khi bị thủng ở tầng họ quản lý.

---

## 13.3. AWS IAM — Identity and Access Management

### 13.3.1. Các thực thể (entities)

| Thực thể | Định nghĩa | ARN ví dụ |
|---|---|---|
| Root user | Chủ tài khoản, toàn quyền tuyệt đối, không giới hạn được bằng IAM policy | `arn:aws:iam::123456789012:root` |
| IAM User | Danh tính người/dịch vụ lâu dài, có credentials | `arn:aws:iam::123456789012:user/alice` |
| IAM Group | Tập hợp user để gắn policy chung | `arn:aws:iam::123456789012:group/devs` |
| IAM Role | Danh tính tạm thời, không có credential cố định, được "assume" | `arn:aws:iam::123456789012:role/app-role` |
| Policy | Tài liệu JSON định nghĩa quyền | `arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess` |

Cấu trúc ARN (Amazon Resource Name) — từng trường:

```
arn : partition : service : region : account-id : resource-type / resource
 |        |         |         |          |              |
 |        |         |         |          |              +-- vd: user/alice, bucket/my-data
 |        |         |         |          +-- 12 chữ số tài khoản
 |        |         |         +-- vd: us-east-1 (S3/IAM thường để trống vì global)
 |        |         +-- vd: iam, s3, ec2
 |        +-- aws | aws-cn (Trung Quốc) | aws-us-gov
 +-- hằng "arn"
```

| Trường ARN | Kích thước | Ý nghĩa | Ví dụ |
|---|---|---|---|
| arn | cố định 3 ký tự | literal | `arn` |
| partition | chuỗi | vùng pháp lý | `aws` |
| service | chuỗi | namespace dịch vụ | `s3` |
| region | chuỗi | region (trống nếu global) | `us-east-1` hoặc rỗng |
| account-id | 12 chữ số | ID tài khoản | `123456789012` |
| resource | chuỗi | định danh tài nguyên | `bucket/logs` |

### 13.3.2. Policy JSON — mổ xẻ từng trường

Đây là cấu trúc trung tâm của toàn bộ ủy quyền AWS. Một policy là một tài liệu JSON.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadSpecificBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::company-reports",
        "arn:aws:s3:::company-reports/*"
      ],
      "Condition": {
        "StringEquals": { "aws:PrincipalTag/team": "finance" },
        "IpAddress": { "aws:SourceIp": "203.0.113.0/24" },
        "Bool": { "aws:MultiFactorAuthPresent": "true" }
      }
    }
  ]
}
```

Mô tả từng trường:

| Trường | Bắt buộc | Ý nghĩa | Giá trị ví dụ |
|---|---|---|---|
| `Version` | Có | Phiên bản ngôn ngữ policy. PHẢI là `2012-10-17` để dùng được biến/condition. `2008-10-17` là cũ, không hỗ trợ policy variables | `2012-10-17` |
| `Statement` | Có | Mảng các câu lệnh quyền | `[ {...} ]` |
| `Sid` | Không | Statement ID, nhãn để đọc/quản lý | `AllowReadSpecificBucket` |
| `Effect` | Có | `Allow` hoặc `Deny` | `Allow` |
| `Action` | Có (hoặc NotAction) | Hành động API, dạng `service:Operation`, hỗ trợ `*` | `s3:GetObject` |
| `Resource` | Có với policy gắn vào identity | ARN tài nguyên áp dụng | `arn:aws:s3:::bucket/*` |
| `Principal` | Chỉ trong resource-based/trust policy | Ai được phép (user/role/service) | `{"AWS": "...role/x"}` |
| `Condition` | Không | Điều kiện bổ sung (khóa toán tử) | `StringEquals`, `IpAddress`, `Bool` |

**Vì sao** `Version` lại là một ngày cố định: đó không phải ngày bạn viết policy mà là **phiên bản của ngữ pháp policy language**. AWS đóng băng giá trị này; ghi sai (vd ngày hôm nay) sẽ làm condition/variable không hoạt động đúng.

Các khóa Condition toán tử thường gặp:

| Toán tử | Dùng cho | Ví dụ key |
|---|---|---|
| `StringEquals` / `StringLike` | so chuỗi (Like hỗ trợ `*`) | `aws:PrincipalTag/team` |
| `IpAddress` / `NotIpAddress` | CIDR | `aws:SourceIp` |
| `Bool` | true/false | `aws:MultiFactorAuthPresent`, `aws:SecureTransport` |
| `DateGreaterThan` | thời gian | `aws:CurrentTime` |
| `ArnLike` | so ARN | `aws:SourceArn` |

### 13.3.3. Thuật toán đánh giá quyền (Policy Evaluation Logic) — từng bước

Khi một request API tới, AWS chạy quy trình quyết định **Allow / Deny** như sau:

```
1. Mặc định: DENY ngầm (implicit deny) cho mọi thứ.
2. Thu thập TẤT CẢ policy áp dụng: identity-based, resource-based,
   permission boundary, SCP (Organizations), session policy.
3. Có Explicit DENY ở bất kỳ policy nào?  --> YES => DENY (kết thúc).
4. SCP cho phép Action?                    --> NO  => DENY.
5. Permission boundary cho phép?           --> NO  => DENY.
6. Có Explicit ALLOW trong identity/resource policy? --> YES => ALLOW.
7. Ngược lại                                --> DENY (implicit).
```

Sơ đồ state machine:

```
        +----------------+
        | Implicit Deny  |  (trạng thái khởi đầu)
        +-------+--------+
                |
        có Explicit Deny? --yes--> [DENY] (luôn thắng)
                | no
        SCP allow & Boundary allow & Explicit Allow? --no--> [DENY]
                | yes
              [ALLOW]
```

**Lưu ý:** Explicit Deny luôn thắng mọi Allow. Đây là nền tảng để dựng guardrail (hàng rào) cho tài khoản: dù ai đó vô tình cấp `AdministratorAccess`, một Deny trong SCP/boundary vẫn chặn được.

### 13.3.4. STS AssumeRole và Trust Policy

STS (Security Token Service) cấp **credential tạm thời**. Một Role có hai phần policy:

- **Permission policy**: role *làm được gì*.
- **Trust policy** (assume role policy document): *ai được phép assume* role này — đây là một resource-based policy đặc biệt với trường `Principal`.

Trust policy mẫu (cho phép một role trong tài khoản khác assume, kèm ExternalId chống "confused deputy"):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::222233334444:role/partner-app" },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": { "sts:ExternalId": "U7x-9213-secret" }
    }
  }]
}
```

Lệnh assume thật và output:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/app-role \
  --role-session-name audit-2026 \
  --external-id U7x-9213-secret \
  --duration-seconds 3600
```

Output (rút gọn):

```json
{
  "Credentials": {
    "AccessKeyId": "ASIA....EXAMPLE",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "SessionToken": "FwoGZXIvYXdz....<rất dài>",
    "Expiration": "2026-06-19T15:00:00Z"
  },
  "AssumedRoleUser": {
    "Arn": "arn:aws:sts::123456789012:assumed-role/app-role/audit-2026"
  }
}
```

Phân biệt qua **prefix của AccessKeyId** — đây là dấu hiệu nhận diện quan trọng khi điều tra log:

| Prefix | Loại credential | Thời hạn |
|---|---|---|
| `AKIA` | Long-term (IAM user access key) | Vĩnh viễn tới khi xóa |
| `ASIA` | Temporary (STS) | Có Expiration |

**Vì sao** cần ExternalId: chống tấn công confused deputy. Nếu một nhà cung cấp SaaS dùng cùng một role-arn cho nhiều khách hàng, kẻ tấn công biết role-arn của bạn có thể lừa SaaS assume role của bạn. ExternalId là bí mật chỉ bạn và SaaS biết, đính kèm trong condition để chặn.

### 13.3.5. Permission Boundary

Là một managed policy gắn vào user/role, đặt **trần quyền tối đa**. Quyền hiệu lực = giao (intersection) của permission policy AND boundary.

```
Quyền hiệu lực = (Identity policy ALLOW)  ∩  (Boundary ALLOW)  -  (mọi DENY)
```

Ví dụ: developer được gắn `AdministratorAccess` nhưng boundary chỉ cho `s3:*` và `ec2:*` => thực tế chỉ thao tác được S3 và EC2. Dùng để **ủy quyền tạo IAM an toàn** (cho dev tự tạo role nhưng không vượt quá boundary).

### 13.3.6. MFA

MFA TOTP theo RFC 6238 (TOTP) dựa trên RFC 4226 (HOTP). Mã 6 chữ số tính từ:

```
TOTP = HOTP(K, T)  với  T = floor((UnixTime - T0) / X)
   K  = shared secret (Base32), X = 30 giây (time step), T0 = 0
   HOTP = Truncate( HMAC-SHA1(K, T) ) mod 10^6
```

Ép buộc MFA bằng condition `aws:MultiFactorAuthPresent` (như mục 13.3.2). **Lưu ý:** với root user, bật MFA phần cứng/ảo là biện pháp ưu tiên số một.

---

## 13.4. AWS VPC — Virtual Private Cloud

Sơ đồ kiến trúc VPC điển hình (subnet public/private, IGW/NAT, vị trí SG và NACL):

```
                          Internet
                             |
                       +-----------+
                       |    IGW    |  (Internet Gateway)
                       +-----------+
                             |
   VPC 10.0.0.0/16           |
   +-------------------------|-----------------------------------+
   |   PUBLIC SUBNET 10.0.1.0/24                                  |
   |   route: 0.0.0.0/0 -> IGW          [NACL áp ở mức subnet]    |
   |   +----------------+      +-----------------+                |
   |   |  NAT Gateway   |      |  Bastion/LB     | (SG ở mức ENI) |
   |   +-------+--------+      +-----------------+                |
   |           |                                                  |
   |  ---------|------------------------------------------------  |
   |   PRIVATE SUBNET 10.0.2.0/24                                 |
   |   route: 0.0.0.0/0 -> NAT GW       [NACL áp ở mức subnet]    |
   |   +----------------+      +-----------------+                |
   |   |  App server    |----->|  Database (RDS) | (SG ở mức ENI) |
   |   |  (SG)          |      |  (SG)           |                |
   |   +----------------+      +-----------------+                |
   |     không có public IP — chỉ ra Internet QUA NAT GW          |
   +-------------------------------------------------------------+
```

Điểm then chốt: **NACL lọc ở biên subnet (stateless)**, còn **Security Group lọc ngay tại ENI của từng instance (stateful)**. Tài nguyên nhạy cảm (DB) đặt trong private subnet, chỉ ra Internet một chiều qua NAT Gateway và không nhận kết nối đến từ Internet.

### 13.4.1. CIDR và phân bổ địa chỉ

VPC là mạng ảo cô lập L3. Bạn gán một khối CIDR (Classless Inter-Domain Routing).

Ký hiệu CIDR `10.0.0.0/16`:

```
10.0.0.0/16  => 10.0.0.0 - 10.0.255.255
  /16 = 32 - 16 = 16 bit host => 2^16 = 65536 địa chỉ
```

| Khái niệm | Bit | Ý nghĩa |
|---|---|---|
| Địa chỉ IPv4 | 32 bit | 4 octet |
| Prefix `/n` | n bit network | phần cố định |
| Host bits | 32 - n | số host |

AWS **chiếm 5 địa chỉ đầu/cuối mỗi subnet**: `.0` (network), `.1` (VPC router), `.2` (DNS Amazon-provided), `.3` (dự phòng tương lai), và `.255` (broadcast — dù VPC không broadcast, vẫn giữ chỗ). Nên subnet `/24` (256 địa chỉ) chỉ dùng được 251 host.

### 13.4.2. Subnet public vs private

Khác biệt **không nằm ở cấu hình subnet** mà ở **route table**:

- **Public subnet**: route table có đường `0.0.0.0/0 -> igw-xxxx` (Internet Gateway).
- **Private subnet**: route mặc định trỏ `0.0.0.0/0 -> nat-xxxx` (NAT Gateway) hoặc không có đường ra Internet.

Route table mẫu:

```
Destination      Target            (public subnet)
10.0.0.0/16      local
0.0.0.0/0        igw-0abc123

Destination      Target            (private subnet)
10.0.0.0/16      local
0.0.0.0/0        nat-0def456
```

### 13.4.3. IGW vs NAT Gateway

| Thành phần | Hướng | Chức năng | Lưu ý |
|---|---|---|---|
| Internet Gateway (IGW) | Hai chiều | Cho phép instance có public IP nhận/gửi Internet, thực hiện NAT 1:1 với Elastic IP | Không tính phí giờ |
| NAT Gateway | Một chiều (ra) | Instance private ra Internet (update, gọi API) nhưng Internet KHÔNG vào được | Tính phí theo giờ + theo GB; đặt trong public subnet |

**Vì sao** NAT GW phải nằm trong public subnet: bản thân NAT GW cần đường ra qua IGW; instance private trỏ route về NAT GW, NAT GW trỏ route về IGW.

### 13.4.4. VPC Flow Logs — định dạng bản ghi

Flow Logs ghi metadata luồng (không nội dung). Định dạng default (v2) gồm các trường theo thứ tự:

```
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
2 123456789012 eni-0abc 10.0.1.5 203.0.113.7 51000 443 6 20 4520 1655640000 1655640060 ACCEPT OK
```

| Trường | Ý nghĩa | Ví dụ |
|---|---|---|
| `version` | phiên bản format | `2` |
| `srcaddr`/`dstaddr` | IP nguồn/đích | `10.0.1.5` |
| `srcport`/`dstport` | cổng | `443` |
| `protocol` | số IANA (6=TCP,17=UDP,1=ICMP) | `6` |
| `action` | `ACCEPT`/`REJECT` (theo SG/NACL) | `ACCEPT` |
| `log-status` | `OK`/`NODATA`/`SKIPDATA` | `OK` |

**Lưu ý:** `REJECT` lặp lại tới nhiều cổng từ một IP = dấu hiệu port scan; dùng làm nguồn cho GuardDuty và phân tích đe dọa.

---

## 13.5. Security Group (stateful) vs Network ACL (stateless)

### 13.5.1. So sánh cơ chế

| Tiêu chí | Security Group | Network ACL (NACL) |
|---|---|---|
| Tầng áp dụng | ENI (network interface của instance) | Subnet |
| Stateful? | CÓ — trả lời tự động được phép | KHÔNG — phải mở cả chiều vào và ra |
| Rule | Chỉ Allow (không có Deny) | Allow VÀ Deny |
| Đánh giá | Tất cả rule cùng lúc (không thứ tự) | Theo THỨ TỰ số rule (thấp -> cao), dừng ở match đầu tiên |
| Mặc định | Deny inbound, Allow all outbound | "default NACL": Allow tất cả; NACL mới tạo: Deny tất cả |

### 13.5.2. Stateful nghĩa là gì (ở mức gói tin)

Khi instance gửi request ra `443` đến server bên ngoài:

```
Outbound: src 10.0.1.5:51000 -> dst 1.2.3.4:443   (SG outbound rule cho phép)
Inbound trả về: src 1.2.3.4:443 -> dst 10.0.1.5:51000
```

- Với **SG (stateful)**: AWS ghi nhớ "connection tracking", gói trả về tự động được phép — KHÔNG cần inbound rule cho port ephemeral 51000.
- Với **NACL (stateless)**: gói trả về về port ephemeral (1024-65535) phải có **inbound rule cho phép dải ephemeral**, nếu không bị chặn.

**Vì sao** phải mở ephemeral port range trên NACL: TCP client chọn port nguồn ngẫu nhiên trong dải ephemeral; phản hồi từ server đến đúng port đó. NACL không nhớ trạng thái nên phải khai báo tường minh.

### 13.5.3. NACL có thứ tự — ví dụ

```
Rule#   Type    Protocol  Port      Source           Allow/Deny
100     HTTP    TCP       80        0.0.0.0/0        ALLOW
130     SSH     TCP       22        0.0.0.0/0        DENY     <-- số 130 < 200
200     SSH     TCP       22        203.0.113.0/24   ALLOW
*       ALL     ALL       ALL       0.0.0.0/0        DENY
```

**Lưu ý:** NACL duyệt **từ số nhỏ tới lớn, dừng ở match đầu tiên**. Trong ví dụ trên, gói SSH từ `203.0.113.5` khớp rule 130 (DENY) TRƯỚC khi tới rule 200 (ALLOW) => bị chặn. Đây là lỗi sắp xếp số rule điển hình. Luôn để rule cụ thể (allow IP tin cậy) có số NHỎ hơn rule deny rộng.

### 13.5.4. Ví dụ thực tế tạo SG

```bash
aws ec2 create-security-group --group-name web-sg \
  --description "Web tier" --vpc-id vpc-0a1b2c3d

aws ec2 authorize-security-group-ingress \
  --group-id sg-0123456789 \
  --protocol tcp --port 443 --cidr 0.0.0.0/0

# Cho phép tier app gọi DB chỉ từ SG của app (tham chiếu SG, không dùng IP)
aws ec2 authorize-security-group-ingress \
  --group-id sg-db-999 \
  --protocol tcp --port 5432 --source-group sg-app-888
```

**Cảnh báo:** tham chiếu **SG-to-SG** thay vì CIDR là best practice — khi IP instance thay đổi, rule vẫn đúng; và không vô tình mở cho IP lạ. Tuyệt đối tránh `--cidr 0.0.0.0/0` cho port 22/3389/3306/5432.

---

## 13.6. Amazon S3 — lưu trữ đối tượng

### 13.6.1. Mô hình truy cập nhiều lớp

Truy cập S3 được quyết định bởi tổ hợp: Block Public Access (BPA) > IAM policy > Bucket policy > ACL. Một explicit Deny ở bất kỳ lớp nào thắng tất cả.

### 13.6.2. Block Public Access — 4 cờ

| Cờ | Tác dụng |
|---|---|
| `BlockPublicAcls` | Chặn PUT ACL công khai mới |
| `IgnorePublicAcls` | Bỏ qua ACL công khai hiện có |
| `BlockPublicPolicy` | Chặn đặt bucket policy công khai |
| `RestrictPublicBuckets` | Hạn chế truy cập qua policy công khai chỉ còn principal cùng account/service |

```bash
aws s3api put-public-access-block --bucket company-reports \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

Từ tháng 4/2023, AWS bật BPA mặc định cho bucket mới. **Vì sao** 4 cờ riêng: ACL và policy là hai cơ chế độc lập lịch sử; cần chặn cả hai nguồn "public".

### 13.6.3. Bucket policy JSON — ép mã hóa khi truyền và chặn non-TLS

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::company-reports",
        "arn:aws:s3:::company-reports/*"
      ],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "DenyUnEncryptedUploads",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::company-reports/*",
      "Condition": {
        "StringNotEquals": { "s3:x-amz-server-side-encryption": "aws:kms" }
      }
    }
  ]
}
```

Statement đầu chặn mọi request không qua HTTPS; statement hai từ chối upload không kèm header `x-amz-server-side-encryption: aws:kms`.

### 13.6.4. Mã hóa SSE — các loại

| Loại | Key quản lý bởi | Header request | Audit qua CloudTrail |
|---|---|---|---|
| SSE-S3 | AWS (AES-256, key của S3) | `x-amz-server-side-encryption: AES256` | Không thấy từng lần dùng key |
| SSE-KMS | AWS KMS (CMK của bạn) | `...: aws:kms` + `x-amz-server-side-encryption-aws-kms-key-id` | CÓ — mỗi Decrypt ghi CloudTrail |
| SSE-C | Khách hàng cung cấp key mỗi request | gửi key trong header | Bạn tự quản key |
| DSSE-KMS | Mã hóa hai lớp KMS | `aws:kms:dsse` | Cho yêu cầu tuân thủ cao |

Từ đầu 2023, S3 áp dụng SSE-S3 mặc định cho mọi object mới (cần kiểm chứng phiên bản chính xác theo region). **Vì sao** chọn SSE-KMS: kiểm soát được ai dùng key (qua KMS key policy) và **có dấu vết audit từng lần giải mã** — cực kỳ giá trị cho điều tra.

### 13.6.5. Versioning

Bật versioning giữ mọi phiên bản object; xóa chỉ đặt "delete marker". Chống ghi đè/xóa do mã độc (ransomware) và lỗi người dùng. Kết hợp với **MFA Delete** và **Object Lock (WORM)** cho bất biến.

```bash
aws s3api put-bucket-versioning --bucket company-reports \
  --versioning-configuration Status=Enabled
```

### 13.6.6. Mẫu sự cố rò rỉ điển hình

Kịch bản lặp lại nhiều lần trong thực tế: bucket chứa backup/PII được đặt ACL `public-read` hoặc bucket policy `Principal:"*"` mà không có điều kiện. Bất kỳ ai có URL `https://bucket.s3.amazonaws.com/key` đọc được dữ liệu.

Phát hiện bằng lệnh kiểm tra nhanh:

```bash
# Liệt kê bucket KHÔNG bật đủ Block Public Access
for b in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  echo "== $b =="
  aws s3api get-public-access-block --bucket "$b" \
    --query 'PublicAccessBlockConfiguration' 2>/dev/null \
    || echo "  !! KHONG CO public-access-block (rui ro)"  # khong co Block Public Access
done
```

---

## 13.7. AWS KMS — Key Management Service

### 13.7.1. CMK và phân loại key

| Loại key | Ai quản lý | Rotation (xoay key) tự động |
|---|---|---|
| AWS owned | AWS dùng nội bộ, bạn không thấy | Tự động |
| AWS managed (`aws/s3`...) | AWS thay mặt dịch vụ | Tự động hàng năm |
| Customer managed (CMK) | Bạn (key policy, rotation, alias) | Tùy chọn (mặc định 1 năm) |

### 13.7.2. Envelope Encryption — từng bước

KMS không mã hóa khối dữ liệu lớn trực tiếp (giới hạn ~4 KB cho `Encrypt`). Thay vào đó dùng **envelope encryption** (nguyên lý AES, AES-GCM và quản lý khóa xem [Chương 4](#sec-04)):

```
1. Client gọi KMS GenerateDataKey(KeyId=CMK, KeySpec=AES_256).
2. KMS trả về:
     - Plaintext data key (DEK) : 256-bit dùng mã hóa dữ liệu cục bộ
     - CiphertextBlob           : chính DEK đó nhưng đã được CMK mã hóa
3. Client dùng DEK plaintext (AES-256-GCM) mã hóa file lớn.
4. Client GHI: ciphertext_file + CiphertextBlob(DEK đã mã hóa).
5. Client XÓA DEK plaintext khỏi RAM.

Giải mã:
6. Client gọi KMS Decrypt(CiphertextBlob) -> nhận lại DEK plaintext.
7. Dùng DEK giải mã file.
```

Sơ đồ:

```
      [CMK trong KMS - không bao giờ rời HSM]
              |  mã hóa/giải mã
              v
   [DEK đã mã hóa: CiphertextBlob]  <-- lưu cạnh dữ liệu
              |  Decrypt qua KMS
              v
   [DEK plaintext]  --AES-256-GCM-->  [dữ liệu]
```

**Vì sao** thiết kế envelope: (1) giảm số lần gọi KMS (mã hóa dữ liệu cục bộ nhanh); (2) CMK gốc không bao giờ rời khỏi HSM của KMS; (3) thu hồi quyền Decrypt CMK lập tức vô hiệu mọi DEK.

Ví dụ thực tế:

```bash
# Tạo DEK
aws kms generate-data-key --key-id alias/app-cmk --key-spec AES_256 \
  --query '{plain:Plaintext, blob:CiphertextBlob}' --output json
# Plaintext (base64) dùng để mã hóa; CiphertextBlob lưu cùng ciphertext.
```

### 13.7.3. KMS Key Policy

Khác IAM: KMS **luôn cần key policy** (resource-based). Một key policy phổ biến trao quyền quản trị cho account root rồi ủy quyền tiếp qua IAM:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "EnableRootIAM",
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
    "Action": "kms:*",
    "Resource": "*"
  }]
}
```

**Lưu ý:** xóa toàn bộ statement trao root quyền có thể khiến key **không thể quản lý được nữa** (cần mở ticket AWS Support để khôi phục).

---

## 13.8. CloudTrail — nhật ký API

### 13.8.1. Là gì

Ghi lại mọi lệnh gọi API (management events) và tùy chọn data events (S3 object-level, Lambda invoke). Là nguồn dữ liệu điều tra số một trong AWS.

### 13.8.2. Cấu trúc một event JSON — từng trường

```json
{
  "eventVersion": "1.09",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROAEXAMPLE:audit-2026",
    "arn": "arn:aws:sts::123456789012:assumed-role/app-role/audit-2026",
    "accountId": "123456789012",
    "accessKeyId": "ASIA....EXAMPLE",
    "sessionContext": {
      "attributes": { "mfaAuthenticated": "false", "creationDate": "2026-06-19T14:00:00Z" }
    }
  },
  "eventTime": "2026-06-19T14:05:11Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "GetObject",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.7",
  "userAgent": "aws-cli/2.15.0",
  "requestParameters": { "bucketName": "company-reports", "key": "q1.pdf" },
  "responseElements": null,
  "readOnly": true,
  "eventType": "AwsApiCall",
  "recipientAccountId": "123456789012",
  "eventID": "a1b2c3d4-....",
  "managementEvent": false
}
```

| Trường | Ý nghĩa điều tra |
|---|---|
| `userIdentity.type` | `Root`, `IAMUser`, `AssumedRole`, `AWSService` — ai gọi |
| `userIdentity.accessKeyId` | `ASIA`=tạm thời, `AKIA`=lâu dài (xem 13.3.4) |
| `sessionContext.mfaAuthenticated` | `"false"` đáng nghi với hành động nhạy cảm |
| `eventSource` + `eventName` | dịch vụ + API cụ thể |
| `sourceIPAddress` | IP nguồn — đối chiếu IP lạ/quốc gia lạ |
| `errorCode` (nếu có) | `AccessDenied` lặp lại = dấu hiệu dò quyền |

**Lưu ý:** bật **log file integrity validation** (CloudTrail tạo digest ký số SHA-256) để phát hiện log bị giả mạo/xóa. Lưu log vào bucket riêng có Object Lock.

---

## 13.9. CloudWatch

CloudWatch = metrics + logs + alarms. Liên quan bảo mật:

- **CloudWatch Logs**: gom log ứng dụng/VPC Flow Logs.
- **Metric filter + Alarm**: phát hiện hành vi từ CloudTrail. Ví dụ tạo alarm khi có `ConsoleLogin` thất bại nhiều lần hoặc khi root đăng nhập.

```bash
aws logs put-metric-filter \
  --log-group-name CloudTrail/Logs \
  --filter-name RootLogin \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.eventName = "ConsoleLogin" }' \
  --metric-transformations metricName=RootLoginCount,metricNamespace=Security,metricValue=1
```

Filter pattern dùng cú pháp JSON path; `$.userIdentity.type` trỏ vào trường lồng. Sau đó gắn `put-metric-alarm` để gửi SNS cảnh báo.

---

## 13.10. GuardDuty

### 13.10.1. Là gì

Dịch vụ phát hiện mối đe dọa dựa trên ML + threat intel, phân tích **CloudTrail, VPC Flow Logs, DNS logs, EKS audit logs, S3 data events** — không cần cài agent.

### 13.10.2. Các họ finding (định dạng tên)

Tên finding theo cấu trúc `ThreatPurpose:ResourceType/ThreatFamilyName.DetectionMechanism!Artifact`:

| Finding ví dụ | Ý nghĩa |
|---|---|
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | Credential của EC2 role bị dùng từ ngoài AWS (dấu hiệu IMDS bị đánh cắp) |
| `Recon:IAMUser/MaliciousIPCaller` | API gọi từ IP độc hại đã biết |
| `CryptoCurrency:EC2/BitcoinTool.B!DNS` | EC2 truy vấn domain mining tiền số |
| `Backdoor:EC2/C&CActivity.B` | EC2 liên lạc C2 |
| `Exfiltration:S3/ObjectRead.Unusual` | Đọc S3 bất thường |
| `Policy:IAMUser/RootCredentialUsage` | Dùng credential root |

**Vì sao** `InstanceCredentialExfiltration.OutsideAWS` rất mạnh: nó tương quan vị trí — credential EC2 role *phải* được dùng từ trong AWS; nếu xuất hiện từ IP bên ngoài, gần như chắc chắn đã bị trích xuất qua SSRF/IMDS.

---

## 13.11. IMDS — Instance Metadata Service (v1 vs v2)

### 13.11.1. Là gì

IMDS phục vụ metadata tại địa chỉ link-local cố định **`169.254.169.254`**. Quan trọng nhất: nó cấp **credential tạm thời của IAM role gắn vào instance**.

```bash
# Lấy tên role
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Lấy credential
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role
```

Output credential:

```json
{
  "Code": "Success",
  "AccessKeyId": "ASIA....",
  "SecretAccessKey": "....",
  "Token": "....",
  "Expiration": "2026-06-19T20:00:00Z"
}
```

### 13.11.2. IMDSv1 (request/response đơn giản — và lỗ hổng SSRF)

IMDSv1: chỉ cần một HTTP GET tới `169.254.169.254`. KHÔNG cần token. Đây là gốc của vô số sự cố SSRF (cơ chế SSRF được trình bày ở [Chương 5 — An ninh ứng dụng Web](#sec-05)).

Kịch bản tấn công SSRF qua IMDSv1:

```
1. Ứng dụng web có tham số: https://app/fetch?url=<URL>  (server tự GET URL).
2. Kẻ tấn công gửi: ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role
3. Server (chạy trên EC2) GET hộ, trả về credential ASIA/Secret/Token.
4. Kẻ tấn công dùng credential từ máy của họ (ngoài AWS) -> GuardDuty
   InstanceCredentialExfiltration.OutsideAWS.
```

### 13.11.3. IMDSv2 — session token, từng bước

IMDSv2 yêu cầu quy trình hai bước **PUT lấy token rồi GET kèm token**:

```bash
# Bước 1: PUT lấy token (TTL tối đa 21600s = 6h)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Bước 2: GET kèm token trong header
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ \
  -H "X-aws-ec2-metadata-token: $TOKEN"
```

| Cơ chế bảo vệ IMDSv2 | Vì sao chặn được SSRF |
|---|---|
| Yêu cầu **PUT** lấy token | Đa số lỗ hổng SSRF chỉ cho GET, không gửi được PUT tùy ý có header |
| Yêu cầu **header tùy chỉnh** `X-aws-ec2-metadata-token` | SSRF cơ bản không thêm được header này |
| Mặc định **`X-Forwarded-For` => từ chối** | Chặn khi request đi qua proxy/WAF/reverse proxy (dấu hiệu SSRF/relay) |
| Giới hạn **PUT response hop limit = 1** | Token không "nhảy" qua container/route khác; gói có IP-TTL bị giảm sẽ bị từ chối |

Ép buộc IMDSv2 (chặn hẳn v1):

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-0123456789 \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --http-endpoint enabled
```

`--http-tokens required` = bắt buộc token (tắt v1). `--http-put-response-hop-limit 1` = gói phản hồi metadata chỉ đi được 1 hop (IP TTL), ngăn container trên instance hoặc reverse proxy chuyển tiếp metadata.

**Lưu ý:** chặn IMDS ở tầng mạng cũng nên kèm — ví dụ iptables drop ra `169.254.169.254` cho user của ứng dụng web không cần metadata.

---

## 13.12. AWS Organizations & SCP (Service Control Policy)

### 13.12.1. Là gì

Organizations quản lý nhiều account theo cây OU (Organizational Unit). SCP là **guardrail** áp ở cấp org/OU/account — đặt **trần quyền tối đa**, KHÔNG tự cấp quyền.

```
Root
 ├── OU: Security  (SCP: Deny tắt CloudTrail)
 ├── OU: Prod      (SCP: chỉ cho region us-east-1, eu-west-1)
 └── OU: Sandbox   (SCP: Deny dịch vụ đắt tiền)
```

### 13.12.2. SCP ví dụ — khóa region và chặn tắt audit

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyOutsideAllowedRegions",
      "Effect": "Deny",
      "NotAction": [ "iam:*", "sts:*", "organizations:*", "cloudfront:*", "route53:*" ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": { "aws:RequestedRegion": [ "us-east-1", "eu-west-1" ] }
      }
    },
    {
      "Sid": "ProtectCloudTrail",
      "Effect": "Deny",
      "Action": [ "cloudtrail:StopLogging", "cloudtrail:DeleteTrail" ],
      "Resource": "*"
    }
  ]
}
```

**Vì sao** `NotAction` chứa `iam`/`sts`: các dịch vụ này là global (region `us-east-1` ngầm); chặn theo region có thể khóa nhầm chúng. SCP áp cho cả **root user của member account** — đây là cách duy nhất hạn chế được root.

---

## 13.13. GCP — tương đương AWS

### 13.13.0. Bảng ánh xạ AWS ↔ GCP

Tra nhanh trước khi vào chi tiết: học một nền tảng rồi suy ra nền tảng còn lại.

| Khái niệm | AWS | GCP |
|---|---|---|
| Danh tính người | IAM User | Google account / member |
| Danh tính workload | IAM Role | Service Account |
| Token tạm thời | STS | SA token qua metadata / STS API |
| Mạng ảo | VPC (theo region) | VPC (global), subnet theo region |
| Tường lửa instance | Security Group (stateful) | Firewall rule (stateful, có priority) |
| ACL stateless | NACL | (không có tương đương trực tiếp; dùng firewall priority) |
| Lưu trữ đối tượng | S3 | Cloud Storage |
| Quản lý khóa | KMS | Cloud KMS |
| Audit API | CloudTrail | Cloud Audit Logs |
| Metrics/log | CloudWatch | Cloud Monitoring / Logging |
| Phát hiện mối đe dọa | GuardDuty | SCC / Event Threat Detection |
| Guardrail tổ chức | SCP | Organization Policy |
| Quản lý bí mật | Secrets Manager | Secret Manager |
| Metadata service | IMDS 169.254.169.254 | metadata.google.internal (169.254.169.254) |

### 13.13.1. GCP IAM

GCP IAM gắn quyền theo công thức **binding**: ai (member) + vai trò (role) + tài nguyên (qua hệ phân cấp).

```
who   = member  (user:, serviceAccount:, group:, domain:, allUsers, allAuthenticatedUsers)
what  = role    (roles/storage.objectViewer ...)
where = resource (Organization > Folder > Project > Resource)  -- quyền KẾ THỪA xuống dưới
```

Phân loại role:

| Loại role | Mô tả | Ví dụ | Lưu ý |
|---|---|---|---|
| Primitive (basic) | Owner/Editor/Viewer áp toàn project | `roles/owner` | Quá rộng — tránh dùng |
| Predefined | Do Google định nghĩa, hạt mịn theo dịch vụ | `roles/storage.objectAdmin` | Khuyến nghị |
| Custom | Bạn tự gộp permission | `projects/p/roles/myAuditor` | Least privilege thực sự |

IAM Policy binding ví dụ (định dạng JSON khi `getIamPolicy`):

```json
{
  "version": 3,
  "bindings": [
    {
      "role": "roles/storage.objectViewer",
      "members": [ "user:alice@example.com", "group:auditors@example.com" ],
      "condition": {
        "title": "only-prod-bucket",
        "expression": "resource.name.startsWith('projects/_/buckets/prod-')"
      }
    }
  ],
  "etag": "BwXyz..."
}
```

| Trường | Ý nghĩa | Ví dụ |
|---|---|---|
| `version` | Phiên bản schema policy (3 để dùng condition) | `3` |
| `bindings[].role` | Vai trò gán | `roles/storage.objectViewer` |
| `bindings[].members[]` | Danh sách thành viên (có prefix loại) | `user:`, `serviceAccount:` |
| `condition.expression` | Biểu thức CEL (Common Expression Language) | điều kiện theo tài nguyên/thời gian |
| `etag` | Khóa tránh ghi đè đồng thời (optimistic locking) | base64 |

**Cảnh báo:** `allUsers` (bất kỳ ai trên Internet) và `allAuthenticatedUsers` (bất kỳ tài khoản Google nào) là tương đương "public" — nguồn rò rỉ Cloud Storage hàng đầu.

### 13.13.2. Service Account & Service Account Key

Service Account (SA) là danh tính cho workload. Có **hai loại bí mật**:

- **Google-managed key**: Google tự xoay, dùng khi workload chạy trên GCP (Metadata server cấp token tự động — tương đương IAM role của AWS).
- **User-managed key (JSON)**: file `.json` tải về — bí mật lâu dài, là **rủi ro lớn nhất** nếu lọt vào git.

Cấu trúc file SA key JSON:

```json
{
  "type": "service_account",
  "project_id": "my-project",
  "private_key_id": "a1b2c3...",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
  "client_email": "app-sa@my-project.iam.gserviceaccount.com",
  "client_id": "10293847566...",
  "token_uri": "https://oauth2.googleapis.com/token"
}
```

| Trường | Ý nghĩa |
|---|---|
| `type` | luôn `service_account` — dấu hiệu nhận diện khi quét secret |
| `private_key` | RSA private key PEM — bí mật cốt lõi |
| `client_email` | định danh SA (kiểm tra quyền của email này) |
| `token_uri` | endpoint đổi JWT lấy access token OAuth2 |

**Lưu ý:** nên **vô hiệu hóa tạo user-managed key** qua Org Policy `iam.disableServiceAccountKeyCreation` và dùng Workload Identity Federation thay vì key file.

### 13.13.3. GCP VPC

Khác AWS điểm then chốt: **VPC của GCP là global**, subnet thuộc region (AWS: VPC theo region, subnet theo AZ). Firewall rules áp ở mức VPC, theo network tag/SA, có priority (0-65535, nhỏ = ưu tiên cao), stateful.

```bash
gcloud compute firewall-rules create allow-https \
  --network=prod-vpc --direction=INGRESS --action=ALLOW \
  --rules=tcp:443 --source-ranges=0.0.0.0/0 \
  --target-tags=web --priority=1000
```

### 13.13.4. Cloud Storage (tương đương S3)

- Quyền: IAM (uniform bucket-level access — khuyến nghị) hoặc ACL (fine-grained — nên tắt).
- Bật **Uniform bucket-level access** để bỏ ACL, tránh nhầm lẫn ACL public.
- Mã hóa mặc định Google-managed; chọn CMEK (Customer-Managed Encryption Key qua Cloud KMS) hoặc CSEK.

```bash
gsutil uniformbucketlevelaccess set on gs://prod-data
# Phát hiện public:
gsutil iam get gs://prod-data | grep -E "allUsers|allAuthenticatedUsers"
```

### 13.13.5. Cloud Logging (tương đương CloudTrail/CloudWatch Logs)

GCP ghi **Audit Logs** chia loại:

| Loại Audit Log | Nội dung | Mặc định |
|---|---|---|
| Admin Activity | thay đổi cấu hình/IAM | Luôn bật, không tắt được |
| Data Access | đọc/ghi dữ liệu | Mặc định TẮT (trừ BigQuery) — phải bật |
| System Event | hành động hệ thống của Google | Luôn bật |
| Policy Denied | bị từ chối do policy | Tự động |

Một entry Cloud Audit Log (định dạng `protoPayload` kiểu AuditLog):

```json
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": { "principalEmail": "alice@example.com" },
    "requestMetadata": { "callerIp": "203.0.113.7" },
    "serviceName": "storage.googleapis.com",
    "methodName": "storage.objects.get",
    "resourceName": "projects/_/buckets/prod-data/objects/q1.pdf"
  },
  "severity": "INFO",
  "timestamp": "2026-06-19T14:05:11Z",
  "logName": "projects/my-project/logs/cloudaudit.googleapis.com%2Fdata_access"
}
```

**Lưu ý:** Data Access log TẮT mặc định — nếu không bật, bạn **không có dấu vết ai đọc object nào** (khác AWS cần bật S3 data events). Đây là khoảng mù điều tra phổ biến.

### 13.13.6. Security Command Center (tương đương GuardDuty + Security Hub + Config)

SCC là nền tảng quản lý tư thế bảo mật của GCP: phát hiện misconfig, lỗ hổng, mối đe dọa.

| Module | Vai trò |
|---|---|
| Security Health Analytics | Quét misconfig (bucket public, SA key, firewall mở) — kiểu CSPM |
| Event Threat Detection | Phân tích log phát hiện hành vi (brute force SSH, IAM bất thường) |
| Container Threat Detection | Phát hiện runtime trong GKE |
| Web Security Scanner | Quét app web |

Finding ví dụ: `PUBLIC_BUCKET_ACL`, `SERVICE_ACCOUNT_KEY_NOT_ROTATED`, `OPEN_FIREWALL`, `MFA_NOT_ENFORCED`.

---

## 13.14. OCI — Oracle Cloud Infrastructure

### 13.14.1. Là gì và vì sao mình phải học nó

Mình vận hành thực tế hai đám mây: prod chạy trên AWS, còn dev (và một phần prod) chạy trên OCI (Oracle Cloud Infrastructure). Lý do phải nắm OCI: nó **không phải bản sao đổi tên của AWS** — nhiều khái niệm nền tảng được thiết kế khác hẳn, và người quen tư duy AWS rất dễ hiểu nhầm rồi cấu hình sai. Mục này ghi lại đúng những chỗ mình từng bỡ ngỡ, và đối chiếu 1-1 với AWS để chuyển tư duy cho nhanh.

Điểm khác biệt lớn nhất phải nắm trước: **AWS cô lập bằng *account* (tài khoản), còn OCI cô lập bằng *compartment* (ngăn) bên trong một *tenancy*.** Hiểu sai chỗ này là hiểu sai toàn bộ mô hình phân quyền của OCI.

### 13.14.2. Tenancy và Compartment — cây phân quyền logic

- **Tenancy**: gốc của toàn bộ tài nguyên OCI của một tổ chức — tương đương "AWS Organizations + account gốc" gộp làm một. Mỗi tài nguyên OCI có một OCID (Oracle Cloud ID) dạng `ocid1.<type>.<realm>..<hash>`, luôn thuộc về một tenancy.
- **Compartment**: một **cây thư mục logic** để nhóm tài nguyên và áp quyền. Đây là chỗ khác AWS nhiều nhất. Trên AWS, muốn tách môi trường/nhóm người ta thường tách *account* rồi ghép bằng Organizations; trên OCI, một tenancy duy nhất chứa nhiều compartment lồng nhau (`dev`, `prod`, `prod/db`, `shared-network`...), và quyền được cấp *theo compartment*.

```
Tenancy (gốc)
 ├── Compartment: network-shared      (VCN, subnet dùng chung)
 ├── Compartment: dev                 (tài nguyên môi trường dev)
 │     └── Compartment: dev/app
 └── Compartment: prod                (tài nguyên prod chạy trên OCI)
       ├── Compartment: prod/app
       └── Compartment: prod/data     (bucket, DB — siết chặt nhất)
```

**Vì sao compartment tiện:** phân quyền, quota và cả bảng theo dõi chi phí đều gắn theo compartment; xóa compartment là dọn sạch mọi thứ bên trong. Nhưng cũng chính vì "một tenancy nhiều compartment", ranh giới cô lập **yếu hơn tách account của AWS** — nếu viết policy lỏng ở cấp tenancy, quyền có thể rò xuống mọi compartment. Đây là lý do phần prod chạy trên OCI phải đặt trong compartment riêng và siết policy đúng phạm vi (xem 13.14.9).

### 13.14.3. IAM policy dạng câu lệnh (khác hẳn JSON của AWS)

Chỗ này làm mình bỡ ngỡ nhất khi từ AWS sang. IAM policy của OCI **không phải tài liệu JSON** với `Effect/Action/Resource` như AWS — nó là **những câu tiếng Anh gần như đọc được thành lời**:

```
Allow group <tên-group> to <động-từ> <loại-tài-nguyên> in compartment <tên> [where <điều-kiện>]
```

Ví dụ thật:

```
Allow group Developers to manage object-family in compartment dev
Allow group DBAdmins   to manage database-family in compartment prod:data
Allow group Auditors   to read all-resources in tenancy
Allow group AppOps     to use secret-family in compartment prod where request.region = 'ap-singapore-1'
```

Bốn **động từ quyền** xếp theo mức tăng dần (đây là điểm cần nhớ, khác cách liệt kê từng action của AWS):

| Động từ | Bao gồm | Tương đương AWS (khái niệm) |
|---|---|---|
| `inspect` | liệt kê tài nguyên (metadata, không nội dung nhạy cảm) | `List*` |
| `read` | inspect + đọc nội dung/chi tiết | `List* + Get*/Describe*` |
| `use` | read + thao tác/cập nhật hiện có (không tạo/xóa) | `Get* + Update*/thao tác chạy` |
| `manage` | use + tạo và xóa | quyền đầy đủ trên loại tài nguyên |

`<loại-tài-nguyên>` là các "family" gộp sẵn: `object-family` (Object Storage), `instance-family` (Compute), `virtual-network-family` (VCN), `secret-family`, `vaults`, `keys`... Mệnh đề `where` gắn điều kiện (region, thời gian, `target.compartment.name`, tag...) — tương đương `Condition` của AWS nhưng viết chung trong câu.

**Vì sao mình thích cú pháp này:** đọc policy OCI gần như đọc chính sách bằng tiếng Anh, ít bị "JSON đúng cú pháp nhưng sai ý" như AWS. **Chỗ dễ sai:** không có `Deny` tường minh — OCI IAM chỉ có Allow (mặc định deny ngầm). Muốn "cấm" thì phải *không cấp*, hoặc siết bằng phạm vi compartment, hoặc dùng cơ chế khác (Network Sources, tag-based). Thói quen viết `Deny` guardrail như SCP của AWS **không áp thẳng được** — cần nghĩ lại theo hướng thu hẹp phạm vi cấp quyền.

### 13.14.4. Dynamic Group + Instance/Resource Principal (danh tính workload, không cắm key tĩnh)

Đây là phần mình đánh giá cao nhất của OCI, và nó tương đương thẳng với "IAM role gắn vào EC2" của AWS: cho phép compute/function **tự lấy credential tạm để gọi OCI API mà không cắm key tĩnh vào code**.

Cơ chế hai bước:

1. **Dynamic Group**: nhóm *các tài nguyên* (không phải người dùng) theo *quy tắc khớp* — ví dụ mọi instance trong một compartment, hoặc function cụ thể.

   ```
   # Matching rule của một dynamic group
   ALL {instance.compartment.id = 'ocid1.compartment.oc1..aaaa....dev'}
   ```

2. **Policy cấp quyền cho dynamic group đó** (viết y như policy thường, chủ thể là `dynamic-group`):

   ```
   Allow dynamic-group DevInstances to read secret-family in compartment dev
   Allow dynamic-group DevInstances to use keys        in compartment dev
   ```

Sau đó code chạy trên instance dùng **Instance Principal** để tự xác thực (SDK tự lấy chứng chỉ tạm từ metadata endpoint), hoàn toàn không có key file:

```python
import oci
signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
secrets = oci.secrets.SecretsClient(config={}, signer=signer)
# gọi API với danh tính máy — credential tạm, tự xoay, không nằm trên đĩa
```

- **Instance Principal**: cho VM/compute.
- **Resource Principal**: cho serverless (OCI Functions) và một số dịch vụ managed — tương đương execution role của Lambda.

**Vì sao quan trọng:** giống AWS, mấu chốt là **"danh tính máy, không phải key file"**. Kể cả "secret để lấy secret" cũng không nằm trên đĩa: app dùng Instance Principal tự xác thực rồi mới fetch bí mật thật từ Vault lúc khởi động. Đây là cách đúng để service ở môi trường dev OCI truy cập Vault mà không hardcode credential.

### 13.14.5. OCI Vault — KMS + Secrets gộp một chỗ

OCI Vault gộp hai vai trò mà AWS tách thành **KMS** (khóa) và **Secrets Manager** (bí mật):

- **Keys (khóa mã hóa)**: master key bảo vệ trong HSM. Hai loại vault: *Default* (dùng chung phân vùng HSM với khách khác — rẻ, đủ cho hầu hết nhu cầu) và *Virtual Private Vault* (được cấp phân vùng HSM riêng, mức cô lập cao hơn, dành cho yêu cầu tuân thủ ngặt — cần kiểm chứng giá và giới hạn theo thời điểm). Dùng cho encryption at-rest của Block Volume, Object Storage, DB. Hỗ trợ rotation và envelope encryption y hệt nguyên lý KMS (mục 13.7.2).
- **Secrets (bí mật)**: DB password, API key... lưu mã hóa bằng chính key trong Vault, quản theo *version* bất biến.

```bash
# Đọc một secret (bundle) — nội dung trả về ở dạng base64
oci secrets secret-bundle get-secret-bundle-by-name \
  --secret-name db-password --vault-id ocid1.vault.oc1..aaaa
```

Kiến trúc bí mật thực tế của mình: **prod dùng AWS Secrets Manager, phần chạy trên OCI dùng OCI Vault** — cùng một nguyên tắc: app không giữ key tĩnh để gọi secret store, nó dùng IAM role (AWS) / Instance Principal (OCI) tự xác thực rồi fetch bí mật lúc runtime.

### 13.14.6. VCN — Security List (mức subnet) vs NSG (mức VNIC)

VCN (Virtual Cloud Network) là mạng ảo cô lập của OCI, tương đương VPC. Nhưng cơ chế tường lửa của OCI có **hai lớp cùng tồn tại**, và ánh xạ sang AWS không hoàn toàn 1-1 nên rất dễ nhầm:

| Tiêu chí | Security List (OCI) | Network Security Group / NSG (OCI) |
|---|---|---|
| Gắn ở đâu | **Subnet** (áp cho MỌI VNIC trong subnet) | **VNIC** của từng tài nguyên (nhóm theo chức năng) |
| Gần với AWS nào | gần **NACL** (mức subnet) nhưng **stateful mặc định** | gần **Security Group** (mức interface) |
| Stateful? | Từng rule chọn được: **stateful hoặc stateless** | Stateful mặc định (chọn stateless được) |
| Tham chiếu nguồn | CIDR, hoặc Service (cho Service Gateway) | CIDR **hoặc chính NSG khác** (như SG-to-SG của AWS) |

Điểm dễ sai nhất khi từ AWS sang: trên OCI, một gói tin phải **qua CẢ Security List của subnet LẪN NSG của VNIC** — cả hai đều phải cho phép thì gói mới đi được (giao AND). Người quen AWS hay chỉ chỉnh SG (nghĩ như Security Group) mà quên Security List ở subnet vẫn đang chặn, hoặc ngược lại.

Khác AWS nữa: Security List **mặc định stateful** (không phải stateless như NACL), nên thường không phải mở tay dải ephemeral port cho gói trả về — trừ khi cố ý đặt rule stateless. Khuyến nghị thực tế: ưu tiên dùng **NSG** để phân quyền mạng theo chức năng (tham chiếu NSG-to-NSG, giống best practice SG-to-SG), giữ Security List ở mức tối giản/mặc định.

### 13.14.7. Object Storage — bucket private mặc định, PAR thay cho public

Object Storage là kho đối tượng của OCI (tương đương S3). Có một điểm mình coi là **điểm cộng thiết kế** so với lịch sử S3:

- **Bucket mặc định là private.** Muốn public phải **chủ động** đổi visibility sang Public. Khác S3 thời kỳ đầu (nơi cấu hình lỏng + ACL public-read là nguồn rò rỉ kinh điển), rủi ro "vô tình public" của OCI thấp hơn theo mặc định — nhưng *vẫn phải kiểm*, vì đổi nhầm sang public vẫn xảy ra.
- **Pre-Authenticated Request (PAR)** thay cho việc mở public: tạo một URL có **thời hạn hết hạn (expiry)** và phạm vi (một object hoặc cả bucket, read/write) — tương đương pre-signed URL của S3. Cần chia sẻ file thì phát PAR có hạn, **không** để bucket public.
- Mã hóa at-rest bật mặc định (Oracle-managed key); dữ liệu nhạy cảm nên chuyển sang **customer-managed key trong OCI Vault** để kiểm soát rotation + audit ai dùng key.

```bash
# Tạo PAR đọc một object, hết hạn sau 24h — thay cho việc để bucket public
oci os preauth-request create --namespace <ns> --bucket-name reports \
  --name share-q1 --access-type ObjectRead \
  --object-name q1.pdf --time-expires 2026-08-15T00:00:00Z
```

**Cloud Guard** (mục 13.14.8) tự gắn cờ bucket public — nên bật sẵn như một lớp phát hiện.

### 13.14.8. Cloud Guard — CSPM của OCI

Cloud Guard là dịch vụ quản lý tư thế bảo mật (CSPM) của OCI, tương đương GuardDuty + Security Hub + Config gộp lại (hoặc SCC của GCP):

- **Detector** quét cấu hình/hành vi rủi ro sinh ra **Problem**: bucket public, security rule mở `0.0.0.0/0` cổng quản trị, IAM policy quá rộng, instance thiếu bản vá, key/secret sắp hết hạn...
- **Responder** cho phép xử lý tự động hoặc bán tự động (ví dụ tự đóng bucket public).
- Đối chiếu benchmark (CIS OCI Foundations).

Cloud Guard đóng vai trò cho môi trường OCI đúng như AWS Config + GuardDuty cho môi trường AWS: phát hiện drift cấu hình, bucket public, rule mạng nới rộng, hành vi bất thường — và đẩy cảnh báo về kênh vận hành thay vì để một người rà tay hàng tháng.

### 13.14.9. Metadata endpoint OCI — IMDS v2 yêu cầu header `Authorization: Bearer Oracle`

OCI cũng có metadata service tại đúng địa chỉ link-local **`169.254.169.254`** như AWS/GCP, và Instance Principal lấy chứng chỉ tạm qua đây — nên **cùng bề mặt tấn công SSRF** như IMDS của AWS (cơ chế SSRF: [Chương 5](#sec-05)).

Điểm khác biệt phòng thủ đáng chú ý — cách chống SSRF của mỗi bên:

| | AWS IMDSv2 | OCI IMDS v2 |
|---|---|---|
| Đường dẫn | `/latest/meta-data/...` | `/opc/v2/...` |
| Cơ chế bảo vệ | **PUT** lấy token trước, rồi GET kèm header token | GET kèm **header cố định** `Authorization: Bearer Oracle` |
| Vì sao chặn SSRF ngây thơ | SSRF cơ bản chỉ làm được GET, không PUT được token | SSRF cơ bản không tự thêm được header `Authorization` |

```bash
# OCI IMDS v2 — thiếu header sẽ bị từ chối
curl -H "Authorization: Bearer Oracle" http://169.254.169.254/opc/v2/instance/
curl -H "Authorization: Bearer Oracle" http://169.254.169.254/opc/v2/identity/cert.pem
```

**Lưu ý quan trọng:** header `Authorization: Bearer Oracle` là **hằng số cố định**, không phải bí mật — nó chỉ nâng rào cho SSRF *ngây thơ* (loại chỉ chèn được URL, không thêm được header). Một SSRF cho phép điều khiển header vẫn vượt qua được. Vì vậy đừng coi metadata v2 (dù AWS hay OCI) là biện pháp đủ: vẫn phải áp đủ bộ SSRF defense ở tầng ứng dụng (allowlist domain, chặn IP private/link-local `169.254.0.0/16`, validate IP sau khi resolve DNS chống rebinding, tắt/validate redirect). OCI v1 (`/opc/v1/`) không yêu cầu header — nên ép dùng v2 giống như ép IMDSv2 trên AWS.

### 13.14.10. Bảng ánh xạ AWS ↔ OCI ↔ GCP

Tra nhanh khi nhảy giữa ba nền tảng — học một, suy ra hai cái còn lại:

| Khái niệm | AWS | OCI | GCP |
|---|---|---|---|
| Ranh giới cô lập | Account (+ Organizations) | **Compartment** (trong 1 tenancy) | Project (+ Folder/Org) |
| Cú pháp IAM policy | JSON (`Effect/Action/Resource`) | **Câu lệnh** (`Allow group … to … in compartment …`) | JSON binding (member+role) |
| Danh tính workload | IAM Role gắn EC2 | **Instance/Resource Principal** (+ Dynamic Group) | Service Account (+ Workload Identity) |
| Guardrail tổ chức | SCP (có Deny) | *(không có Deny; siết bằng phạm vi compartment / policy)* | Organization Policy |
| Mạng ảo | VPC | **VCN** | VPC (global) |
| Tường lửa mức interface | Security Group | **NSG** | Firewall rule (theo tag/SA) |
| Firewall mức subnet | NACL (stateless) | **Security List** (stateful mặc định) | *(không có; dùng priority)* |
| Lưu trữ đối tượng | S3 | **Object Storage** | Cloud Storage |
| Bucket private mặc định | BPA (bật mặc định từ 4/2023) | **Mặc định private sẵn** | Uniform bucket-level access |
| URL chia sẻ có hạn | Pre-signed URL | **Pre-Authenticated Request (PAR)** | Signed URL |
| Quản lý khóa | KMS | **Vault (Keys)** | Cloud KMS |
| Quản lý bí mật | Secrets Manager | **Vault (Secrets)** | Secret Manager |
| Audit API | CloudTrail | **Audit** (bật mặc định) | Cloud Audit Logs |
| CSPM / phát hiện đe dọa | GuardDuty + Security Hub + Config | **Cloud Guard** | Security Command Center |
| Metadata endpoint | `169.254.169.254` `/latest/` (IMDSv2: PUT token) | `169.254.169.254` `/opc/v2/` (header `Bearer Oracle`) | `metadata.google.internal` |

### 13.14.11. Nguyên tắc vận hành đa đám mây (kinh nghiệm thực tế)

Vận hành song song AWS (prod) + OCI (dev và một phần prod), mình rút ra mấy nguyên tắc mà lý thuyết ít nói thẳng:

- **Ranh giới đúng là prod vs non-prod, KHÔNG phải AWS vs OCI.** Việc prod nằm ở AWS còn dev ở OCI chỉ là *tình cờ có lợi* (tách cả nhà cung cấp lẫn credential nên blast radius nhỏ), nhưng đừng biến "nhà cung cấp" thành tiêu chí phân loại bảo mật.
- **Phần prod chạy trên đám mây "dev" phải áp CÙNG chuẩn siết như prod chính.** Đây là bẫy nguy hiểm nhất: một compartment prod đặt chung tenancy với dev rất dễ "thừa hưởng" thói quen cấu hình lỏng của dev (rule mạng rộng, bucket dễ dãi, policy tenancy-wide). Prod-OCI phải: least privilege theo compartment, không bucket public, bí mật trong Vault, bật logging/Cloud Guard — y như prod-AWS.
- **Tách credential / network / quyền giữa môi trường.** Credential dev lộ ra ngoài không được mở nổi bất cứ thứ gì ở prod. Kết nối giữa hai đám mây (nếu có, ví dụ VPN AWS↔OCI) chỉ mở đúng cổng thật sự cần.
- **Dữ liệu thật không nằm ở dev.** Môi trường dev cấu hình lỏng hơn là chuyện bình thường — nhưng chỉ chấp nhận được khi dev *không chạm dữ liệu thật*. Rủi ro lớn nhất của mô hình "dev trên OCI" là một máy dev cấu hình lỏng lại vô tình có dữ liệu production.
- **Chuẩn hóa bằng IaC để quản hai bộ IAM/tooling.** Cái giá của đa đám mây là phải quản hai hệ IAM, hai bộ công cụ; bù lại bằng Terraform/IaC + policy-as-code (Checkov/Trivy quét cả cấu hình AWS lẫn OCI) để không phải nhớ hai lối cấu hình bằng tay.

---

## 13.15. Tấn công đám mây và cách phát hiện

### 13.15.1. Misconfiguration

Nguyên nhân hàng đầu. Phát hiện bằng CSPM (mục 13.16). Các dạng: bucket public, SG mở `0.0.0.0/0` port quản trị (22/3389/database), CloudTrail không bật, mã hóa tắt, IMDSv1 còn bật, IAM policy `"Action":"*","Resource":"*"`.

### 13.15.2. Credential leak — key trong git

AWS access key có dạng nhận diện rõ:

```
AKIA[0-9A-Z]{16}        <- Access Key ID (20 ký tự, prefix AKIA)
40-ký-tự base64 secret   <- Secret Access Key
```

Quét git bằng các công cụ thật:

```bash
# trufflehog quét toàn lịch sử repo và xác thực key còn sống
trufflehog git file://./myrepo --only-verified

# gitleaks
gitleaks detect --source . --report-format json --report-path leaks.json
```

Output gitleaks mẫu:

```json
{
  "Description": "AWS Access Key",
  "Secret": "AKIAIOSFODNN7EXAMPLE",
  "File": "config/old_settings.py",
  "Commit": "9f3c1a...",
  "Author": "dev@example.com",
  "RuleID": "aws-access-token"
}
```

**Vì sao** quét cả lịch sử commit: xóa key trong commit mới nhưng vẫn còn trong lịch sử git => kẻ tấn công `git log -p` lấy được. Phải vừa **revoke key (vô hiệu hóa ngay)** vừa làm sạch lịch sử (hoặc coi như đã lộ vĩnh viễn).

GitHub Secret Scanning + push protection chặn ngay khi push; AWS có cơ chế tự gắn policy `AWSCompromisedKeyQuarantine` khi phát hiện key public.

### 13.15.3. Privilege Escalation qua `iam:PassRole`

Đây là một trong những đường leo thang quyền nguy hiểm và phổ biến nhất.

**Cơ chế:** `iam:PassRole` cho phép một principal "trao" một role cho một dịch vụ (EC2, Lambda...). Nếu kẻ tấn công có:
- `iam:PassRole` cho một role quyền cao (vd `AdminRole`), VÀ
- quyền tạo tài nguyên gắn role đó (vd `ec2:RunInstances` hoặc `lambda:CreateFunction`),

thì họ leo thang lên Admin dù bản thân tài khoản của họ không phải Admin.

Bước khai thác cụ thể (qua Lambda):

```bash
# 1. Tạo Lambda chạy dưới AdminRole (cần iam:PassRole + lambda:CreateFunction)
aws lambda create-function --function-name pwn \
  --runtime python3.12 --handler index.handler \
  --role arn:aws:iam::123456789012:role/AdminRole \
  --zip-file fileb://payload.zip

# 2. Lambda code gọi AWS API với quyền AdminRole, vd tạo user admin mới
aws lambda invoke --function-name pwn out.json
```

Hoặc qua EC2 + IMDS:

```bash
# Khởi tạo EC2 gắn AdminRole, rồi đọc credential từ IMDS bên trong
aws ec2 run-instances --image-id ami-xxx --instance-type t3.micro \
  --iam-instance-profile Name=AdminInstanceProfile
# Sau đó SSH/SSM vào, curl IMDS lấy credential AdminRole.
```

**Phòng thủ:**
- Hạn chế `iam:PassRole` chỉ tới role cụ thể qua `Resource` (không để `"Resource":"*"`).
- Dùng condition `iam:PassedToService` để giới hạn role chỉ trao cho dịch vụ đúng.

```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::123456789012:role/app-limited-role",
  "Condition": { "StringEquals": { "iam:PassedToService": "lambda.amazonaws.com" } }
}
```

**Phát hiện:** trong CloudTrail tìm `RunInstances`/`CreateFunction` có `requestParameters` chứa role ARN quyền cao, được gọi bởi principal không phải admin. Công cụ Pacu (framework khai thác AWS) có module liệt kê đường leo thang:

```bash
pacu
> run iam__enum_permissions
> run iam__privesc_scan
```

### 13.15.4. Exposed bucket — phát hiện và khai thác

```bash
# Truy cập ẩn danh thử liệt kê
aws s3 ls s3://target-bucket --no-sign-request
aws s3 cp s3://target-bucket/secret.txt . --no-sign-request
```

`--no-sign-request` = không gửi credential => kiểm tra liệu bucket có cho phép truy cập ẩn danh (public). Phát hiện phía phòng thủ: bật BPA toàn tài khoản, Macie quét PII, Config rule `s3-bucket-public-read-prohibited`.

---

## 13.16. CSPM — Cloud Security Posture Management

### 13.16.1. Là gì

CSPM tự động quét cấu hình cloud so với benchmark (CIS, PCI) và phát hiện sai lệch liên tục. Native: AWS Security Hub + Config, GCP SCC. Open source: **Prowler**, **ScoutSuite**.

### 13.16.2. Prowler — ví dụ thực tế

```bash
# Quét toàn bộ checks theo CIS benchmark, xuất HTML + JSON
prowler aws --compliance cis_2.0_aws --output-formats html json-ocsf
```

Output mẫu (rút gọn):

```
FAIL  s3_bucket_public_access  company-reports  Bucket allows public read
FAIL  iam_root_mfa_enabled     account 1234     Root account MFA not enabled
PASS  cloudtrail_multi_region  account 1234     Multi-region trail enabled
```

### 13.16.3. ScoutSuite

```bash
scout aws --report-dir ./scout-report
# Mở ./scout-report/scoutsuite-results/...html xem dashboard rủi ro theo dịch vụ
```

### 13.16.4. AWS Config rule (native CSPM)

```bash
# Bật managed rule kiểm tra bucket không được public
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-no-public-read",
  "Source": { "Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED" }
}'
```

Config liên tục đánh giá tài nguyên khi thay đổi và gắn cờ NON_COMPLIANT, có thể tự động remediation qua SSM Automation.

---

## 13.17. Secret Manager

### 13.17.1. AWS Secrets Manager

Lưu bí mật (DB password, API key) mã hóa bằng KMS, hỗ trợ **rotation (xoay key) tự động** qua Lambda rotation function.

```bash
aws secretsmanager create-secret --name prod/db/password \
  --secret-string '{"username":"app","password":"S3cr3t!"}' \
  --kms-key-id alias/app-cmk

aws secretsmanager get-secret-value --secret-id prod/db/password \
  --query SecretString --output text
```

So với Parameter Store: Secrets Manager có rotation tích hợp + tính phí/bí mật; SSM Parameter Store (SecureString) rẻ hơn, không tự rotate.

### 13.17.2. GCP Secret Manager

Phiên bản (version) bất biến; truy cập kiểm soát qua IAM `roles/secretmanager.secretAccessor`.

```bash
echo -n "S3cr3t!" | gcloud secrets create db-pass --data-file=-
gcloud secrets versions access latest --secret=db-pass
```

**Cảnh báo** (bảo mật chung): (1) không bao giờ truyền secret qua biến môi trường hiện trong log/`ps`; ưu tiên fetch lúc runtime; (2) cấp quyền đọc secret theo least privilege và bật audit log mỗi lần access; (3) bật rotation định kỳ.

---

## 13.18. Tổng kết các nguyên tắc phòng thủ cốt lõi

| Nguyên tắc | Áp dụng cụ thể |
|---|---|
| Least privilege | IAM/role hạt mịn, Resource/compartment cụ thể, bỏ `*` |
| Explicit deny guardrail | SCP / Org Policy / permission boundary (OCI không có Deny — siết bằng phạm vi compartment) |
| Loại bỏ credential lâu dài | IAM Role/SA token/Instance Principal thay access key; WIF; IMDSv2 |
| Mã hóa mặc định | SSE-KMS/CMEK/OCI Vault key + chặn non-TLS |
| Khả năng quan sát | CloudTrail + Config + GuardDuty / Audit Logs + SCC / OCI Audit + Cloud Guard, log bất biến |
| Chặn public mặc định | S3 BPA / Uniform bucket-level access / OCI bucket private sẵn |
| Phát hiện liên tục | CSPM (Prowler/ScoutSuite/SCC/Cloud Guard) + secret scanning trong CI |
| Ranh giới môi trường | Tách theo prod vs non-prod (không theo nhà cung cấp); prod trên cloud "dev" siết ngang prod chính |

Toàn bộ kiến trúc bảo mật đám mây quy về: **kiểm soát danh tính (IAM) chặt, loại bỏ bí mật lâu dài, mã hóa mọi nơi, ghi log đầy đủ và bất biến, chặn public mặc định, và quét cấu hình sai liên tục.** Phần lớn sự cố thực tế nằm ở "IN the cloud" — tức trong tầm kiểm soát và trách nhiệm của bạn.


---

## Ghi chú của mình

> *Khu vực ghi chú cá nhân: những điểm từng hiểu sai, phần còn đang tìm hiểu, hoặc kinh nghiệm rút ra khi thực hành — cập nhật dần.*

**Từ AWS sang OCI — mấy chỗ mình bị hụt tư duy.** Mình học cloud từ AWS trước, nên khi phải vận hành thêm OCI (dev và một phần prod) thì bị "vấp" đúng ở những khái niệm tưởng giống mà không giống:

- **Compartment không phải account.** Ban đầu mình cứ tìm "tạo account con" như Organizations của AWS, mãi mới nhận ra OCI cô lập bằng compartment *trong cùng một tenancy*. Hệ quả bảo mật: ranh giới yếu hơn tách account, nên một policy viết ở cấp tenancy có thể rò quyền xuống mọi compartment. Từ đó mình cẩn thận đặt phạm vi `in compartment <cụ thể>` chứ không `in tenancy` cho tiện.
- **Policy dạng câu, và KHÔNG có Deny.** Cú pháp `Allow group … to manage … in compartment …` đọc rất dễ chịu, nhưng mình mất một lúc mới thấm là *không có `Deny` tường minh* như SCP. Thói quen dựng guardrail bằng explicit Deny của AWS không bê thẳng sang được — phải nghĩ lại theo hướng "chỉ cấp đúng phạm vi", hoặc dùng Network Sources/tag. Đây là chỗ mình vẫn đang tìm hiểu tiếp: làm guardrail cấp tenancy trên OCI cho gọn thì dùng gì cho tương đương SCP.
- **Hai lớp tường lửa Security List + NSG.** Một lần đổi rule trên NSG mà gói vẫn không đi, mất công debug mới nhớ ra Security List ở subnet vẫn đang chặn — cả hai phải cùng cho phép (AND). Và Security List **stateful mặc định** (khác NACL của AWS là stateless), nên đừng máy móc mở dải ephemeral port như thói quen NACL. Giờ mình theo nguyên tắc: phân quyền mạng bằng NSG (tham chiếu NSG-to-NSG), giữ Security List tối giản.
- **Bucket private mặc định là điểm cộng thật.** Sau ám ảnh "S3 public-read" kinh điển, việc Object Storage của OCI mặc định private làm mình nhẹ đầu hơn — nhưng vẫn bật Cloud Guard để nó gắn cờ nếu ai đó lỡ đổi sang public. Chia sẻ file thì phát Pre-Authenticated Request có hạn, không bao giờ để bucket public "cho tiện".
- **Metadata `Bearer Oracle` không phải bí mật.** Lúc đầu mình tưởng header `Authorization: Bearer Oracle` là một dạng token nên yên tâm. Không phải — nó là hằng số cố định, chỉ chặn được SSRF *ngây thơ* (loại không thêm được header). SSRF điều khiển được header vẫn qua. Nên mình vẫn siết đủ bộ SSRF defense ở tầng app, coi metadata v2 (cả AWS lẫn OCI) chỉ là một lớp phụ.

**Bài học vận hành đa đám mây lớn nhất:** ranh giới bảo mật đúng là **prod vs non-prod**, không phải AWS vs OCI. Prod chạy trên OCI mình bắt áp đúng chuẩn siết như prod AWS — cái bẫy là để compartment prod "thừa hưởng" thói quen lỏng của dev vì ở chung tenancy. Việc prod-AWS và dev-OCI tách cả nhà cung cấp lẫn credential là một lợi thế blast-radius *tình cờ*, nhưng mình không dựa vào đó thay cho kỷ luật cấu hình.

**Đang tìm hiểu tiếp:** chuẩn hóa cả hai đám mây bằng Terraform + policy-as-code (Checkov/Trivy quét cả AWS lẫn OCI) để bớt phải nhớ hai lối cấu hình tay; và cách gom log/alert của Cloud Guard (OCI) với GuardDuty/Config (AWS) về cùng một chỗ để một người vẫn theo dõi xuể.
