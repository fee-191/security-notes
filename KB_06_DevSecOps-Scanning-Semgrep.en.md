# Chapter 6 — DevSecOps & Source Code Security Scanning

## Overview

Traditional security is a checkpoint at the end: write the code, then someone reviews it right before release. That has a very practical problem — by the time anything turns up, fixing it is expensive, often expensive enough that the finding gets accepted as risk and waved through. **DevSecOps** inverts that order by embedding security controls into the development process itself, and **shift-left** means moving each check as early as it will go — the earliest being the developer's own machine, before the code has left it.

The place those checks live is the **CI/CD pipeline**. This chapter walks through each class of scanning in terms of its blind spot, because none of them catches everything: **SAST** reads source statically (good at injection, XSS, path traversal), **DAST** attacks the running application (runtime faults and misconfiguration), **IAST** instruments the runtime to connect data flow with code location, **SCA** checks third-party libraries against CVE databases, plus **secret scanning**, **IaC scanning** and **container scanning**. Three tools get covered deeply enough to use immediately: **Semgrep** (SAST matching on AST structure rather than plain text — the focus being YAML rules, metavariables like `$X`, and taint mode), **gitleaks** (scanning both content and git history, combining structural regex with Shannon entropy) and **Trivy** (images, filesystems, IaC, SBOM).

The second half shifts from tools to operating them without the team turning against you. **Gates** talk to the pipeline through exit codes and must be tiered — serious findings block the build, minor ones only warn — because otherwise alert fatigue kills the whole control. Alongside that: supply chain security (**SBOM** to answer "which of our products contains the component with this CVE", artifact signing with cosign/sigstore), centralised secret management with **Vault** — dynamic secrets, and OIDC/workload identity to solve the "secret zero" problem — and **pre-commit hooks** as the furthest-left checkpoint (which developers can skip, so CI must repeat everything). The final section covers **AI-generated code**: it runs but isn't safe, it brings its own risks like slopsquatting, and the answer is reusing the pipeline you already have rather than building a parallel process.

> Every tool here comes with a runnable example and an explanation of why it was designed that way — anything version-dependent carries its own note.
---

## 6.1. The shift-left philosophy & the DevSecOps model

### 6.1.1. The economics behind shift-left

DevSecOps is not a tool but an **operating model** in which security controls are embedded into every stage of the software development lifecycle (SDLC) rather than performed once at the end.

The underlying reason is that the cost of fixing a defect grows exponentially with the stage at which it is found. The classic cost model (often attributed to NIST / the IBM Systems Sciences Institute — the exact figures should be verified against sources, as citations vary widely) is qualitatively as follows:

| Stage where the defect is found | Relative cost (qualitative) | Why |
|---|---|---|
| Coding / IDE | 1x | The developer still holds the context and fixes it immediately |
| Build / CI | ~5x | Must go back, context is lost, the pipeline reruns |
| QA / Test | ~10x | Requires investigation and writing a reproduction test |
| Production | ~30x–100x+ | Emergency hotfix, downtime, possible prior exploitation, legal liability |

"Shift-left" means moving security activities **to the left** on the SDLC timeline (left = earlier). The goal is not to abandon final testing, but to **reduce the number of defects that survive** to the expensive stages.

```
TRADITIONAL (security at the end):
[Plan]→[Code]→[Build]→[Test]→[Release]→[Deploy]→[Operate]
                                                    └── Pentest once/year

DEVSECOPS (security at every point):
[Plan]    [Code]      [Build]      [Test]     [Release]   [Deploy]    [Operate]
  │         │           │            │           │           │           │
threat    SAST        SCA          DAST       sign        admission   runtime
model   pre-commit   secret      IAST        SBOM       controller   detection
        IDE plugin   container   ZAP        provenance   policy      WAF/EDR
                     scan
```

### 6.1.2. Core design principles

- **Automation**: humans do not scale; gates must run automatically in the pipeline.
- **Fast feedback**: alerts must reach the developer within minutes (at the PR/MR), not weeks (a PDF report).
- **Policy as Code**: security policy is codified (YAML rules, OPA Rego, manifests) so it is versioned, reviewable, and reproducible.
- **Fail tiered**: not every finding blocks the build — distinguish blocking vs. warning (see 6.9).
- **Guardrails, not gatekeepers**: provide rails to move fast safely, rather than blocking gates that push developers to find workarounds (shadow IT).

### 6.1.3. The full tiered shift-left pipeline (applied in practice)

Applied to a real project, the theory above becomes a concrete chain of tiers that can be built entirely with open-source tools. **Each tier catches its own class of defects, and no tier can replace another** — dropping a tier opens exactly that tier's blind spot.

```
IDE ────► pre-commit ────► CI (on PR) ─────────► staging ────► runtime
Semgrep    gitleaks         Semgrep + gitleaks    OWASP ZAP     SIEM
/linter                     + Trivy (image+deps)  (DAST)        monitoring
```

| Tier | Tools | What it catches | Why it cannot be dropped |
|---|---|---|---|
| IDE (while typing) | Semgrep extension, linter | Dangerous patterns as they are written (SQLi, `eval`, hardcoding) | Instant feedback, 1x fix cost; but the developer can turn it off |
| pre-commit (dev machine) | gitleaks | Secrets before they enter git history | A committed and pushed secret is considered exposed and must be rotated; but the hook can be bypassed with `--no-verify` |
| CI on the PR | Semgrep (SAST) + gitleaks + Trivy (image + dependency) | Code defects, secrets that slipped past the hook, CVEs in libraries and images | The server-side gate that cannot be bypassed — repeats every check from the earlier tiers |
| Staging (pre-deploy) | OWASP ZAP (DAST) | Runtime bugs, misconfig, missing headers — SAST's blind spot | Only visible when the app actually runs |
| Runtime (production) | SIEM monitoring & alerting (see [Chapter 8](#sec-08)) | Real attacks, anomalous behavior | No set of scanners catches everything before deploy; there must be eyes at the last tier |

The first two tiers run on the developer's machine, so they are only a "courtesy layer" — their real value is early feedback, while enforcement lives in CI (see 6.12.3). Conversely, with CI only and no IDE/pre-commit tier, developers get feedback hours later and the secret has already made it into git history.

---

## 6.2. A taxonomy of security scanning techniques

This is the foundational section: each family of tools views software from a different angle and has its own blind spot. Understanding the mechanism helps you choose the right tool and understand why multiple types must be combined (defense in depth for the testing process itself).

### 6.2.1. Overview table

| Type | Full name | Input | App must run? | Detects well | Blind spot | Representative tools |
|---|---|---|---|---|---|---|
| SAST | Static Application Security Testing | Source/bytecode | No | SQLi, XSS, path traversal, hardcoded crypto | Runtime/config bugs, auth logic | Semgrep, SonarQube |
| DAST | Dynamic Application Security Testing | Running app (HTTP) | Yes | Runtime bugs, server misconfig, auth | Cannot see code, coverage depends on the crawler | OWASP ZAP |
| IAST | Interactive AST | Agent in the runtime + traffic | Yes | Combines runtime data flow + code location | Requires instrumentation, limited languages | (mostly commercial) |
| SCA | Software Composition Analysis | Dependency manifest/lockfile | No | CVEs in third-party libraries, license | Bugs in your own code | Trivy, Dependabot |
| Secret scanning | — | Source + git history | No | API keys, tokens, private keys committed | Encrypted secrets, secrets outside the repo | gitleaks |
| IaC scanning | Infrastructure as Code | Terraform/K8s/CFN | No | Public S3, SG open to 0.0.0.0/0 | Runtime drift vs. code | Checkov, Trivy (misconfig) |
| Container scanning | — | Image layers / filesystem | No | CVEs in OS packages, app deps in the image | Application logic bugs | Trivy |

A point worth noting for small teams: the core set (Semgrep, gitleaks, Trivy, ZAP, Checkov) is all open source and essentially free. The real cost is not licenses but **human operating time** — tuning rules, triaging results, keeping the pipeline alive. The problem is not "having budget for tools" but "having the discipline to use the tools + automation so that few people can carry the load."

### 6.2.2. SAST — static analysis

**What it is**: analysis of source code (or bytecode) without executing it.

**Internal mechanism**: the typical pipeline is:

1. **Lexing (tokenize)**: character stream → tokens. For example, `user_id = req.params.id` → `[IDENT(user_id), OP(=), IDENT(req), DOT, IDENT(params), DOT, IDENT(id)]`.
2. **Parsing**: tokens → **AST** (Abstract Syntax Tree) according to the language grammar.
3. **Semantic analysis**: build the control-flow graph (CFG), data-flow graph (DFG), and call graph.
4. **Taint analysis**: track data from a **source** (untrusted input) to a **sink** (dangerous function) without passing through a **sanitizer**.

**Why use an AST instead of a regex**: a regex does not understand syntactic structure. For example, a regex looking for `query(...)` will false-alarm on comments and string literals, or miss matches when the code wraps across lines. An AST understands that `query` is a function call whose argument is a string-concatenation expression containing a tainted variable.

### 6.2.3. DAST — dynamic analysis

**Mechanism**: the tool acts as an HTTP client/proxy, **crawls** the application to map out endpoints, then **fuzzes** each parameter with attack payloads (`' OR 1=1--`, `<script>`, `../../etc/passwd`), observing the **response** (status code, latency, content, error message) to infer vulnerabilities. Black-box: it cannot see the code.

### 6.2.4. IAST

**Mechanism**: attach an **agent** (instrumentation) to the runtime (for example, a Java agent via `-javaagent`, bytecode instrumentation). When DAST/tests send a request, the agent observes the **actual** data flow inside the process — it knows the payload travels from an HTTP parameter into the executed SQL statement. It combines data-flow accuracy (like SAST) with runtime context (like DAST), so it produces fewer false positives.

### 6.2.5. SCA

**Mechanism**: read the manifest/lockfile (`package-lock.json`, `pom.xml`, `go.sum`, `requirements.txt`), build the dependency tree (including transitive dependencies), and match it against vulnerability databases (NVD, GitHub Advisory, OSV). Then map version → CVE via the affected version ranges. This matters because more than 80% of a modern codebase is third-party code.

---

## 6.3. Semgrep — architecture and the parse → AST → matching mechanism

Semgrep ("semantic grep") is an open-source SAST tool positioned between "grep" (fast, simple) and heavyweight SAST (accurate, slow). Its philosophy: a rule **looks like the code you want to find**.

### 6.3.1. Internal processing pipeline

```
                Source file (e.g. app.py)
                        │
                        ▼
         ┌──────────────────────────────┐
         │  Tree-sitter / own parser    │  Parse to language-specific CST/AST
         └──────────────────────────────┘
                        │
                        ▼
         ┌──────────────────────────────┐
         │   Generic AST (semgrep core) │  Normalize to a shared multi-language AST
         └──────────────────────────────┘
                        │
   Rule pattern ──────► │  The pattern is also parsed into the same kind of AST
                        ▼
         ┌──────────────────────────────┐
         │   Structural matching        │  Tree-against-tree match + metavariable
         │   + metavariable binding     │  constraints, taint propagation
         └──────────────────────────────┘
                        │
                        ▼
                  Findings (JSON/SARIF)
```

The trick is that **the pattern in a rule is also parsed into an AST** just like the target code, and Semgrep then matches **tree against tree** (structural match), not text against text. That's why:

- `foo(1, 2)` matches whether the code is written `foo(1,2)`, `foo( 1, 2 )`, or wrapped across lines.
- Comments, whitespace, and redundant parentheses are naturally ignored.
- Basic semantics are understood (for example, `$X == $X` understands both sides as the same variable).

### 6.3.2. Equivalences (semantic equivalence)

Semgrep automatically applies a number of equivalences to reduce the number of rules you must write. For example: aliased imports (`import subprocess as sp` → the pattern `subprocess.call(...)` still matches `sp.call(...)`), simple constant propagation, and equivalent call forms. This is why a short pattern catches many variants.

### 6.3.3. Installation and basic CLI commands

```bash
# Install via pip (Python 3.8+)
python3 -m pip install semgrep
semgrep --version        # e.g.: 1.x.x

# Or Docker (no local install needed)
docker run --rm -v "$PWD:/src" semgrep/semgrep semgrep --config auto /src
```

The core scan commands:

```bash
# Scan with a ready-made community ruleset (registry)
semgrep --config "p/owasp-top-ten" .

# 'auto' = Semgrep picks the ruleset based on the detected language
semgrep --config auto .

# Use a single local rule file
semgrep --config ./rules/sqli.yaml ./src

# Multiple configs at once
semgrep --config p/security-audit --config ./rules/ .
```

Explanation of important parameters:

| Parameter | Meaning |
|---|---|
| `--config <X>` | Rule source: `p/<pack>` (registry), a file/directory path, a URL, or `auto` |
| `--json` / `--sarif` | Output format (CI integration / GitHub code scanning) |
| `--output <file>` | Write results to a file |
| `--severity <LVL>` | Filter by ERROR/WARNING/INFO |
| `--error` | Return a non-zero exit code when there is a finding (used for gates — see 6.9) |
| `--baseline-commit <sha>` | Report only **new** findings relative to a base commit (diff-aware) |
| `--exclude <glob>` | Skip a path (e.g. `--exclude 'tests/*'`) |
| `--max-target-bytes` | Skip files larger than the threshold (default ~1MB) |
| `--metrics off` | Disable sending anonymous metrics |

---

## 6.4. YAML rule-writing syntax — field structure

### 6.4.1. The skeleton of a rule

A Semgrep rule file is YAML with the root key `rules` (an array). Each element describes one rule. The fields:

| Field | Required | Type | Meaning | Example |
|---|---|---|---|---|
| `id` | Yes | string | Unique identifier (appears in reports) | `python.sqli.format-string` |
| `languages` | Yes | list | Languages it applies to | `[python]`, `[javascript, typescript]` |
| `severity` | Yes | enum | `ERROR` / `WARNING` / `INFO` | `ERROR` |
| `message` | Yes | string | Description sent to the developer (should include how to fix) | `SQL injection detected...` |
| `pattern` | (one of these) | string | A single pattern to match | `eval(...)` |
| `patterns` | — | list | AND logic: all children must hold | (see below) |
| `pattern-either` | — | list | OR logic: any child matching is a match | |
| `pattern-not` | — | string | Exclusion (reduces false positives) | |
| `pattern-inside` | — | string | Match only when inside this context | |
| `pattern-not-inside` | — | string | Exclude if inside this context | |
| `metavariable-regex` | — | map | Constrain a metavariable by regex | |
| `mode` | — | enum | `search` (default) or `taint` | `taint` |
| `metadata` | — | map | CWE, OWASP, references, confidence | |
| `fix` | — | string | Automatic fix (autofix) | |

### 6.4.2. The metavariable `$X`

A metavariable is a **variable within a pattern**, written in uppercase and starting with `$`: `$X`, `$FUNC`, `$ARG`. It matches any AST node (an expression, an identifier, a call, etc.) and **remembers** (binds) that value. The same metavariable name within the same pattern must match the same content.

```yaml
# [DEMO] Catch comparing a variable with itself (always true/false — a logic bug); illustrates the metavariable mechanism only.
rules:
  - id: self-comparison
    languages: [python]
    severity: WARNING
    message: "Comparing $X with itself always yields a fixed result."
    pattern: $X == $X
```

The pattern above matches `a == a` and `user.id == user.id` (because both sides bind to the same `$X`), but does NOT match `a == b`.

Special metavariable forms:

| Syntax | Matches |
|---|---|
| `$X` | A single node |
| `...` (ellipsis) | A sequence of 0+ arbitrary arguments/statements/elements |
| `$...ARGS` | A sequence of arguments, but with a bound name |
| `"..."` | Any string literal |
| `$X.$METHOD(...)` | Any method call on `$X` |

The ellipsis `...` is very important: `foo(...)` matches `foo()`, `foo(1)`, `foo(a, b, c)`. And `foo(..., $SENSITIVE, ...)` matches `$SENSITIVE` appearing at any argument position.

### 6.4.3. `patterns` (AND), `pattern-either` (OR), `pattern-not`, `pattern-inside`

```yaml
# [PROD] Rule tight enough for production use (constant commands excluded via pattern-not).
rules:
  - id: dangerous-subprocess-with-shell
    languages: [python]
    severity: ERROR
    message: "subprocess called with shell=True and dynamic input → command injection."
    patterns:
      # AND: must match the call AND have shell=True AND NOT be a literal
      - pattern-either:
          - pattern: subprocess.call(...)
          - pattern: subprocess.run(...)
          - pattern: subprocess.Popen(...)
      - pattern: $FN(..., shell=True, ...)
      - pattern-not: $FN("...", ..., shell=True, ...)   # skip constant commands
```

Logical semantics:

- `patterns:` = **AND** — every child item must hold over the same region of code.
- `pattern-either:` = **OR** — only one child item needs to hold.
- `pattern-not:` = negation — drop the finding if this pattern matches (reduces FPs).
- `pattern-inside:` = context constraint — match only when the code is **inside** an enclosing structure (for example, inside a function or a loop).

Example of `pattern-inside` to catch the bug only within a route handler:

```yaml
# [PROD] Rule tight enough for production use (context scoped to a Flask route via pattern-inside).
rules:
  - id: raw-sql-in-flask-route
    languages: [python]
    severity: ERROR
    message: "String-concatenated SQL statement inside a Flask route."
    patterns:
      - pattern-inside: |
          @app.route(...)
          def $HANDLER(...):
              ...
      - pattern: $CUR.execute("..." % ...)
```

### 6.4.4. `metavariable-regex` and `metavariable-pattern`

```yaml
# [PROD] Rule tight enough for production use (weak algorithm constrained via metavariable-regex).
rules:
  - id: weak-hash-algo
    languages: [python]
    severity: WARNING
    message: "Weak hash algorithm: $ALGO"
    patterns:
      - pattern: hashlib.new($ALGO, ...)
      - metavariable-regex:
          metavariable: $ALGO
          regex: ^["'](md5|sha1)["']$
```

`metavariable-regex` applies a regex to the **textual value** that the metavariable has bound. Here it only reports when the algorithm is `md5` or `sha1`.

---

## 6.5. Taint mode — source / sink / sanitizer

### 6.5.1. Mechanism

`search` mode matches structurally at a single point. But SQLi/command injection are **data flow** problems: tainted data travels from A to B through several steps. `mode: taint` models this with a three-set scheme:

- **source**: where untrusted data appears (HTTP param, file read, env).
- **sink**: where it is dangerous if it receives tainted data (`execute`, `eval`, `os.system`).
- **sanitizer**: where the data is "cleaned" (escape, parametrize, allowlist). If the data passes through a sanitizer before reaching the sink → no report.

Semgrep tracks the propagation of taint through assignments, string concatenation, and function calls. A finding is only raised when there exists a path **source → ... → sink** that does NOT cross a sanitizer.

```
[source]──taint──►[var a]──taint──►[a + "x"]──taint──►[sink]   ❌ REPORT BUG
[source]──taint──►[sanitize(a)]──clean──►[sink]                ✅ SAFE
```

### 6.5.2. Taint example catching SQL injection

```yaml
# [PROD] Taint rule tight enough for production use (has source/sink/sanitizer and focus-metavariable).
rules:
  - id: python-sqli-taint
    languages: [python]
    severity: ERROR
    message: >
      Data from an HTTP request flows into a SQL statement without parameterization
      → SQL injection (CWE-89).
    mode: taint
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A05:2025 - Injection"
      confidence: HIGH
    pattern-sources:
      - pattern: flask.request.$ANYTHING
      - pattern: flask.request.args.get(...)
      - pattern: flask.request.form[...]
    pattern-sanitizers:
      - pattern: int(...)                       # int cast = safe against SQLi
      - pattern: $DB.execute($Q, $PARAMS)       # parameterized query
    pattern-sinks:
      - patterns:
          - pattern: $CURSOR.execute($QUERY, ...)
          - focus-metavariable: $QUERY
```

Code that is caught:

```python
from flask import request
name = request.args.get("name")          # SOURCE
q = "SELECT * FROM users WHERE name='%s'" % name   # taint propagates
cursor.execute(q)                        # SINK  → REPORT BUG
```

Code that is NOT caught (sanitized):

```python
uid = int(request.args.get("id"))        # int() = sanitizer
cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))  # parameterized
```

`focus-metavariable` narrows the finding to the exact part of the expression (`$QUERY`) rather than the whole call, helping the report pinpoint the location accurately.

---

## 6.6. Several real-world rule examples

### 6.6.1. Catching `eval()` on dynamic input (RCE)

```yaml
# [PROD] Rule tight enough for production use.
rules:
  - id: js-eval-user-input
    languages: [javascript, typescript]
    severity: ERROR
    message: "eval() with dynamic data → remote code execution (CWE-95)."
    metadata: { cwe: "CWE-95", owasp: "A05:2025" }
    patterns:
      - pattern: eval($X)
      - pattern-not: eval("...")     # allow eval of a constant string (still better avoided)
```

```javascript
eval(req.query.code);   // ❌ matches
eval("1 + 1");          // ✅ skipped thanks to pattern-not
```

### 6.6.2. Catching hardcoded secrets

```yaml
# [PROD] Rule tight enough for production use (matches AWS Access Key ID structure + constrains the variable name).
rules:
  - id: hardcoded-aws-key
    languages: [python, javascript, go]
    severity: ERROR
    message: "AWS Access Key ID hardcoded in source."
    patterns:
      - pattern-regex: AKIA[0-9A-Z]{16}
  - id: hardcoded-generic-password
    languages: [python]
    severity: WARNING
    message: "Password hardcoded into a variable."
    patterns:
      - pattern-either:
          - pattern: $PWD = "..."
      - metavariable-regex:
          metavariable: $PWD
          regex: (?i)(password|passwd|pwd|secret|token|api_?key)
      - pattern-not: $PWD = ""
```

`AKIA[0-9A-Z]{16}` is the structure of an AWS Access Key ID: the prefix `AKIA` + 16 characters (20 characters total). Semgrep's `pattern-regex` applies a regex over the source text (and can be combined with the AST via `patterns`).

### 6.6.3. Catching command injection (Go)

```yaml
# [PROD] Taint rule tight enough for production use.
rules:
  - id: go-command-injection
    languages: [go]
    severity: ERROR
    message: "exec.Command with input from HTTP → command injection."
    mode: taint
    pattern-sources:
      - pattern: $R.URL.Query().Get(...)
      - pattern: $R.FormValue(...)
    pattern-sinks:
      - pattern: exec.Command($CMD, ...)
      - pattern: exec.Command("sh", "-c", $ARG)
```

### 6.6.4. Autofix

```yaml
# [PROD] Rule tight enough for production use (includes autofix to safe_load).
rules:
  - id: insecure-yaml-load
    languages: [python]
    severity: ERROR
    message: "yaml.load is unsafe → use safe_load."
    pattern: yaml.load($X)
    fix: yaml.safe_load($X)
```

Running `semgrep --config rule.yaml --autofix .` will replace `yaml.load(data)` with `yaml.safe_load(data)` directly in the file.

### 6.6.5. Sample output

```
$ semgrep --config rules/ src/app.py

┌─────────────┐
│ 2 Findings  │
└─────────────┘

  src/app.py
    python-sqli-taint
        Data from an HTTP request flows into a SQL statement... (CWE-89)
        12┆ cursor.execute(q)

    hardcoded-aws-key
        AWS Access Key ID hardcoded in source.
        20┆ KEY = "AKIAIOSFODNN7EXAMPLE"

Ran 5 rules on 1 file: 2 findings.
```

### 6.6.6. Handling false positives & severity

A strategy for reducing false positives, in order of priority:

1. **Add `pattern-not` / `pattern-not-inside`** to exclude known-safe cases.
2. **Add a sanitizer** (taint mode) for internal data-cleaning functions.
3. **Inline nolint**: add a `# nosemgrep: <rule-id>` comment right on the line to intentionally skip it (should include a reason).
4. **`.semgrepignore`** (same syntax as `.gitignore`) to exclude paths (vendored code, tests, generated files).

```python
result = eval(trusted_expr)   # nosemgrep: js-eval-user-input — string is whitelisted
```

**A team-scale strategy against false-positive fatigue.** If you enable a large ruleset on day one and Semgrep reports hundreds of warnings, developers give up — and that is when the scan is effectively dead even though it still runs in the pipeline. The more sustainable approach:

1. **Start with a small, high-confidence ruleset** (SQLi, hardcoded secrets, XSS — rules that almost never false-alarm), then expand gradually once the team is used to it.
2. **Make only a few rules blocking, the rest warnings** — true tiering (see 6.9), prioritizing by severity instead of chasing finding counts.
3. **Triage periodically**: a fixed schedule for reviewing warning findings, tuning rules (`pattern-not`, sanitizers), and deciding whether to promote them to blocking or drop them entirely. A rule no one looks at is a rule that should be turned off.
4. **A few custom rules for internal patterns are worth more than enabling everything**: SAST struggles with business logic, but a handful of well-placed self-written rules — things like "every controller must have an authorization guard," "no raw queries without parameterization" — catch exactly the mistakes the team actually makes, without adding noise.

Severity → action convention (linked to the pipeline gate in 6.9):

| Severity | Meaning | Suggested pipeline action |
|---|---|---|
| ERROR | Exploitable vulnerability, high confidence | Block the build (blocking) |
| WARNING | Possibly an issue / needs review | Warn, do not block |
| INFO | Recommendation, best practice | Note |

---

## 6.7. Gitleaks — secret scanning (regex + entropy)

### 6.7.1. The two-tier mechanism

Gitleaks scans **file contents AND git history** (every commit/blob via `git log -p`), looking for secrets using two complementary methods:

1. **Regex rules**: catch secrets with a **recognizable structure** (AWS key `AKIA...`, GitHub PAT `ghp_...`, JWT `eyJ...`). High accuracy, few FPs.
2. **Shannon entropy**: catch **unstructured** secrets (highly random strings such as base64 tokens). Entropy measures the "randomness" of a string:

```
H = -Σ p(x) · log2 p(x)        (bits/character)
```

English text is typically ~3.5–4.5 bits/character, whereas random base64 secrets are typically >4.5. Setting an entropy threshold helps catch unusual secrets; but if the threshold is set too low, it easily produces false positives.

### 6.7.2. Commands

```bash
# Scan the entire git history of the current repo
gitleaks detect --source . --verbose

# Scan only the working directory (no history) — fast, for pre-commit
gitleaks detect --no-git --source .

# Scan the currently staged changes (pre-commit hook)
gitleaks protect --staged --source .

# Output a report + non-zero exit code if there is a leak
gitleaks detect --source . --report-format sarif --report-path leaks.sarif
```

Version note: as of gitleaks v8.19, the command set was reorganized — `gitleaks git` (scan a repo + its history), `gitleaks dir` (scan a directory, replacing `detect --no-git`), `gitleaks stash`; the old `detect`/`protect` commands are marked deprecated but still work (verify against the version you use):

```bash
gitleaks git .              # replaces: gitleaks detect --source .
gitleaks dir .              # replaces: gitleaks detect --no-git --source .
gitleaks git --pre-commit --staged .   # for use in a pre-commit hook
```

### 6.7.3. `.gitleaks.toml` example

```toml
# [PROD] Configuration tight enough for production use (inherits the default rules, adds internal rules + allowlist).
title = "Company Gitleaks configuration"

[extend]
useDefault = true        # inherit the default rule set, then add below

[[rules]]
id = "company-internal-token"
description = "Internal service token (prefix INT_)"
regex = '''INT_[A-Za-z0-9]{32}'''
keywords = ["INT_"]      # speed optimization: only run the regex if the file contains the keyword
entropy = 3.5            # require a minimum entropy to reduce FPs

[[rules]]
id = "generic-api-key"
description = "Generic API key assigned to a variable"
regex = '''(?i)(api[_-]?key|apikey)['"\s:=]{1,5}['"]([0-9a-zA-Z]{32,45})['"]'''
secretGroup = 2          # the capture group containing the real secret value

[allowlist]
description = "Skip test and example samples"
regexes = [
  '''AKIAIOSFODNN7EXAMPLE''',     # AWS's official example key
]
paths = [
  '''(.*?)(test|spec|fixtures)(.*?)''',
]
```

Description of the main rule fields:

| Field | Meaning |
|---|---|
| `id` | Rule identifier |
| `regex` | The pattern identifying the secret |
| `keywords` | Fast filter: only run the regex if the file contains the keyword (performance optimization) |
| `entropy` | Minimum entropy threshold of the capture group |
| `secretGroup` | The regex group containing the secret value (for entropy/redaction) |
| `[allowlist]` | Exclusions by regex/path/commit (reduces FPs) |

---

## 6.8. Trivy — scanning images / filesystems / IaC

Trivy is a versatile scanner: container images, filesystems, git repos, IaC, and SBOM generation.

### 6.8.1. Scanning a container image

```bash
trivy image --severity HIGH,CRITICAL nginx:1.21.0
```

Mechanism: Trivy **unpacks the layers** of the image, reads the distro's package database (APK/`/lib/apk/db`, DPKG/`/var/lib/dpkg/status`, RPM), enumerates (package, version), and compares it against a vulnerability database (`trivy-db`, synced from NVD, GHSA, distro advisories). It also detects application dependencies (lockfiles embedded in the image).

Sample output (abridged):

```
nginx:1.21.0 (debian 10.9)
Total: 142 (HIGH: 130, CRITICAL: 12)

┌──────────┬────────────────┬──────────┬─────────────────┬──────────────────┐
│ Library  │ Vulnerability  │ Severity │ Installed Ver   │ Fixed Version    │
├──────────┼────────────────┼──────────┼─────────────────┼──────────────────┤
│ openssl  │ CVE-2021-3711  │ CRITICAL │ 1.1.1d-0+deb10  │ 1.1.1d-0+deb10u7 │
│ libc6    │ CVE-2021-33574 │ CRITICAL │ 2.28-10         │ (won't fix)      │
└──────────┴────────────────┴──────────┴─────────────────┴──────────────────┘
```

Important parameters:

| Parameter | Meaning |
|---|---|
| `--severity` | Filter by level (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL) |
| `--ignore-unfixed` | Skip CVEs with no patch yet (reduces non-actionable noise) |
| `--exit-code 1` | Return a non-zero exit when something is found (gate) |
| `--scanners vuln,secret,misconfig` | Select the scan types |
| `--format sarif --output x.sarif` | CI integration |

### 6.8.2. Scanning filesystems & IaC

```bash
# Scan deps in source (lockfile) + secrets + misconfig
trivy fs --scanners vuln,secret,misconfig .

# Scan infrastructure configuration (Terraform / K8s / Dockerfile)
trivy config ./infra/
```

`trivy config` detects misconfigurations such as: a public S3 bucket, a security group open to `0.0.0.0/0`, a container running `privileged: true`, or a missing `readOnlyRootFilesystem`.

### 6.8.3. Gate in CI

```bash
# [PROD] Tiered-gate command pair, tight enough for production use.
trivy image --exit-code 0 --severity MEDIUM,HIGH --format table myapp:ci   # warn
trivy image --exit-code 1 --severity CRITICAL --ignore-unfixed myapp:ci    # block
```

The two separate commands express the tiered gate principle (6.9): CRITICAL blocks, HIGH only warns.

### 6.8.4. Prioritizing when the scanner reports hundreds of CVEs

Running a dependency scan for the first time on a codebase of some age and getting 200+ CVEs is normal — and nobody can fix them all, especially when the person handling them is a team of one. The problem is not "fix everything" but **prioritize correctly**. A CVE is only worth immediate action when it meets all of:

1. **High severity** (High/Critical) — filter with `--severity`.
2. **A fix version exists** — filter with `--ignore-unfixed`; a CVE without a patch admits no direct action (see below).
3. **Reachability**: it sits on a code path that actually executes — not a devDependency, not a module that is imported but unused. This is the most commonly ignored factor: a 9.8 CVE in a library whose affected code path the app never touches is less dangerous than a 7.5 CVE sitting right on a public endpoint.

Beyond CVSS (theoretical severity), cross-check two sources that measure **real-world exploitability**: **EPSS** (Exploit Prediction Scoring System — the probability the CVE will be exploited within the next 30 days) and **CISA KEV** (Known Exploited Vulnerabilities — the list of vulnerabilities *actively* being exploited in the wild). A CVE on the KEV list gets patched first regardless of its CVSS score.

For a Critical CVE with no patch yet: determine whether the affected code path is actually used; if it is, apply temporary mitigations (a WAF rule, input blocking, disabling the feature, isolating the service) and watch the advisory; if you are forced to defer, make it a **time-boxed** risk acceptance, never one that fades into oblivion.

Trivy's ignore mechanism serves exactly this purpose — but it demands discipline. A `.trivyignore` file in the repo:

```
# [PROD] Every ignored line must carry a reason + a re-review date.
# CVE-2025-12345 (lodash): affected code path unused (we only import cloneDeep)
#   Decided by: SecOps · Re-review: 2026-09-15
CVE-2025-12345

# CVE-2025-67890 (openssl in the base image): no fix yet, related cipher blocked at the LB
#   Decided by: SecOps · Re-review: 2026-08-30
CVE-2025-67890
```

Trivy only reads the CVE ID lines (`#` lines are comments), but it is precisely the comments that keep the ignore list from becoming "a graveyard of decisions nobody remembers the reasons for." An ignore without a re-review date is forgotten forever.

---

## 6.9. Designing pipeline gates — exit codes and tiering

### 6.9.1. The exit code is the contract between the scanner and CI

CI/CD treats a process's **exit code** as a pass/fail signal: `0` = pass, `!= 0` = fail (the build stops). Every scanner lets you control the exit code:

- Semgrep: `--error` → exit 1 if there is a finding; you can filter `--severity ERROR` first.
- Trivy: `--exit-code 1`.
- Gitleaks: defaults to exit 1 when a leak is found.

### 6.9.2. Why split into two tiers (blocking vs. warning)

If you block the build on **every** finding (including HIGH/MEDIUM), developers suffer "alert fatigue" and start disabling the scan or committing with `--no-verify`. If you block **nothing**, critical vulnerabilities slip into production. The solution: **two tiers**.

| Tier | Severity | Exit | Effect | Goal |
|---|---|---|---|---|
| Blocking gate | CRITICAL (and ERROR with HIGH confidence) | 1 | Red build, cannot merge | Block exploitable vulnerabilities |
| Warning gate | HIGH / WARNING | 0 | Green build + PR annotation/comment | Build awareness, add to the backlog |

The criterion for what belongs in the blocking tier: **unambiguous and almost never a false positive**. In practice I hard-block three groups — a committed secret (gitleaks), a Critical/High CVE **with an available fix version** (Trivy `--ignore-unfixed`), and IaC creating dangerous resources such as a public bucket / a security group open to `0.0.0.0/0`. The noisy remainder (low-severity SAST, DAST informational, CVEs without a patch) only warns + creates a ticket under an SLA. Hard-block everything and the team grows to hate the pipeline and finds ways around it; loosen everything and the gate is meaningless.

### 6.9.3. GitLab CI example (.gitlab-ci.yml)

```yaml
stages: [security]

semgrep_block:
  stage: security
  image: semgrep/semgrep
  script:
    # Only ERROR blocks; --error sets the exit code based on the remaining findings
    - semgrep --config p/security-audit --severity ERROR --error --json --output sg.json .
  artifacts:
    when: always
    reports:
      sast: sg.json

semgrep_warn:
  stage: security
  image: semgrep/semgrep
  allow_failure: true          # does NOT block the pipeline even if there are findings
  script:
    - semgrep --config p/security-audit --severity WARNING .

trivy_block:
  stage: security
  image: aquasec/trivy
  script:
    - trivy image --exit-code 1 --severity CRITICAL --ignore-unfixed $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

gitleaks:
  stage: security
  image: ghcr.io/gitleaks/gitleaks:latest   # the current official image (the old zricethezav/gitleaks still exists)
  script:
    - gitleaks git . --no-banner
```

`allow_failure: true` is GitLab's mechanism that lets a job fail without turning the pipeline red — exactly what a "warning gate" means. The `semgrep_block` job does not have it, so its failure blocks the merge.

To reduce noise on PRs/MRs, use diff-aware scanning (report only **new** findings):

```bash
semgrep ci   # automatically uses baseline = the target branch in the CI environment
# or manually:
semgrep --config auto --baseline-commit "$CI_MERGE_REQUEST_DIFF_BASE_SHA" .
```

### 6.9.4. A controlled exception mechanism

The most practical question about gates: **what happens when the gate blocks a merge and the release is urgent?** If there is no answer prepared in advance, the team will answer it themselves by turning the gate off — and once off, it rarely comes back on. A proper exception design:

- **Explicit approval required** from the person responsible for security (or a delegated lead when that person is away) — not the developer's own call.
- **A recorded reason + a mandatory, deadline-bound fix ticket** — today's override is debt with a due date, not a write-off.
- **An audit trail**: the exception lives in a PR comment / ticket, traceable to who approved it, when, and why. Never override silently (editing the gate config and putting it back).

An exception is a **controlled exception, not a default back door**. It also doubles as a health metric for the gate: if you have to override every single week, the problem is not the exception process but a gate threshold set wrong — fix the gate, do not normalize going around it.

---

## 6.10. Software supply chain security

### 6.10.1. Dependency confusion

**Attack mechanism**: if a company uses an internal package named `internal-utils` that exists only in a private registry, an attacker pushes a public package with the **same name** to a public registry (npm/PyPI) with a **higher version**. A misconfigured package manager may prefer the public registry (because the version is higher) → it downloads the attacker's malicious code.

```
The resolver sees: internal-utils
  ├─ private registry: 1.2.0   ← desired
  └─ public registry:  99.0.0  ← attacker's (higher version)
If both are queried → it may pick 99.0.0  → RCE at install time (postinstall)
```

**Defenses**: scoped packages (`@company/utils`), pin the registry per scope, use a lockfile + hashes, enable namespace/scope reservation, and use a read-only internal mirror.

### 6.10.2. SLSA levels

SLSA (Supply-chain Levels for Software Artifacts) is a framework for evaluating the integrity of a build process. A general description of the levels (the specific numbering should be verified against the current SLSA version, as it changed between v0.1 and v1.0):

| Level | Focus | Core requirement |
|---|---|---|
| L1 | Provenance exists | The build produces provenance describing how the artifact was created |
| L2 | Signed provenance + build service | Build on an authenticated service, provenance is signed |
| L3 | Isolated build, non-forgeable | Hardened build platform, tamper-resistant provenance |
| (L4 in v0.1, restructured in v1.0) | Dependencies + two reviewers | Should be verified against the current spec |

The core of SLSA is **provenance**: evidence of "which source this artifact was built from, by which builder, with what parameters."

### 6.10.3. SBOM — CycloneDX and SPDX

An SBOM (Software Bill of Materials) = the "component list" of software, so that when a new CVE is published (for example, Log4Shell) you can quickly trace "which product contains this component."

Two standard formats:

| Characteristic | CycloneDX | SPDX |
|---|---|---|
| Organization | OWASP | Linux Foundation (ISO/IEC 5962:2021) |
| Orientation | Security / vuln / VEX | License compliance + security |
| Format | JSON, XML | JSON, YAML, RDF, tag-value |
| Component identifier | PURL, CPE | PURL, CPE, SPDX-ID |

Generate an SBOM with Trivy or Syft:

```bash
trivy image --format cyclonedx --output sbom.cdx.json myapp:1.0
syft myapp:1.0 -o spdx-json=sbom.spdx.json
```

CycloneDX structure (JSON, abridged) — the main fields:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-...",
  "version": 1,
  "metadata": { "timestamp": "2026-06-19T00:00:00Z",
                "component": { "type": "application", "name": "myapp" } },
  "components": [
    {
      "type": "library",
      "name": "log4j-core",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "hashes": [ { "alg": "SHA-256", "content": "ab12..." } ]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `bomFormat` / `specVersion` | The format and spec version |
| `serialNumber` | A unique UUID for the SBOM (for referencing) |
| `version` | The number of revisions of the SBOM for the same serialNumber |
| `components[].purl` | Package URL — the standard identifier `pkg:<type>/<ns>/<name>@<ver>` |
| `components[].hashes` | Hashes to verify integrity |

The PURL is the key to matching CVEs: for example, `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` maps directly to the Log4Shell advisory.

### 6.10.4. Artifact signing with cosign / sigstore

Goal: prove that an artifact (image, SBOM, blob) **has not been modified** and **comes from a known party**. Cosign (part of Sigstore) supports **keyless signing**: instead of holding a long-lived private key, it uses an OIDC identity (Google/GitHub/CI) to request a **short-lived** certificate from the Fulcio CA, signs, and then records the signature in the **Rekor** transparency log (immutable, append-only).

```bash
# Keyless sign: opens the OIDC flow, gets a short-lived cert, signs, records in Rekor
# (as of cosign v2.0 keyless is the default, no COSIGN_EXPERIMENTAL=1 needed as in 1.x — needs verification)
cosign sign myregistry/myapp@sha256:abcd...

# Verify: check the signature + allowed identity + presence in Rekor
cosign verify \
  --certificate-identity "https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  myregistry/myapp@sha256:abcd...
```

Why the keyless design: it eliminates the risk of a leaked long-lived private key; the identity is tied to the workload/CI identity; the transparency log allows detection of unexpected signatures.

Reference an image by its **digest** (`@sha256:...`) rather than a tag, because a tag can be overwritten (mutable), whereas a digest is a content hash (immutable).

### 6.10.5. Provenance in CI

Sign along with a provenance attestation so that "where it was built from" can be verified:

```bash
cosign attest --predicate provenance.json --type slsaprovenance \
  myregistry/myapp@sha256:abcd...
```

An admission controller (for example, Kyverno / the Sigstore policy-controller) in the cluster can **reject** the deployment of any image that lacks a valid signature + provenance — turning the supply chain into a policy enforced at deploy time.

---

## 6.11. Secret management — Vault, dynamic secrets, OIDC

### 6.11.1. The problem with static secrets

Hardcoded secrets / secrets kept in an env file: no rotation, a leak means permanent exposure, and it is hard to audit "who used it and when." The solution: a **centralized secret manager** (HashiCorp Vault, AWS Secrets Manager) with **dynamic** and **short-lived** secrets.

### 6.11.2. Dynamic secrets

**Mechanism**: instead of storing a DB password, Vault **generates credentials on demand** with a short TTL. When the app needs to access the DB, Vault creates a temporary DB user (via the database secrets engine), returns it to the app, and **automatically revokes** it when the TTL expires or the lease is revoked.

```bash
# Enable the engine and configure the connection to Postgres
vault secrets enable database
vault write database/config/mydb \
  plugin_name=postgresql-database-plugin \
  connection_url="postgresql://{{username}}:{{password}}@db:5432/app" \
  allowed_roles="app-role" username="vaultadmin" password="..."

# Define the role: SQL that creates a temporary user, TTL 1h
vault write database/roles/app-role \
  db_name=mydb \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl="1h" max_ttl="24h"

# The app requests credentials (different each time, living for 1h)
vault read database/creds/app-role
# Key                Value
# lease_id           database/creds/app-role/abcd...
# lease_duration     1h
# password           A1b2-randomgenerated
# username           v-token-app-role-x9...
```

Why this is good: short-lived credentials → a small attack window; each consumer has its own credential → accurate auditing; immediate revocation when something is suspected.

### 6.11.3. OIDC / workload identity (eliminating the initial secret)

The "secret zero" problem: how can an app/CI **authenticate to Vault** without a hardcoded secret to start with? The answer: **OIDC / JWT auth** — a workload (GitHub Actions, K8s pod, AWS instance) already has a **signed identity** (a JWT issued by the OIDC provider). Vault trusts that issuer and grants a token based on the claims.

```bash
# Configure Vault to trust GitHub Actions OIDC
vault auth enable jwt
vault write auth/jwt/config \
  oidc_discovery_url="https://token.actions.githubusercontent.com"

# Role: only the main workflow of a specific repo is allowed, with an attached policy
vault write auth/jwt/role/ci-role \
  role_type="jwt" user_claim="actor" bound_audiences="https://vault.company.com" \
  bound_claims_type="glob" \
  bound_claims='{"repository":"org/repo","ref":"refs/heads/main"}' \
  policies="app-policy" ttl="15m"
```

In GitHub Actions, the runner obtains a JWT (`id-token: write`) and exchanges it for a Vault token — **no long-lived secret** is stored. The JWT contains claims such as `repository`, `ref`, `actor`, `sub`; Vault binds them (`bound_claims`) so that only a valid workflow receives permission.

---

## 6.12. pre-commit hook — blocking on the developer's machine (shift-left to the extreme)

### 6.12.1. Mechanism

Git supports **hooks**: scripts in `.git/hooks/` that run at certain events. `pre-commit` runs **before** a commit completes; if the hook returns a non-zero exit code, the commit is aborted. The `pre-commit` framework (Python) manages multiple hooks through a single declaration file and automatically installs an environment for each hook.

This is the furthest-left shift-left point: it catches secrets/defects **before** the code ever leaves the developer's machine — the secret never enters the git history (because once committed and pushed, a secret is considered exposed and must be rotated).

### 6.12.2. `.pre-commit-config.yaml` example

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks            # block secrets before committing

  - repo: https://github.com/semgrep/semgrep   # the org renamed from returntocorp
    rev: v1.50.0                               # pin to the latest release when adopting (needs verification)
    hooks:
      - id: semgrep
        args: ["--config", "p/security-audit", "--error", "--skip-unknown-extensions"]

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key  # catch a PRIVATE KEY block
      - id: check-added-large-files
        args: ["--maxkb=500"]
```

Installation and usage:

```bash
pip install pre-commit
pre-commit install            # write to .git/hooks/pre-commit
pre-commit run --all-files    # try it on the whole repo

# When a developer commits:
git commit -m "feat: ..."
#  → gitleaks, semgrep run; if they fail, the commit is blocked
```

| Field | Meaning |
|---|---|
| `repos[].repo` | URL of the repo containing the hook definition |
| `repos[].rev` | Pinned tag/commit (ensures reproducibility, avoids unexpectedly pulling a new version) |
| `hooks[].id` | The specific hook within that repo |
| `hooks[].args` | Arguments passed to the hook |

### 6.12.3. Security considerations for pre-commit

- pre-commit is **not the only safeguard**: a developer can `git commit --no-verify` to bypass the hook. Therefore the checks must be **repeated** in CI (server-side) — that is the gate that cannot be bypassed.
- `rev` must be pinned to defend against supply-chain attacks via the hook (accidentally pulling a malicious version).
- pre-commit runs fast (only on staged files); leave heavy checks for CI.

---

## 6.13. Summary of the tiered defense architecture

| Insertion point | Representative tools | Type | Gate tier |
|---|---|---|---|
| IDE / pre-commit | Semgrep, Gitleaks | SAST, secret | Local (bypassable → must be repeated in CI) |
| CI build | Semgrep, Trivy fs/config, SCA | SAST, SCA, IaC | Blocking (CRITICAL) + Warning (HIGH) |
| Image build | Trivy image, cosign sign, SBOM | Container, signing, SBOM | Blocking on CRITICAL CVE |
| Pre-deploy | cosign verify, admission controller | Provenance/policy | Blocking if unsigned |
| Staging | OWASP ZAP (DAST) | DAST | Baseline on every PR, full scan before release |
| Runtime | WAF, EDR, SIEM | Monitoring/detection | Warn + block attacks |

The principle running throughout: **each tier has a blind spot, so stack the tiers to compensate for one another**; catch secrets as early as possible; only block the build on exploitable risks; every policy is code, versioned and reviewable.

---

## 6.14. Controlling AI-generated code — the three-layer model

### 6.14.1. The problem

Most developers today use an AI coding assistant daily (surveys put the figure at ~70%+ — needs verification). AI writes code fast, but it tends to suggest code that **runs but is not safe** — string-concatenated SQL, missing validation, missing authorization checks — because it optimizes for "it works" without holding the system's security context. Responsibility is clear enough: **the person who merges is responsible for the vulnerability, not the tool**. The most persuasive convention: treat AI output like code from a brand-new junior — useful, but mandatory to review, and never paste secrets/PII into a prompt.

Effective control is not banning AI (developers will use it covertly) but placing guardrails at **three layers** — before, during, and after the code is generated:

| Layer | Control | Concrete measures |
|---|---|---|
| **Input** (before the AI generates code) | Steer the AI from the start | An AI-assistant rules file in the repo (e.g. `CLAUDE.md`, `.cursor/rules`) stating concrete security rules: parameterized queries mandatory, authz checks mandatory, no hardcoded secrets. Semgrep custom rules banning the dangerous patterns AI tends to produce |
| **Process** (within the workflow) | Catch early on the dev machine and at the PR | pre-commit hooks running Semgrep + gitleaks (6.12); an automated AI security review commenting security issues on the PR; a mandatory PR security checklist (see [Chapter 7](#sec-07)) |
| **Output** (before production) | Non-negotiable gates | CI automatically fails by severity (Critical/High); **mandatory human review** for auth / payment / PII flows — do not delegate AI reviewing AI in those places; DAST on staging before going to production |

These three layers are really the shift-left pipeline of 6.1.3 applied to a new source of code: AI-generated code does not need its own pipeline, it needs to **go through the existing pipeline** plus the input layer (rules file) that human-written code does not have.

### 6.14.2. Slopsquatting — the AI-specific supply chain risk

A new risk arrived along with AI assistants: the AI **hallucinates package names that do not exist** when suggesting dependencies — and these invented names often repeat across sessions/models. Attackers collect the commonly hallucinated names and **pre-register** those packages on public registries (npm/PyPI) with malicious code; the developer trusts the AI's suggestion, runs `npm install`, and pulls the malware in with their own hands. The technique is called **slopsquatting** — a cousin of typosquatting and dependency confusion (6.10.1), except the "bait" is not a human typo but a name the AI made up.

Defenses:

- **Verify a package before installing it**: does it really exist, how many downloads, does the source repo exist — especially for AI-suggested names you have never heard of.
- Lockfile + SCA scanning (Trivy) in CI to catch strange/malicious packages as soon as they enter the dependency tree.
- Put it in the AI rules file: only use dependencies already in the lockfile; adding a new one must be called out explicitly and left for a human to decide.

---

## Appendix A — OWASP ZAP (DAST) runnable example

ZAP (Zed Attack Proxy) is OWASP's open-source DAST tool (see also [Chapter 12](#sec-12)). It ships with two packaged scan modes:

```bash
# Baseline scan: passive (spider + response analysis), NO active attacks.
# Fast, safe for CI, ~1-2 minutes.
docker run --rm -v "$PWD:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy zap-baseline.py \
  -t https://app.staging.company.com -r baseline-report.html

# Full scan: active attack (sends real XSS/SQLi payloads) — slow, use on staging.
docker run --rm -v "$PWD:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy zap-full-scan.py \
  -t https://app.staging.company.com -r full-report.html
```

| Parameter | Meaning |
|---|---|
| `-t` | Target URL |
| `-r` | HTML report file |
| `-J` | JSON report (parsed by CI) |
| `-c` | Rule config file (set WARN/FAIL/IGNORE per alert) |
| `-I` | Do not return a failing exit on warnings (for a warning gate) |

Baseline vs. full mechanism: **baseline** only spiders and **passively** analyzes responses (missing headers, cookies without `Secure/HttpOnly`), so it is harmless — suitable as a CI gate on every PR. **Full** actually **fires attack payloads** at parameters, which can create junk data / trigger side effects — run it only on staging with disposable data, never on production. This is why the two modes are split, mirroring the tiered gate principle in 6.9.


---

## My notes

> *Personal notes: points I previously misunderstood, areas I'm still exploring, or lessons from hands-on practice — updated over time.*

- I am currently the only security person at a small company, and the biggest lesson of this chapter once it met reality: **automation + guardrails are the only way one person scales**. One person cannot sit and review every PR — if the operating model is "everything goes through SecOps," it will certainly bottleneck, and that is a signal to fix the model, not to work more hours. My job is to make "doing it right" the easiest path: rules already running in the pipeline, automatic gates, developers getting feedback within minutes without me being online.
- A lesson about picking the starting point: I did not build the whole pipeline at once — I chose **gitleaks first** as the quick win. Reasons: secret leaks are the clearest class of defect (almost no false positives, nothing to argue about), deployment is fast (one pre-commit hook + one CI job), and the value shows in the first week. Once the first "win" is acknowledged by the team, adding Semgrep and Trivy later is much easier — rollout order is a political decision, not just a technical one.
- Something I got wrong: I assumed the stricter the gate, the safer. In reality, when I tried blocking builds even on noisy findings, the developers' reaction was not to fix everything but to find a way around — `--no-verify`, endless exception requests — and to lose trust in the pipeline. That is when the tiering table in 6.9 truly sank in: a gate is only credible when every time it turns red, people believe something real happened. The number of exception requests per week is now the metric I use to gauge whether the gate threshold is set right.
- Still exploring: feeding EPSS/KEV into the CVE triage flow automatically instead of looking things up by hand, and writing more Semgrep custom rules for internal patterns (along the lines of "every new endpoint must have an authorization guard") — a few well-placed rules are catching more real bugs than the community rulesets.
