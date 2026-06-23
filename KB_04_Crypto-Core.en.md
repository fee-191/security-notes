# Chapter 4 — Cryptography & Security Foundations

## Overview

**Cryptography** is the science of protecting information through three core capabilities: keeping secrets, guaranteeing integrity, and proving origin. Every transaction on the Internet (logging in, transferring money, messaging, shopping) relies on cryptographic primitives to defend against eavesdropping, tampering, and forgery. This chapter presents each primitive in sequence: **concept → mechanism → example → security notes**.

**Three foundational goals (CIA, AAA, Non-repudiation):**

- **CIA** — the three security objectives: **Confidentiality** (secrecy — only authorized parties may read), **Integrity** (data is not modified without authorization), **Availability** (accessible when needed). Every tool choice must clearly identify which property is being protected.
- **AAA** — three questions about a subject: **Authentication** ("who are you"), **Authorization** ("what are you allowed to do"), **Accounting** (logging — "what did you do").
- **Non-repudiation** — a subject cannot deny an action it performed. Achievable only through digital signatures with a private key.

**Distinguishing Encoding — Hashing — Encryption:**

- **Encoding** (e.g., Base64) — merely changes how data is represented; reversible without a key, **provides no security**. Base64-ing a password is a common mistake.
- **Hashing** — produces a fixed-length fingerprint, **one-way and irreversible**. Used for integrity checks and password storage.
- **Encryption** — locks data with a secret key, reversible only with the key. This is the only primitive that guarantees confidentiality.

**Symmetric encryption** — one key for both encryption and decryption; **AES** + **AEAD** (see 4.3).

**Asymmetric encryption** — a **key pair** (public/private) for key exchange; **RSA**, **ECC**, **DH/ECDHE** (see 4.4).

**Cryptographic hash functions** — a fixed-length, one-way fingerprint with the **avalanche** effect; **SHA-256/SHA-3**, **MD5/SHA-1 are broken** (see 4.5).

**Password storage** — never store in plaintext and never use a fast hash (too fast). Use a function that is **deliberately slow and memory-hard** (**Argon2**, **bcrypt**, **scrypt**) together with a **salt** (random and unique per user) and a **pepper** (a shared secret stored separately).

**HMAC** — uses a shared secret key to authenticate message integrity and origin. Applications: JWT, webhook signatures, signing API requests.

**Digital signatures** — sign with a **private key**, verify with a **public key**; simultaneously guarantee integrity, authentication, and non-repudiation. The roles of the key pair are reversed relative to asymmetric encryption.

**PKI & X.509** — a certificate system that guarantees a public key belongs to the correct subject. A **CA (Certificate Authority)** signs to vouch for an **X.509 certificate**; **revocation** mechanisms (CRL, OCSP) invalidate compromised or mis-issued certificates. This is the foundation of HTTPS.

**Risk model** — four concepts to distinguish: **Vulnerability** (a weakness), **Threat** (a threat actor), **Exploit** (a tool that takes advantage), **Risk** (= Likelihood × Impact). Identification uses **CVE** (a specific vulnerability), **CWE** (a general weakness type), **CVSS** (a 0–10 scale).

**Design principles** — including **Least Privilege**, **Defense in Depth**, **Zero Trust**, and especially **Kerckhoffs's principle**: a system must remain secure even when an adversary knows the entire mechanism, as long as the key is kept secret. This is why AES, RSA, and SHA-256 are all open standards.

> A technical reference for security engineers (Blue Team / AppSec / DevSecOps). Each section progresses from concept → internal mechanism (at the bit/byte/step level) → runnable real-world example → security notes. The technical figures follow NIST FIPS / RFC; anything requiring further verification is noted explicitly.

---

## 4.1. Foundational conceptual framework: CIA, AAA, Non-repudiation

### 4.1.1. The CIA triad

Every cryptographic decision serves one of the three goals of the CIA triad. Knowing clearly "which property is being protected" helps select the right cryptographic primitive.

| Property | Protective question | Typical cryptographic primitive | Lost when |
|---|---|---|---|
| Confidentiality | "Who may read?" | Encryption (AES-GCM, ChaCha20, RSA-OAEP) | Eavesdropping, key leak, ECB pattern |
| Integrity | "Has the data been modified?" | Hash, HMAC, AEAD tag, digital signature | Bit-flip, MITM tampering |
| Availability | "Is it accessible when needed?" | Not a pure cryptographic problem (DoS, backup, ransomware) | DDoS, ransomware encrypting data |

A common confusion: **encryption does NOT guarantee integrity**. AES-CBC keeps a secret, but an attacker can still flip ciphertext bits to manipulate the plaintext (bit-flipping). That is why, in practice, **AEAD** (Authenticated Encryption with Associated Data) is used to combine both C and I.

### 4.1.2. AAA — Authentication, Authorization, Accounting

| A | Definition | "Who you are / what you may do / what you did" | Technical example |
|---|---|---|---|
| Authentication | Verifying identity | "Who are you?" | Password + bcrypt, MFA TOTP, client cert mTLS |
| Authorization | Granting permissions | "What may you do?" | RBAC, ABAC, OAuth scopes, IAM policy |
| Accounting (Auditing) | Recording behavior | "What did you do?" | Audit log, SIEM, CloudTrail |

Note the distinction **Authentication ≠ Authorization**: a valid JWT proves *who you are* (authn), but the `scope`/`role` claim inside it determines *what you can do* (authz). The common IDOR/BOLA flaw is correct authn but missing authz.

### 4.1.3. Non-repudiation

Non-repudiation = "I cannot deny that I did it." Achievable only through a **digital signature with a private key** that only the subject possesses.

- HMAC does **not** provide non-repudiation: both sender and receiver know the shared secret key → the receiver could forge the message themselves → it cannot be proven to a third party.
- An RSA/ECDSA signature **does** provide non-repudiation: only the private-key holder can sign, while anyone can verify with the public key.

---

## 4.2. Three frequently confused concepts: Encoding vs Hashing vs Encryption

| Criterion | Encoding | Hashing | Encryption |
|---|---|---|---|
| Purpose | Represent data for transport/storage | Integrity, fingerprint, password storage | Confidentiality |
| Needs a key? | No | No (HMAC does) | Yes |
| Reversible? | Yes, anyone can reverse it | NO (one-way) | Yes, if you have the key |
| Fixed-length output? | No | Yes (SHA-256 is always 256-bit) | No (roughly the input length) |
| Examples | Base64, URL-encode, hex, ASCII | SHA-256, SHA-3, bcrypt | AES, RSA, ChaCha20 |

**A fatal mistake:** "I Base64-encoded the password to keep it safe." Base64 is NOT encryption — there is no key, and it is reversed instantly.

```bash
# Base64 provides no security whatsoever:
$ echo -n 'P@ssw0rd' | base64
UEBzc3cwcmQ=
$ echo -n 'UEBzc3cwcmQ=' | base64 -d
P@ssw0rd     # decoded immediately, no key required
```

The Base64 mechanism (RFC 4648): group **3 input bytes (24 bits)** → split into **4 groups of 6 bits** → each 6-bit group (0–63) indexes a table of 64 characters `A-Za-z0-9+/`. Missing bytes are padded with `=`. Because 6 bits does not divide evenly into a byte, the output is ~33% longer than the input.

```
Input :  P        @        s          (3 bytes = 24 bits)
ASCII : 0x50     0x40     0x73
bits  : 01010000 01000000 01110011
split6: 010100 000100 000001 110011
value :   20      4       1     51
base64:   U       E       B     z
```

---

## 4.3. Symmetric encryption: AES (Advanced Encryption Standard)

### 4.3.1. Overview and design rationale

AES is the FIPS 197 standard, based on the **Rijndael** algorithm. It is a **block cipher**: it processes data in fixed **128-bit (16-byte)** blocks. The key supports 3 lengths → with corresponding round counts:

| Variant | Key size | Rounds (Nr) | Key words (Nk) |
|---|---|---|---|
| AES-128 | 128-bit (16 bytes) | 10 | 4 |
| AES-192 | 192-bit (24 bytes) | 12 | 6 |
| AES-256 | 256-bit (32 bytes) | 14 | 8 |

The block is always 128 bits regardless of key size (Nb = 4 words = 128 bits). The block is represented as a **state** — a 4×4 byte matrix, filled column by column (column-major):

```
input bytes b0..b15  →  state:
            col0 col1 col2 col3
row0       b0   b4   b8   b12
row1       b1   b5   b9   b13
row2       b2   b6   b10  b14
row3       b3   b7   b11  b15
```

### 4.3.2. The four transformations in each round

Each round (except the final one, which omits MixColumns) consists of 4 steps on the 4×4 state:

**1. SubBytes** — a nonlinear substitution of each byte through an **S-box** (256 entries). The S-box = the inverse in the Galois field GF(2⁸) (irreducible polynomial `0x11B`) followed by an affine transform. Purpose: create **confusion** (a complex key↔ciphertext relationship), resisting linear/differential attacks.

For the GF(2⁸) math here you only need the **idea**: each byte is "scrambled" through a fixed lookup table so the input-output relationship is nonlinear and hard to analyze. In practice the S-box is a precomputed table, so you never have to compute it yourself.

```
byte 0x53 → S-box[0x53] = 0xED
(look up row 0x5, column 0x3 in the 16×16 table)
```

**2. ShiftRows** — a cyclic left shift of each row: row 0 shifts 0, row 1 shifts 1, row 2 shifts 2, row 3 shifts 3 bytes. Purpose: **diffusion** across columns.

```
before:         after ShiftRows:
b0 b4 b8 b12    b0  b4  b8  b12   (shift 0)
b1 b5 b9 b13    b5  b9  b13 b1    (shift 1)
b2 b6 b10 b14   b10 b14 b2  b6    (shift 2)
b3 b7 b11 b15   b15 b3  b7  b11   (shift 3)
```

**3. MixColumns** — each column is multiplied by a fixed matrix in GF(2⁸):

```
| 02 03 01 01 |   | s0 |
| 01 02 03 01 | x | s1 |
| 01 01 02 03 |   | s2 |
| 03 01 01 02 |   | s3 |
```

Purpose: **diffusion** — one input byte affects all 4 output bytes of the column. (The final round omits this step because it adds no security, only cost, and to make decryption symmetric.) The matrix multiplication in GF(2⁸) looks heavy, but grasping the **idea** — "stir together the bytes within a single column" — is enough; the arithmetic detail is only for those implementing the algorithm.

**4. AddRoundKey** — XOR the state with the round's 128-bit round key. This is the only step that introduces the key. Round keys are generated from the **key schedule** (Rijndael key expansion) using RotWord, SubWord, Rcon.

The full AES-128 sequence (10 rounds):
```
AddRoundKey(K0)                      # pre-whitening
for r = 1..9:
    SubBytes → ShiftRows → MixColumns → AddRoundKey(Kr)
round 10:
    SubBytes → ShiftRows → AddRoundKey(K10)   # NO MixColumns
```

**Why 10/12/14 rounds?** A longer key needs more rounds to achieve sufficient confusion/diffusion against related-key attacks and statistical distinguishing.

### 4.3.3. Modes of Operation

A block cipher only encrypts a single 16-byte block. To encrypt longer data, a **mode** is needed.

| Mode | Needs IV/Nonce | Parallelizable | Integrity? | Issue |
|---|---|---|---|---|
| ECB | No | Yes | No | Leaks patterns |
| CBC | 16-byte IV (random, unpredictable) | Encrypt: no / Decrypt: yes | No | Padding oracle, bit-flip |
| CTR | Nonce + counter | Yes | No | Nonce reuse = disaster |
| GCM | 96-bit nonce recommended | Yes | YES (128-bit tag) | Nonce reuse breaks everything |

**ECB — why does it leak patterns?** Identical plaintext blocks → identical ciphertext blocks (`Ci = E(K, Pi)`). An ECB-encrypted image reveals outlines because uniform color regions become identical blocks.

```
ECB:  C1=E(P1)  C2=E(P2)  C3=E(P3)   # same P → same C
```

**CBC** — XORs the previous block into the current one to achieve diffusion:
```
C0 = E(K, P0 XOR IV)
Ci = E(K, Pi XOR C(i-1))
```
The IV must be **random and unpredictable** (16 bytes), otherwise it is vulnerable to chosen-plaintext attacks (see TLS 1.0 BEAST).

**CTR** — turns a block cipher into a stream cipher: encrypt a counter, then XOR with the plaintext:
```
Ci = Pi XOR E(K, nonce || counter_i)
```
If the (key, nonce) pair is reused, two ciphertexts XOR away the keystream → revealing `P1 XOR P2`.

**GCM** = CTR (confidentiality) + GHASH (integrity). It generates a **128-bit authentication tag** over the ciphertext + AAD. The recommended nonce is **96 bits (12 bytes)**. AAD (Associated Data) is authenticated but not encrypted (e.g., a packet header). Nonce reuse in GCM additionally leaks the authentication key H → enabling forgery.

### 4.3.4. A real-world example with OpenSSL

```bash
# Generate a 256-bit (32-byte) key and a 128-bit (16-byte) IV in hex
$ KEY=$(openssl rand -hex 32)   # 64 hex chars = 32 bytes
$ IV=$(openssl rand -hex 16)    # 32 hex chars = 16 bytes

# Encrypt with AES-256-CBC
$ echo -n "Secret message" > pt.txt
$ openssl enc -aes-256-cbc -K $KEY -iv $IV -in pt.txt -out ct.bin
$ xxd ct.bin
00000000: 8d2a 1f... (16 bytes, since input <16 → padded with PKCS#7 up to one block)

# Decrypt
$ openssl enc -d -aes-256-cbc -K $KEY -iv $IV -in ct.bin
Secret message
```

Parameter explanation: `enc` = symmetric encryption; `-aes-256-cbc` = algorithm+keysize+mode; `-K` = hex key (capital K, uses a raw key — unlike lowercase `-k`, which is a passphrase passed through a KDF); `-iv` = hex IV; `-d` = decrypt.

AEAD with GCM (Python, the `cryptography` library):
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key   = AESGCM.generate_key(bit_length=256)   # 32 bytes
nonce = os.urandom(12)                          # 96-bit nonce
aad   = b"header-v1"                            # authenticated, not encrypted
aesgcm = AESGCM(key)

ct = aesgcm.encrypt(nonce, b"top secret", aad)  # ct = ciphertext || tag(16B)
print(len(ct))   # = 10 (plaintext) + 16 (tag) = 26

pt = aesgcm.decrypt(nonce, ct, aad)  # raises InvalidTag if ct/aad/nonce is modified
```

**AES security notes:**
- Always prefer **AES-GCM** or **ChaCha20-Poly1305** (AEAD), not bare CBC.
- **Never reuse a nonce** with the same key in GCM/CTR.
- Do not implement the algorithm yourself; use vetted libraries (libsodium, BoringSSL).
- ECB should only be used for single-block random data (almost never the case in practice).

---

## 4.4. Asymmetric encryption: RSA, ECC, DH/ECDHE

### 4.4.1. RSA — step by step mathematics

RSA is based on the difficulty of **prime factorization** of large numbers.

**Key generation:**

| Symbol | Meaning | Illustrative example (small numbers for clarity) |
|---|---|---|
| p, q | Two large secret primes | p=61, q=53 |
| n = p·q | Modulus (public), 2048/4096-bit | n=3233 |
| φ(n)=(p-1)(q-1) | Euler's totient function, secret | 60·52=3120 |
| e | Public exponent, gcd(e,φ)=1, usually 65537 | e=17 |
| d ≡ e⁻¹ mod φ(n) | Private exponent, secret | d=2753 |

- Public key = (n, e); Private key = (n, d).
- **Encryption:** `c = m^e mod n`
- **Decryption:** `m = c^d mod n`

With the example: m=65 → c = 65¹⁷ mod 3233 = 2790 → m = 2790²⁷⁵³ mod 3233 = 65.

**Why 65537 (0x10001)?** It is the Fermat number F₄, with binary form `10000000000000001` having only 2 set bits → fast exponentiation (only 17 squarings + 1 multiplication) yet large enough to avoid small-e attacks (e=3 is prone to Coppersmith/broadcast attacks).

**Mandatory padding:** "textbook" RSA (no padding) is extremely insecure (deterministic, malleable). Use:
- **OAEP** for encryption (RSAES-OAEP).
- **PSS** for signatures (RSASSA-PSS).

Key length: 2048-bit is the current minimum; 3072/4096-bit for the long term. RSA-1024 is now considered weak.

```bash
# Generate a 4096-bit RSA key pair
$ openssl genrsa -out priv.pem 4096
$ openssl rsa -in priv.pem -pubout -out pub.pem

# Inspect key details (modulus, exponent)
$ openssl rsa -in priv.pem -text -noout | head
Private-Key: (4096 bit, 2 primes)
modulus: 00:c3:a1:...        # n
publicExponent: 65537 (0x10001)
privateExponent: ...          # d
prime1: ... prime2: ...        # p, q

# Encrypt a small file with OAEP (RSA can only encrypt ≤ keysize - padding)
$ echo -n "session-key-material" | \
  openssl pkeyutl -encrypt -pubin -inkey pub.pem \
  -pkeyopt rsa_padding_mode:oaep -out enc.bin
$ openssl pkeyutl -decrypt -inkey priv.pem \
  -pkeyopt rsa_padding_mode:oaep -in enc.bin
session-key-material
```

RSA can only encrypt data smaller than the modulus → in practice **hybrid encryption** is used: RSA encrypts a random AES key, and AES encrypts the large data.

```
Hybrid encryption diagram:

Sender                                               Recipient
──────                                               ─────────
data (large) ─┐
              │
   K_sym ─────┼──► AES-GCM(K_sym, data) ─► ciphertext ────────► AES-GCM decrypt ─► data
  (random)    │                                                       ▲
              │                                                       │ K_sym
              └──► RSA-OAEP(pub, K_sym) ─► enc_key ──────────► RSA decrypt (priv)
                   (asymmetric key exchange)         (symmetric encrypts bulk data)
```

Asymmetric crypto (RSA/ECDH) only handles secure **session-key exchange**; the symmetric key (AES) carries the bulk-data encryption because it is much faster. This is precisely the model TLS uses for every HTTPS session.

### 4.4.2. ECC — Elliptic Curve Cryptography

ECC is based on the difficulty of the **elliptic curve discrete logarithm problem (ECDLP)**. Its advantage: much shorter keys at the same security level.

| Equivalent security level | RSA | ECC |
|---|---|---|
| ~128-bit | 3072-bit | 256-bit (P-256, Curve25519) |
| ~192-bit | 7680-bit | 384-bit (P-384) |
| ~256-bit | 15360-bit | 521-bit (P-521) |

A Weierstrass-form curve: `y² = x³ + ax + b mod p`. The basic operations are **point addition** and **scalar multiplication** `Q = k·G` (G is the generator point, k is the private key, Q is the public key). It is secure because recovering k from Q and G is hard.

Common curves: NIST P-256 (secp256r1), **Curve25519** (X25519 for ECDH, Ed25519 for signatures) — Curve25519 is favored for its design that resists implementation flaws and has no suspect parameters that could hide a backdoor.

```bash
# Generate an Ed25519 key (signing) — example modern SSH key
$ ssh-keygen -t ed25519 -C "ops@example.com" -f id_ed25519
# The public key is only ~68 chars, with ~128-bit security
```

### 4.4.3. Diffie-Hellman & ECDHE — Forward Secrecy

**DH** lets two parties agree on a shared key over a public channel without transmitting the key.

```
Public: prime p, generator g
Alice: chooses secret a → sends A = g^a mod p
Bob  : chooses secret b → sends B = g^b mod p
Shared key: Alice computes B^a = g^(ab); Bob computes A^b = g^(ab)  → EQUAL
An eavesdropper sees g, p, A, B but cannot compute g^(ab) (the DLP problem)
```

**ECDHE** = DH over an elliptic curve, **ephemeral** (a temporary key per session). The trailing "E" (ephemeral) is the key to **Forward Secrecy (PFS)**:

> If the server's long-term private key is leaked in the future, sessions recorded in the past **cannot** be decrypted, because the session key used the ephemeral ECDHE pair that has since been destroyed.

This is why TLS 1.3 **mandates** the use of ephemeral (EC)DHE, completely removing static RSA key exchange (which lacks forward secrecy — a leaked server private key can decrypt every previously recorded session).

---

## 4.5. Cryptographic hash functions

### 4.5.1. Required properties

| Property | Definition | Consequence if broken |
|---|---|---|
| Pre-image resistance | Given h, hard to find m such that H(m)=h | Reverse the hash |
| Second pre-image | Given m1, hard to find m2≠m1 with the same hash | Targeted forgery |
| Collision resistance | Hard to find any m1≠m2 with the same hash | Forged certificates (MD5/SHA-1 broken) |
| Avalanche effect | Changing 1 input bit → ~50% of output bits change | — |

### 4.5.2. SHA-256 — the Merkle–Damgård structure

| Parameter | Value |
|---|---|
| Output size | 256 bits (32 bytes) |
| Block size | 512 bits (64 bytes) |
| Word size | 32 bits |
| Compression rounds | 64 |
| Initial H constants | 8 words (from the square roots of the first 8 primes) |
| K constants | 64 words (from the cube roots of the first 64 primes) |

**Process (Merkle–Damgård):**
1. **Padding:** append a `1` bit, then `0` bits, so the length ≡ 448 mod 512, then the final 64 bits record the **original message length** (big-endian). The total is a multiple of 512.
2. Split into 512-bit blocks.
3. For each block: expand 16 words → 64 words (the message schedule W), run 64 compression rounds updating the 8 working variables a–h with the Σ, σ, Ch, Maj functions.
4. Add into the intermediate hash (chaining); the final block yields the digest.

```
[H0..H7 init] → compress(block1) → compress(block2) → ... → 256-bit digest
                     ↑ chaining value fed into the next block
```

You don't need to memorize each Σ/σ/Ch/Maj function — grasping the **idea** is enough: split the message into blocks, "compress" each block in turn into a state value carried to the next block, and the final block yields the digest.

```bash
$ echo -n "abc" | sha256sum
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -
# always 64 hex chars = 256 bits, regardless of input length
$ echo -n "abd" | sha256sum   # change 1 char → completely different digest (avalanche)
a52d159f262b2c6ddb724a61840befc36eb30c88877a4030b65cbe86298449c9  -
```

**Length-extension vulnerability:** because Merkle–Damgård exposes the intermediate state as the digest, an attacker who knows `H(secret||msg)` and the secret's length can compute `H(secret||msg||padding||extra)` without knowing the secret. This is why you should **not use `H(secret||message)` as a MAC** — you must use HMAC. (SHA-3 is immune thanks to its sponge structure.)

### 4.5.3. SHA-3 (Keccak) — the Sponge structure

SHA-3 (FIPS 202) uses a **sponge** structure entirely different from Merkle–Damgård:
- A 1600-bit state, split into **rate (r)** + **capacity (c)**.
- The **absorb** phase: XOR a block into the rate portion, then apply the Keccak-f permutation.
- The **squeeze** phase: take output from the rate portion.
- Immune to length-extension. It also has the SHAKE128/256 variants (XOF — output of arbitrary length).

SHA-3 is an architectural backup for SHA-2, **not** because SHA-2 has become weak — SHA-2 remains secure today. Having two function families with entirely different structures diversifies risk: if Merkle–Damgård is ever attacked, we still have the sponge to switch to.

### 4.5.4. Why MD5 and SHA-1 are retired

| Function | Output | Status | Evidence |
|---|---|---|---|
| MD5 | 128-bit | COMPLETELY BROKEN | Collisions produced in seconds; forged CA certificate (Flame malware 2012) |
| SHA-1 | 160-bit | BROKEN | SHAttered (2017, Google): two different PDFs with the same SHA-1; Git has been migrating to SHA-256 |
| SHA-256/SHA-3 | 256-bit | Secure | Current recommendation |

MD5/SHA-1 are now acceptable only for **non-security checksums** (detecting random transmission errors), and must never be used for signatures, certificates, or password storage.

---

## 4.6. Secure password storage

### 4.6.1. Why not a plain hash

A plain hash (SHA-256) is **too fast** → GPUs try billions of candidates per second (brute-force, rainbow tables). You need a function that is **deliberately slow** and **salted**.

| Concept | Definition | Protects against |
|---|---|---|
| Salt | A random string unique per user, stored alongside the hash | Rainbow tables, duplicate hashes |
| Pepper | A shared secret (HSM/environment variable), NOT stored alongside the DB | A full DB leak is still safe if the pepper is not leaked |
| Work factor / cost | A parameter that slows the function down (iterations, RAM) | GPU/ASIC brute-force |

### 4.6.2. bcrypt — detailed format

bcrypt produces a **60-character** string with the structure:

```
$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
└┬┘└┬┘ └───────────────────┬──────────────────────────────┘
 │  │                       │
 │  │   salt(22 chars,128-bit) + hash(31 chars,184-bit) — bcrypt base64
 │  └─ cost = 12 → 2^12 = 4096 key-setup rounds
 └─ algo version: $2b$ (modern variant)
```

| Field | Size | Meaning | Example |
|---|---|---|---|
| Prefix | 4 chars | Version | `$2b$` |
| Cost | 2 chars | log2(number of rounds) | `12` |
| Salt | 22 chars (128-bit) | base64 salt | `R9h/cIPz0gi.URNNX3kh2O` |
| Hash | 31 chars (184-bit) | Digest | `PST9/...MUW` |

Limitation: bcrypt truncates input at **72 bytes**. Increasing cost by 1 doubles the time.

```python
import bcrypt
pw = b"P@ssw0rd"
hashed = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12))
# b'$2b$12$....'  — the salt is embedded in the string, no need to store it separately
assert bcrypt.checkpw(pw, hashed)   # True
```

### 4.6.3. scrypt & Argon2

- **scrypt:** adds **memory-hard** parameters (N, r, p) → it costs RAM, defeating ASICs/GPUs that are weak on memory.
- **Argon2** (winner of the 2015 Password Hashing Competition): the current recommended standard.
  - **Argon2id** (hybrid, the recommended default), Argon2i (side-channel resistant), Argon2d (GPU resistant).
  - Parameters: `m` (memory in KiB), `t` (iterations/time), `p` (parallelism).

```
$argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<hash-b64>
         │     │     │    │  │
         │     │     │    │  └ parallelism=4 threads
         │     │     │    └ iterations=3
         │     │     └ memory=65536 KiB (64 MiB)
         │     └ version 0x13 (19)
         └ the id variant
```

```bash
# argon2 CLI
$ echo -n "P@ssw0rd" | argon2 mysalt1234 -id -t 3 -m 16 -p 4
Encoded: $argon2id$v=19$m=65536,t=3,p=4$bXlzYWx0MTIzNA$...
```

**Notes:** use Argon2id for new systems; bcrypt is still acceptable; use PBKDF2 only when compliance requires it (FIPS). Store the pepper separately from the DB (KMS/HSM). Always compare hashes with a **constant-time** function to defend against timing attacks.

---

## 4.7. HMAC — Hash-based Message Authentication Code

HMAC proves **integrity + origin authentication** using a shared key. The formula (RFC 2104):

```
HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )

K'   = the key padded/hashed to exactly the block size of H (SHA-256: 64 bytes)
ipad = the byte 0x36 repeated (block-size times)
opad = the byte 0x5c repeated (block-size times)
```

**Why two layers (inner+outer) and ipad/opad?** The doubly-nested structure defends against the very length-extension attack described in section 4.5.2; with just `H(K||m)` it could be forged. ipad/opad are two different constants so the two hashing passes use "different" keys, increasing robustness.

```bash
$ echo -n "msg" | openssl dgst -sha256 -hmac "secretkey"
HMAC-SHA256(stdin)= 3f2a...   # change the key or msg → the MAC changes completely
```

```python
import hmac, hashlib
mac = hmac.new(b"secretkey", b"msg", hashlib.sha256).hexdigest()
# Verification MUST use compare_digest (constant-time) to resist timing attacks:
hmac.compare_digest(mac, received_mac)
```

Applications: JWT (HS256), API request signing (AWS SigV4), webhook signatures (GitHub `X-Hub-Signature-256`), TOTP/HOTP.

---

## 4.8. Digital signatures — step by step

Digital signatures guarantee **Integrity + Authentication + Non-repudiation**.

**Signing (sender, using the PRIVATE key):**
```
1. digest = H(message)                 # hash first, because RSA/ECDSA only sign small numbers
2. signature = Sign(privKey, digest)   # RSA-PSS: based on digest^d mod n
3. Send: message || signature
```

**Verifying (recipient, using the PUBLIC key):**
```
1. digest'  = H(message)               # re-hash the received message
2. valid    = Verify(pubKey, signature, digest')
3. valid==true ↔ the message was not modified AND was signed by the private-key holder
```

Comparison with encryption: encryption uses the public key to encrypt (anyone can encrypt, only the owner decrypts); signing uses the **private key to sign** (only the owner can sign, anyone can verify) — the reverse direction.

```bash
# Sign a file
$ openssl dgst -sha256 -sign priv.pem -out sig.bin document.pdf
# Verify
$ openssl dgst -sha256 -verify pub.pem -signature sig.bin document.pdf
Verified OK
```

Algorithms: **RSA-PSS** (RSA), **ECDSA** (P-256), **Ed25519** (fast, secure, deterministic — it does not depend on the RNG when signing, avoiding nonce flaws like the Sony PS3 ECDSA 2010 case that used a fixed nonce and leaked the private key).

---

## 4.9. PKI & X.509

### 4.9.1. The chain of trust

```
Root CA (self-signed, in the OS/browser trust store)
   └── Intermediate CA (signed by the Root)
          └── Leaf/End-entity cert (signed by the Intermediate) — your server
```

A client trusts the Leaf because it can verify the signature chain up to a Root it already trusts. The server must send the full **chain** (leaf + intermediate), but does not need to send the root.

### 4.9.2. X.509 v3 certificate fields

| Field | Meaning | Example |
|---|---|---|
| Version | Version (v3 = 2) | v3 |
| Serial Number | A unique serial issued by the CA | `04:A2:...` |
| Signature Algorithm | The algorithm the CA signs with | `sha256WithRSAEncryption` / `ecdsa-with-SHA256` |
| Issuer | The DN of the issuing CA | `CN=R3, O=Let's Encrypt` |
| Validity (Not Before / Not After) | The validity window | 2026-01-01 → 2026-04-01 |
| Subject | The subject's DN | `CN=example.com` |
| Subject Public Key Info | Public key + algorithm | RSA 2048 / EC P-256 |
| **SAN** (Subject Alternative Name) | The list of valid hosts (MANDATORY, CN is deprecated) | `DNS:example.com, DNS:www.example.com` |
| Key Usage | The key's purpose | `Digital Signature, Key Encipherment` |
| Extended Key Usage | EKU | `TLS Web Server Authentication` |
| Basic Constraints | Whether it is a CA | `CA:FALSE` |
| Signature | The CA's signature over the entire TBSCertificate | — |

**Important:** modern browsers **ignore the CN** and only check the **SAN**. A certificate missing a SAN → the error `ERR_CERT_COMMON_NAME_INVALID`.

```bash
# View a server's certificate details
$ openssl s_client -connect example.com:443 -servername example.com </dev/null \
  | openssl x509 -noout -text

# Or quickly check the main fields
$ echo | openssl s_client -connect example.com:443 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
subject=CN=example.com
issuer=C=US, O=DigiCert Inc, CN=...
notBefore=...  notAfter=...
X509v3 Subject Alternative Name:
    DNS:example.com, DNS:www.example.com
```

```bash
# Create a CSR (Certificate Signing Request) with a SAN
$ openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out req.csr \
  -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com"
```

### 4.9.3. Revocation: CRL vs OCSP

| Mechanism | Description | Drawback |
|---|---|---|
| CRL (Certificate Revocation List) | The CA publishes a list of revoked serials; the client downloads it | Large file, slow updates |
| OCSP | The client queries the CA in real time about one specific cert | Reveals the user's browsing to the CA; latency |
| **OCSP Stapling** | The server fetches the OCSP response itself (CA-signed, timestamped) and "staples" it into the TLS handshake | Fixes OCSP's privacy + latency issues |

```bash
# Check OCSP stapling
$ openssl s_client -connect example.com:443 -status </dev/null 2>/dev/null \
  | grep -A2 "OCSP Response Status"
OCSP Response Status: successful (0x0)
    Cert Status: good
```

---

## 4.10. Risk model & vulnerability management

### 4.10.1. Four core concepts

| Term | Definition | Example |
|---|---|---|
| Vulnerability | A weakness in the system | SQLi, an unpatched library |
| Threat | An actor/event that could exploit a weakness | An attacker, a ransomware group |
| Exploit | A specific tool/technique that takes advantage of a vuln | A PoC RCE, a Metasploit module |
| Risk | The likelihood of harm = **Likelihood × Impact** | A vuln with a public exploit on a public server = high risk |

> **Risk = Likelihood × Impact.** A severe vuln (high impact) that is only exploitable from an isolated internal network (low likelihood) → lower risk than a medium-severity vuln on a public Internet endpoint.

### 4.10.2. CVE and CWE

- **CVE** (Common Vulnerabilities and Exposures): identifies **a specific vulnerability in a specific product**. The format is `CVE-YYYY-NNNNN` (e.g., `CVE-2021-44228` = Log4Shell).
- **CWE** (Common Weakness Enumeration): classifies a general **weakness type** (e.g., `CWE-79` = XSS, `CWE-89` = SQLi, `CWE-787` = Out-of-bounds Write). A CVE typically maps to one or more CWEs.

The relationship: CWE is the "disease type," CVE is the "specific case."

### 4.10.3. CVSS v3.1 — each metric of the Base Score

The CVSS Base score (0.0–10.0) is computed from 8 metrics in 2 groups:

**Exploitability metrics:**

| Metric | Values | Meaning |
|---|---|---|
| **AV** Attack Vector | Network(N) / Adjacent(A) / Local(L) / Physical(P) | Where it can be exploited from — N (over the Internet) is the most dangerous |
| **AC** Attack Complexity | Low(L) / High(H) | Whether special conditions are required |
| **PR** Privileges Required | None(N) / Low(L) / High(H) | What privileges are needed before exploiting |
| **UI** User Interaction | None(N) / Required(R) | Whether the victim needs to click/interact |

**Scope + Impact metrics:**

| Metric | Values | Meaning |
|---|---|---|
| **S** Scope | Unchanged(U) / Changed(C) | Whether the exploit reaches beyond the affected component (e.g., escaping a sandbox/VM) |
| **C** Confidentiality | None/Low/High | The degree of data exposure |
| **I** Integrity | None/Low/High | The degree of data modification |
| **A** Availability | None/Low/High | The degree of service disruption |

**Example vector string** (Log4Shell, score 10.0 Critical):
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
        │    │    │    │    │   │   │   │
        │    │    │    │    │   └───┴───┴── High impact across the board
        │    │    │    │    └ Scope Changed (beyond the component)
        │    │    │    └ no user interaction required
        │    │    └ no prior privileges required
        │    └ low complexity
        └ exploitable over the network
```

Qualitative thresholds: 0.0 None · 0.1–3.9 Low · 4.0–6.9 Medium · 7.0–8.9 High · 9.0–10.0 Critical.

> **Scope is the pivotal metric.** Unlike the other seven metrics, which each contribute to only one side, Scope affects **both Exploitability and Impact**: when `S:Changed`, the scoring formula shifts and the Impact ceiling is raised, so a single change in Scope can push the score up substantially. Assessing Scope accurately (whether the exploit reaches beyond the security authority of the affected component) is therefore a critical decision when scoring CVSS.

Beyond the Base score there are the **Temporal** group (exploit maturity, whether a patch exists) and the **Environmental** group (customized to the organization's environment). Note: CVSS v4.0 has been released (2023) with a changed metric structure — when deploying, verify which version is in use.

```bash
# Scan for vulns and map CVE/CVSS in CI (e.g., a container)
$ trivy image --severity HIGH,CRITICAL myapp:latest
myapp:latest (alpine 3.18)
Total: 2 (HIGH: 1, CRITICAL: 1)
┌──────────┬───────────────┬──────────┬───────────────┐
│ Library  │ Vulnerability │ Severity │ Fixed Version │
├──────────┼───────────────┼──────────┼───────────────┤
│ openssl  │ CVE-2023-xxxx │ CRITICAL │ 3.1.4-r0      │
└──────────┴───────────────┴──────────┴───────────────┘
```

---

## 4.11. Secure Design Principles

| Principle | Content | Practical application |
|---|---|---|
| Least Privilege | Grant the minimum privilege sufficient to function | Narrow IAM scope, non-root containers |
| Defense in Depth | Multiple independent layers of defense | WAF + input validation + parameterized query |
| Fail Securely | On error, default to denial | `deny by default`, exceptions that don't leak stack traces |
| Complete Mediation | Check permissions on every access | Don't cache stale authz decisions |
| Open Design (Kerckhoffs) | Safety rests on the KEY, not on hiding the algorithm | Use public AES, not a "secret algo" |
| Economy of Mechanism | As simple as possible | Less code = fewer bugs |
| Separation of Duties | Separate roles | The deployer ≠ the approver |
| Psychological Acceptability | Security doesn't get in the way excessively | SSO instead of 20 passwords |
| Zero Trust | "Never trust, always verify" | Authenticate every request, internal mTLS |
| Secure Defaults | Defaults are safe | TLS enabled by default, ports closed by default |

**Kerckhoffs's Principle** is the philosophical foundation of the whole chapter: a cryptosystem must remain secure even when everything about it (except the key) is public. This is why AES/RSA/SHA-256 are all open standards, publicly dissected — "security through obscurity" (hiding the algorithm) is not security.

---

## 4.12. Post-Quantum Cryptography & crypto-agility

### 4.12.1. Why quantum computers are a threat

All asymmetric cryptography in use today (see [Chapter 4](#sec-04) above, and PKI/TLS in [Chapter 1](#sec-01)) rests on two problems: integer factorization (RSA) and discrete logarithms (ECC, DH/ECDHE). **Shor's algorithm**, run on a sufficiently large quantum computer, solves both in polynomial time, breaking RSA and ECC fundamentally — not by requiring longer keys but by eliminating the very mathematical hardness they rely on.

Symmetric cryptography and hash functions are affected more mildly: **Grover's algorithm** only reduces security to the square root, so AES-256 retains roughly 128-bit security and SHA-256/SHA-384 remain usable. The remedy for the symmetric side is simply to increase key/digest length; the real burden lies with the asymmetric side.

### 4.12.2. Harvest-now, decrypt-later

The threat is not confined to the distant future: an attacker can **collect encrypted traffic today and decrypt it later** once a quantum computer becomes available (the "harvest-now, decrypt-later" model). ECDHE's forward secrecy (see 4.4.3) does **not** help here, because the ECDHE key exchange itself is broken by Shor.

The risk is proportional to the **lifetime over which a secret must stay protected**. For long-retained financial data — KYC records, transaction history, signing keys, contracts — data intercepted today is still sensitive when decrypted years later. This is why the financial sector should plan its PQC migration earlier rather than wait for quantum computers to arrive.

### 4.12.3. The NIST PQC 2024 standards

In August 2024 NIST published its first PQC standards, based on lattice problems (which Shor does not break):

| Standard | Algorithm | Role |
|---|---|---|
| **FIPS 203** | **ML-KEM** (formerly CRYSTALS-Kyber) | Key encapsulation — key exchange, replacing ECDHE/RSA key exchange |
| **FIPS 204** | **ML-DSA** (formerly CRYSTALS-Dilithium) | Digital signatures — replacing RSA-PSS/ECDSA |
| **FIPS 205** | **SLH-DSA** (formerly SPHINCS+) | Hash-based signatures, serving as a risk-diversifying fallback |

ML-KEM is a **KEM** (Key Encapsulation Mechanism), not a direct encryption scheme: it produces a shared symmetric session key, after which data is still encrypted with AEAD (see [Chapter 11](#sec-11)) — the same hybrid model as RSA/ECDH exchanging a key for AES in 4.4.1.

### 4.12.4. Hybrid key exchange

Because the PQC algorithms are still relatively new, the current deployment practice is **hybrid** (classical + post-quantum): combine a thoroughly vetted algorithm with a PQC one, so the session key is exposed only if **both** are broken.

For example, in TLS 1.3 the key group **X25519MLKEM768** pairs X25519 (classical) with ML-KEM-768 (post-quantum): client and server derive a shared secret from both exchanges and concatenate them as input to the key schedule. If ML-KEM is later found to have an implementation weakness, X25519 still holds at the classical level; conversely, if a quantum computer breaks X25519, ML-KEM still stands. Browsers and several large CDNs already enable this configuration by default.

### 4.12.5. Crypto-agility

**Crypto-agility** is the ability to design a system so that you can **swap cryptographic algorithms without rewriting the architecture**. The PQC migration will span years and may recur (if a PQC standard reveals a weakness), so agility is an operational requirement, not just a technical detail:

- **Do not hard-code algorithms/key lengths** scattered throughout the code; centralize them in an abstraction layer or configuration.
- **Declare the algorithm explicitly** in the data format (an algorithm identifier alongside the ciphertext/signature) so the decrypting side knows how to process it and rotation is easy.
- **Inventory every place cryptography is used** — libraries, certificates, protocols, hardware — so you know the scope to change when standards shift.
- Prefer **hybrid** during the transition to reduce the risk of betting on a single PQC algorithm.

The overarching principle is still Kerckhoffs (see 4.11): security rests on the key and on the ability to rotate quickly, not on any single algorithm remaining unchanged forever.

---

## 4.13. Summary decision map

| What you need | What to use |
|---|---|
| Confidentiality of large data volumes | AES-256-GCM / ChaCha20-Poly1305 (AEAD) |
| Key exchange over an open channel | ECDHE (forward secrecy) |
| Encrypting a key / small asymmetric data | RSA-OAEP 3072+ or ECIES |
| Integrity + authentication with a shared key | HMAC-SHA256 |
| Integrity + authentication + non-repudiation | Digital signature Ed25519 / ECDSA / RSA-PSS |
| Secure fingerprint / checksum | SHA-256 / SHA-3 |
| Password storage | Argon2id (or bcrypt) + salt + pepper |
| Server identity on the Internet | X.509 + TLS 1.3 + OCSP stapling |

The overarching rule: **do not implement cryptographic primitives yourself**, use vetted libraries (libsodium, BoringSSL, Go crypto, Python `cryptography`), follow Kerckhoffs, prefer AEAD and forward secrecy, and always ask "which CIA property is being protected?" before choosing a tool.


---

## My notes

> *Personal notes: points I previously misunderstood, areas I'm still exploring, or lessons from hands-on practice — updated over time.*
