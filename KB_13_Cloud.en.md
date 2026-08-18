# Chapter 13 — Cloud Security

## Overview

I picked up this cloud security material for a very practical reason: the infrastructure I run spans both AWS and OCI, and sooner or later GCP comes into the picture too when working with partners who run on it. Reading through real-world breach reports, one pattern keeps repeating: it's almost never the provider getting hacked — it's the customer misconfiguring something, a bucket left public, a security group with an admin port opened by mistake, an IMDSv1 nobody bothered to disable. So the first question this chapter needs to answer isn't "is the cloud safe," it's "out of this whole stack, which part is actually my job."

The chapter starts right at that boundary: the IaaS/PaaS/SaaS models and the Shared Responsibility Model, which spell out who patches which layer and kill the "the provider handles everything once we move to the cloud" assumption. From there it moves into the pieces you actually have to manage yourself — IAM and least privilege, VPCs with Security Groups and Network ACLs, the services most likely to bite you in practice like S3 and KMS, the observability layer of CloudTrail/CloudWatch/GuardDuty, and IMDS, a classic SSRF target if you're still running v1. Organizations and SCPs close out this half by locking down guardrails at the org level, independent of whether any individual account was configured carefully.

The second half steps outside AWS: first a mapping table to GCP so learning one platform lets you infer the other, then a dedicated section on OCI (13.14). I used to assume OCI was just AWS with different service names — turns out a lot of the foundational concepts are genuinely different: isolation by compartment instead of account, policies written as sentences instead of JSON, buckets private by default instead of something you have to lock down yourself. After lining up all three platforms, the chapter wraps with common cloud attack paths, CSPM tools that continuously scan for misconfiguration, and Secret Manager for keeping secrets out of source code.

> Examples throughout are real AWS CLI and OCI CLI commands with sample output; anywhere a figure might drift over time, it's flagged "needs verification."

---

## 13.1. Cloud service models: IaaS / PaaS / SaaS

### 13.1.1. What it is

Cloud computing is layered by "who operates which layer" of the infrastructure stack. The three standard models (original definition: NIST SP 800-145):

| Model | Provider manages | Customer manages | AWS example | GCP example |
|---|---|---|---|---|
| IaaS (Infrastructure) | Hypervisor, host OS, physical network, physical storage | Guest OS, runtime, app, data, virtual network configuration | EC2, EBS, VPC | Compute Engine, Persistent Disk |
| PaaS (Platform) | Additionally: OS, runtime, patching | App code + data + application configuration | Elastic Beanstalk, Lambda, RDS | App Engine, Cloud Functions, Cloud SQL |
| SaaS (Software) | The entire stack | Only user data + in-app configuration | WorkMail, QuickSight | Workspace |

### 13.1.2. Internals: the trust boundary shifts by layer

The core security point: **the attack surface and patching obligation shift along with the model**.

```
                 IaaS            PaaS            SaaS
               +--------+      +--------+      +--------+
   App         |  CUST  |      |  CUST  |      |  PROV  |
   Data        |  CUST  |      |  CUST  |      |  CUST* |   *Customer still owns/configures data access
   Runtime     |  CUST  |      |  PROV  |      |  PROV  |
   OS          |  CUST  |      |  PROV  |      |  PROV  |
   Hypervisor  |  PROV  |      |  PROV  |      |  PROV  |
   Phys. net   |  PROV  |      |  PROV  |      |  PROV  |
               +--------+      +--------+      +--------+
   CUST = Customer,  PROV = Provider
```

**Why:** with IaaS, an unpatched kernel vulnerability in the guest OS is your responsibility; with PaaS such as Lambda, AWS patches the runtime but **a vulnerable npm library in your deployment package is still yours**. Misunderstanding this boundary is the root of most misconfiguration incidents.

---

## 13.2. Shared Responsibility Model

### 13.2.1. What it is

A framework that divides security responsibility. AWS phrases it as:

- **Security OF the cloud** — AWS's responsibility: hardware, regions/AZs, physical network, hypervisor, foundational services.
- **Security IN the cloud** — the customer's responsibility: IAM, data encryption, Security Group configuration, patching the guest OS (for IaaS), data classification.

GCP uses the term "shared fate" — emphasizing that Google proactively provides secure-by-default blueprints, but the division of responsibility is essentially equivalent.

Responsibility boundary diagram:

```
        ===== SECURITY IN THE CLOUD (Customer) =====
        +-----------------------------------------------+
        |  Customer data + data classification          |
        |  IAM / policy / identity & access management  |
        |  Security Group, NACL, firewall config        |
        |  At-rest / in-transit encryption (enable&cfg) |
        |  Patching guest OS, runtime, app (IaaS level) |
        +-----------------------------------------------+
                          | responsibility boundary
        +-----------------------------------------------+
        |  Hypervisor / virtualization                  |
        |  Foundational services (compute, storage, DB) |
        |  Physical network, region / AZ                |
        |  Hardware, physical facilities (datacenter)   |
        +-----------------------------------------------+
        ===== SECURITY OF THE CLOUD (Provider) =====
```

The boundary line shifts up or down depending on the service model (IaaS pushes the boundary lower, SaaS pushes it higher), but data and access configuration always remain the customer's responsibility. This is why most breaches sit in the upper half of the diagram.

### 13.2.2. Detailed responsibility breakdown by service

| Item | EC2 (IaaS) | RDS (PaaS) | S3 (managed storage) |
|---|---|---|---|
| Patch hypervisor | AWS | AWS | AWS |
| Patch OS | Customer | AWS | N/A |
| Patch DB engine | Customer | AWS | N/A |
| At-rest encryption | Customer enables | Customer enables | Customer enables/SSE |
| In-transit encryption | Customer configures | Customer (force SSL) | Customer (policy `aws:SecureTransport`) |
| Access configuration (IAM/policy) | Customer | Customer | Customer |
| Data classification | Customer | Customer | Customer |

**Note:** nearly **every famous cloud data breach falls within the "IN the cloud" portion** — that is, a customer error (public bucket, key leaked in git, overly broad IAM). AWS/GCP are rarely breached at the layers they manage.

---

## 13.3. AWS IAM — Identity and Access Management

### 13.3.1. Entities

| Entity | Definition | Example ARN |
|---|---|---|
| Root user | Account owner, absolute full access, cannot be restricted by IAM policy | `arn:aws:iam::123456789012:root` |
| IAM User | A long-lived person/service identity with credentials | `arn:aws:iam::123456789012:user/alice` |
| IAM Group | A collection of users for attaching shared policies | `arn:aws:iam::123456789012:group/devs` |
| IAM Role | A temporary identity with no fixed credentials, that is "assumed" | `arn:aws:iam::123456789012:role/app-role` |
| Policy | A JSON document defining permissions | `arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess` |

ARN (Amazon Resource Name) structure — field by field:

```
arn : partition : service : region : account-id : resource-type / resource
 |        |         |         |          |              |
 |        |         |         |          |              +-- e.g. user/alice, bucket/my-data
 |        |         |         |          +-- 12-digit account number
 |        |         |         +-- e.g. us-east-1 (S3/IAM usually empty because global)
 |        |         +-- e.g. iam, s3, ec2
 |        +-- aws | aws-cn (China) | aws-us-gov
 +-- the literal "arn"
```

| ARN field | Size | Meaning | Example |
|---|---|---|---|
| arn | fixed 3 characters | literal | `arn` |
| partition | string | legal jurisdiction | `aws` |
| service | string | service namespace | `s3` |
| region | string | region (empty if global) | `us-east-1` or empty |
| account-id | 12 digits | account ID | `123456789012` |
| resource | string | resource identifier | `bucket/logs` |

### 13.3.2. Policy JSON — dissecting each field

This is the central structure of all AWS authorization. A policy is a JSON document.

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

Field-by-field description:

| Field | Required | Meaning | Example value |
|---|---|---|---|
| `Version` | Yes | Policy language version. MUST be `2012-10-17` to use variables/conditions. `2008-10-17` is old and does not support policy variables | `2012-10-17` |
| `Statement` | Yes | Array of permission statements | `[ {...} ]` |
| `Sid` | No | Statement ID, a label for reading/managing | `AllowReadSpecificBucket` |
| `Effect` | Yes | `Allow` or `Deny` | `Allow` |
| `Action` | Yes (or NotAction) | API action, in the form `service:Operation`, supports `*` | `s3:GetObject` |
| `Resource` | Yes for identity-attached policies | ARN of the resource it applies to | `arn:aws:s3:::bucket/*` |
| `Principal` | Only in resource-based/trust policies | Who is allowed (user/role/service) | `{"AWS": "...role/x"}` |
| `Condition` | No | Additional conditions (operator keys) | `StringEquals`, `IpAddress`, `Bool` |

**Why** `Version` is a fixed date: it is not the date you wrote the policy but the **version of the policy language grammar**. AWS freezes this value; writing it incorrectly (e.g. today's date) will cause conditions/variables to malfunction.

Commonly used Condition operator keys:

| Operator | Used for | Example key |
|---|---|---|
| `StringEquals` / `StringLike` | string comparison (Like supports `*`) | `aws:PrincipalTag/team` |
| `IpAddress` / `NotIpAddress` | CIDR | `aws:SourceIp` |
| `Bool` | true/false | `aws:MultiFactorAuthPresent`, `aws:SecureTransport` |
| `DateGreaterThan` | time | `aws:CurrentTime` |
| `ArnLike` | ARN comparison | `aws:SourceArn` |

### 13.3.3. Policy Evaluation Logic — step by step

When an API request arrives, AWS runs the following **Allow / Deny** decision process:

```
1. Default: implicit DENY for everything.
2. Collect ALL applicable policies: identity-based, resource-based,
   permission boundary, SCP (Organizations), session policy.
3. Any Explicit DENY in any policy?         --> YES => DENY (end).
4. Does the SCP allow the Action?            --> NO  => DENY.
5. Does the permission boundary allow it?    --> NO  => DENY.
6. Is there an Explicit ALLOW in identity/resource policy? --> YES => ALLOW.
7. Otherwise                                 --> DENY (implicit).
```

State machine diagram:

```
        +----------------+
        | Implicit Deny  |  (initial state)
        +-------+--------+
                |
        Explicit Deny? --yes--> [DENY] (always wins)
                | no
        SCP allow & Boundary allow & Explicit Allow? --no--> [DENY]
                | yes
              [ALLOW]
```

**Note:** an Explicit Deny always beats any Allow. This is the foundation for guarding an account: even if someone accidentally grants `AdministratorAccess`, a Deny in an SCP/boundary still blocks it.

### 13.3.4. STS AssumeRole and Trust Policy

STS (Security Token Service) issues **temporary credentials**. A Role has two policy parts:

- **Permission policy**: what the role *can do*.
- **Trust policy** (assume role policy document): *who is allowed to assume* this role — this is a special resource-based policy with a `Principal` field.

Sample trust policy (allowing a role in another account to assume it, with an ExternalId to prevent the "confused deputy" problem):

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

The real assume command and its output:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/app-role \
  --role-session-name audit-2026 \
  --external-id U7x-9213-secret \
  --duration-seconds 3600
```

Output (abbreviated):

```json
{
  "Credentials": {
    "AccessKeyId": "ASIA....EXAMPLE",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "SessionToken": "FwoGZXIvYXdz....<very long>",
    "Expiration": "2026-06-19T15:00:00Z"
  },
  "AssumedRoleUser": {
    "Arn": "arn:aws:sts::123456789012:assumed-role/app-role/audit-2026"
  }
}
```

Distinguish them by the **AccessKeyId prefix** — this is a key identifier when investigating logs:

| Prefix | Credential type | Lifetime |
|---|---|---|
| `AKIA` | Long-term (IAM user access key) | Permanent until deleted |
| `ASIA` | Temporary (STS) | Has an Expiration |

**Why** ExternalId: it prevents the confused deputy attack. If a SaaS provider uses the same role ARN for multiple customers, an attacker who knows your role ARN could trick the SaaS into assuming your role. The ExternalId is a secret known only to you and the SaaS, attached in the condition to block this.

### 13.3.5. Permission Boundary

This is a managed policy attached to a user/role that sets the **maximum permission ceiling**. Effective permissions = the intersection of the permission policy AND the boundary.

```
Effective permissions = (Identity policy ALLOW)  ∩  (Boundary ALLOW)  -  (any DENY)
```

Example: a developer is granted `AdministratorAccess` but the boundary only allows `s3:*` and `ec2:*` => in practice they can only operate S3 and EC2. Used to **safely delegate IAM creation** (let developers create their own roles but never exceeding the boundary).

### 13.3.6. MFA

MFA TOTP follows RFC 6238 (TOTP), which is based on RFC 4226 (HOTP). The 6-digit code is computed from:

```
TOTP = HOTP(K, T)  where  T = floor((UnixTime - T0) / X)
   K  = shared secret (Base32), X = 30 seconds (time step), T0 = 0
   HOTP = Truncate( HMAC-SHA1(K, T) ) mod 10^6
```

Enforce MFA with the `aws:MultiFactorAuthPresent` condition (as in section 13.3.2). **Note:** for the root user, enabling a hardware/virtual MFA device is the number-one priority.

---

## 13.4. AWS VPC — Virtual Private Cloud

A typical VPC architecture diagram (public/private subnets, IGW/NAT, placement of SG and NACL):

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
   |   route: 0.0.0.0/0 -> IGW        [NACL applied at subnet]    |
   |   +----------------+      +-----------------+                |
   |   |  NAT Gateway   |      |  Bastion/LB     | (SG at ENI)    |
   |   +-------+--------+      +-----------------+                |
   |           |                                                  |
   |  ---------|------------------------------------------------  |
   |   PRIVATE SUBNET 10.0.2.0/24                                 |
   |   route: 0.0.0.0/0 -> NAT GW     [NACL applied at subnet]    |
   |   +----------------+      +-----------------+                |
   |   |  App server    |----->|  Database (RDS) | (SG at ENI)    |
   |   |  (SG)          |      |  (SG)           |                |
   |   +----------------+      +-----------------+                |
   |     no public IP — outbound to Internet ONLY VIA NAT GW      |
   +-------------------------------------------------------------+
```

Key point: **the NACL filters at the subnet boundary (stateless)**, while the **Security Group filters right at each instance's ENI (stateful)**. Sensitive resources (the DB) sit in the private subnet, with only one-way outbound Internet access through the NAT Gateway and no inbound connections from the Internet.

### 13.4.1. CIDR and address allocation

A VPC is an isolated L3 virtual network. You assign it a CIDR (Classless Inter-Domain Routing) block.

CIDR notation `10.0.0.0/16`:

```
10.0.0.0/16  => 10.0.0.0 - 10.0.255.255
  /16 = 32 - 16 = 16 host bits => 2^16 = 65536 addresses
```

| Concept | Bits | Meaning |
|---|---|---|
| IPv4 address | 32 bits | 4 octets |
| Prefix `/n` | n network bits | the fixed portion |
| Host bits | 32 - n | number of hosts |

AWS **reserves 5 addresses at the start/end of each subnet**: `.0` (network), `.1` (VPC router), `.2` (Amazon-provided DNS), `.3` (reserved for future use), and `.255` (broadcast — even though a VPC does not broadcast, it is still held). So a `/24` subnet (256 addresses) only provides 251 usable hosts.

### 13.4.2. Public vs private subnets

The difference is **not in the subnet configuration** but in the **route table**:

- **Public subnet**: the route table has a `0.0.0.0/0 -> igw-xxxx` (Internet Gateway) route.
- **Private subnet**: the default route points to `0.0.0.0/0 -> nat-xxxx` (NAT Gateway) or has no Internet route at all.

Sample route tables:

```
Destination      Target            (public subnet)
10.0.0.0/16      local
0.0.0.0/0        igw-0abc123

Destination      Target            (private subnet)
10.0.0.0/16      local
0.0.0.0/0        nat-0def456
```

### 13.4.3. IGW vs NAT Gateway

| Component | Direction | Function | Note |
|---|---|---|---|
| Internet Gateway (IGW) | Bidirectional | Lets instances with a public IP receive/send Internet traffic, performing 1:1 NAT with an Elastic IP | No hourly charge |
| NAT Gateway | One-way (outbound) | Private instances reach the Internet (updates, API calls) but the Internet CANNOT reach in | Charged per hour + per GB; placed in a public subnet |

**Why** the NAT GW must sit in a public subnet: the NAT GW itself needs an outbound route through the IGW; private instances route to the NAT GW, and the NAT GW routes to the IGW.

### 13.4.4. VPC Flow Logs — record format

Flow Logs record flow metadata (not content). The default format (v2) includes the following fields in order:

```
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
2 123456789012 eni-0abc 10.0.1.5 203.0.113.7 51000 443 6 20 4520 1655640000 1655640060 ACCEPT OK
```

| Field | Meaning | Example |
|---|---|---|
| `version` | format version | `2` |
| `srcaddr`/`dstaddr` | source/destination IP | `10.0.1.5` |
| `srcport`/`dstport` | port | `443` |
| `protocol` | IANA number (6=TCP, 17=UDP, 1=ICMP) | `6` |
| `action` | `ACCEPT`/`REJECT` (per SG/NACL) | `ACCEPT` |
| `log-status` | `OK`/`NODATA`/`SKIPDATA` | `OK` |

**Note:** repeated `REJECT` to many ports from one IP = a sign of a port scan; use this as a source for GuardDuty and threat analysis.

---

## 13.5. Security Group (stateful) vs Network ACL (stateless)

### 13.5.1. Mechanism comparison

| Criterion | Security Group | Network ACL (NACL) |
|---|---|---|
| Layer applied | ENI (the instance's network interface) | Subnet |
| Stateful? | YES — return traffic is automatically allowed | NO — you must open both inbound and outbound |
| Rules | Allow only (no Deny) | Allow AND Deny |
| Evaluation | All rules at once (no ordering) | In rule-number ORDER (low -> high), stopping at the first match |
| Default | Deny inbound, Allow all outbound | "default NACL": allow all; a newly created NACL: deny all |

### 13.5.2. What stateful means (at the packet level)

When an instance sends a request out to `443` toward an external server:

```
Outbound: src 10.0.1.5:51000 -> dst 1.2.3.4:443   (SG outbound rule allows it)
Inbound return: src 1.2.3.4:443 -> dst 10.0.1.5:51000
```

- With a **SG (stateful)**: AWS keeps "connection tracking", so the return packet is automatically allowed — NO inbound rule is needed for ephemeral port 51000.
- With a **NACL (stateless)**: the return packet to the ephemeral port (1024-65535) must have an **inbound rule allowing the ephemeral range**, otherwise it is blocked.

**Why** you must open the ephemeral port range on a NACL: the TCP client picks a random source port in the ephemeral range; the server's response goes to that exact port. Because the NACL keeps no state, this must be declared explicitly.

### 13.5.3. NACL is ordered — example

```
Rule#   Type    Protocol  Port      Source           Allow/Deny
100     HTTP    TCP       80        0.0.0.0/0        ALLOW
130     SSH     TCP       22        0.0.0.0/0        DENY     <-- number 130 < 200
200     SSH     TCP       22        203.0.113.0/24   ALLOW
*       ALL     ALL       ALL       0.0.0.0/0        DENY
```

**Note:** a NACL is evaluated **from the lowest number to the highest, stopping at the first match**. In the example above, an SSH packet from `203.0.113.5` matches rule 130 (DENY) BEFORE reaching rule 200 (ALLOW) => it is blocked. This is a classic rule-numbering mistake. Always give the specific rule (allowing the trusted IP) a SMALLER number than the broad deny rule.

### 13.5.4. Practical example of creating a SG

```bash
aws ec2 create-security-group --group-name web-sg \
  --description "Web tier" --vpc-id vpc-0a1b2c3d

aws ec2 authorize-security-group-ingress \
  --group-id sg-0123456789 \
  --protocol tcp --port 443 --cidr 0.0.0.0/0

# Allow the app tier to reach the DB only from the app's SG (reference the SG, not an IP)
aws ec2 authorize-security-group-ingress \
  --group-id sg-db-999 \
  --protocol tcp --port 5432 --source-group sg-app-888
```

**Warning:** referencing **SG-to-SG** instead of CIDR is best practice — when an instance's IP changes, the rule still holds; and you do not accidentally open access to an unknown IP. Absolutely avoid `--cidr 0.0.0.0/0` for ports 22/3389/3306/5432.

---

## 13.6. Amazon S3 — object storage

### 13.6.1. The multi-layer access model

S3 access is decided by the combination: Block Public Access (BPA) > IAM policy > Bucket policy > ACL. An explicit Deny at any layer beats everything.

### 13.6.2. Block Public Access — 4 flags

| Flag | Effect |
|---|---|
| `BlockPublicAcls` | Blocks new public ACL PUTs |
| `IgnorePublicAcls` | Ignores existing public ACLs |
| `BlockPublicPolicy` | Blocks setting a public bucket policy |
| `RestrictPublicBuckets` | Restricts access via a public policy to principals in the same account/service only |

```bash
aws s3api put-public-access-block --bucket company-reports \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

Since April 2023, AWS enables BPA by default for new buckets. **Why** 4 separate flags: ACLs and policies are two historically independent mechanisms; you need to block both "public" sources.

### 13.6.3. Bucket policy JSON — enforce in-transit encryption and block non-TLS

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

The first statement blocks any request not over HTTPS; the second rejects uploads that do not include the `x-amz-server-side-encryption: aws:kms` header.

### 13.6.4. SSE encryption — the types

| Type | Key managed by | Request header | Audited via CloudTrail |
|---|---|---|---|
| SSE-S3 | AWS (AES-256, S3's key) | `x-amz-server-side-encryption: AES256` | Key usage not visible per-use |
| SSE-KMS | AWS KMS (your CMK) | `...: aws:kms` + `x-amz-server-side-encryption-aws-kms-key-id` | YES — each Decrypt is logged in CloudTrail |
| SSE-C | Customer supplies the key on each request | sends the key in a header | You manage the key yourself |
| DSSE-KMS | Dual-layer KMS encryption | `aws:kms:dsse` | For high-compliance requirements |

Since early 2023, S3 applies SSE-S3 by default to every new object (the exact version per region needs verification). **Why** choose SSE-KMS: you control who can use the key (via the KMS key policy) and **you get an audit trail for each decryption** — extremely valuable for investigations.

### 13.6.5. Versioning

Enabling versioning keeps every object version; a delete only places a "delete marker". This protects against malicious overwrites/deletes (ransomware) and user error. Combine it with **MFA Delete** and **Object Lock (WORM)** for immutability.

```bash
aws s3api put-bucket-versioning --bucket company-reports \
  --versioning-configuration Status=Enabled
```

### 13.6.6. The classic breach pattern

A scenario repeated many times in the real world: a bucket holding backups/PII is set to ACL `public-read` or a bucket policy with `Principal:"*"` and no condition. Anyone with the URL `https://bucket.s3.amazonaws.com/key` can read the data.

Detect it with a quick check command:

```bash
# List buckets that do NOT have full Block Public Access enabled
for b in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  echo "== $b =="
  aws s3api get-public-access-block --bucket "$b" \
    --query 'PublicAccessBlockConfiguration' 2>/dev/null \
    || echo "  !! NO public-access-block (risk)"  # no Block Public Access
done
```

---

## 13.7. AWS KMS — Key Management Service

### 13.7.1. CMK and key classification

| Key type | Who manages it | Automatic key rotation |
|---|---|---|
| AWS owned | AWS uses internally, you cannot see it | Automatic |
| AWS managed (`aws/s3`...) | AWS on behalf of the service | Automatic, yearly |
| Customer managed (CMK) | You (key policy, rotation, alias) | Optional (default 1 year) |

### 13.7.2. Envelope Encryption — step by step

KMS does not encrypt large data blocks directly (the limit for `Encrypt` is ~4 KB). Instead it uses **envelope encryption** (the principles of AES, AES-GCM, and key management are covered in [Chapter 4](#sec-04)):

```
1. The client calls KMS GenerateDataKey(KeyId=CMK, KeySpec=AES_256).
2. KMS returns:
     - Plaintext data key (DEK) : 256-bit, used to encrypt data locally
     - CiphertextBlob           : that same DEK, but encrypted by the CMK
3. The client uses the plaintext DEK (AES-256-GCM) to encrypt the large file.
4. The client WRITES: ciphertext_file + CiphertextBlob(the encrypted DEK).
5. The client ERASES the plaintext DEK from RAM.

Decryption:
6. The client calls KMS Decrypt(CiphertextBlob) -> gets back the plaintext DEK.
7. Uses the DEK to decrypt the file.
```

Diagram:

```
      [CMK inside KMS - never leaves the HSM]
              |  encrypt/decrypt
              v
   [Encrypted DEK: CiphertextBlob]  <-- stored next to the data
              |  Decrypt via KMS
              v
   [Plaintext DEK]  --AES-256-GCM-->  [data]
```

**Why** the envelope design: (1) it reduces the number of KMS calls (encrypting data locally is fast); (2) the root CMK never leaves the KMS HSM; (3) revoking Decrypt permission on the CMK immediately invalidates every DEK.

Practical example:

```bash
# Create a DEK
aws kms generate-data-key --key-id alias/app-cmk --key-spec AES_256 \
  --query '{plain:Plaintext, blob:CiphertextBlob}' --output json
# The Plaintext (base64) is used to encrypt; the CiphertextBlob is stored with the ciphertext.
```

### 13.7.3. KMS Key Policy

Unlike IAM: KMS **always requires a key policy** (resource-based). A common key policy grants administrative rights to the account root and then delegates further via IAM:

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

**Note:** deleting all statements that grant the root permissions can leave the key **unmanageable** (you would need to open an AWS Support ticket to recover it).

---

## 13.8. CloudTrail — the API log

### 13.8.1. What it is

It records every API call (management events) and, optionally, data events (S3 object-level, Lambda invoke). It is the number-one investigation data source in AWS.

### 13.8.2. Structure of an event JSON — field by field

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

| Field | Investigative meaning |
|---|---|
| `userIdentity.type` | `Root`, `IAMUser`, `AssumedRole`, `AWSService` — who called |
| `userIdentity.accessKeyId` | `ASIA`=temporary, `AKIA`=long-term (see 13.3.4) |
| `sessionContext.mfaAuthenticated` | `"false"` is suspicious for sensitive actions |
| `eventSource` + `eventName` | service + specific API |
| `sourceIPAddress` | source IP — cross-check against unknown IPs/countries |
| `errorCode` (if present) | repeated `AccessDenied` = a sign of permission probing |

**Note:** enable **log file integrity validation** (CloudTrail generates a SHA-256-signed digest) to detect tampered/deleted logs. Store logs in a dedicated bucket with Object Lock.

---

## 13.9. CloudWatch

CloudWatch = metrics + logs + alarms. Security-relevant aspects:

- **CloudWatch Logs**: aggregates application logs / VPC Flow Logs.
- **Metric filter + Alarm**: detects behavior from CloudTrail. For example, create an alarm when there are repeated failed `ConsoleLogin` attempts or when the root user logs in.

```bash
aws logs put-metric-filter \
  --log-group-name CloudTrail/Logs \
  --filter-name RootLogin \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.eventName = "ConsoleLogin" }' \
  --metric-transformations metricName=RootLoginCount,metricNamespace=Security,metricValue=1
```

The filter pattern uses JSON-path syntax; `$.userIdentity.type` points to the nested field. Then attach `put-metric-alarm` to send an SNS alert.

---

## 13.10. GuardDuty

### 13.10.1. What it is

A threat detection service based on ML + threat intelligence, analyzing **CloudTrail, VPC Flow Logs, DNS logs, EKS audit logs, S3 data events** — with no agent to install.

### 13.10.2. Finding families (name format)

Finding names follow the structure `ThreatPurpose:ResourceType/ThreatFamilyName.DetectionMechanism!Artifact`:

| Example finding | Meaning |
|---|---|
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | An EC2 role's credentials used from outside AWS (a sign of stolen IMDS credentials) |
| `Recon:IAMUser/MaliciousIPCaller` | API call from a known malicious IP |
| `CryptoCurrency:EC2/BitcoinTool.B!DNS` | An EC2 instance querying a cryptocurrency-mining domain |
| `Backdoor:EC2/C&CActivity.B` | An EC2 instance communicating with a C2 server |
| `Exfiltration:S3/ObjectRead.Unusual` | Unusual S3 reads |
| `Policy:IAMUser/RootCredentialUsage` | Use of root credentials |

**Why** `InstanceCredentialExfiltration.OutsideAWS` is so powerful: it correlates location — an EC2 role's credentials *must* be used from inside AWS; if they appear from an external IP, they have almost certainly been extracted via SSRF/IMDS.

---

## 13.11. IMDS — Instance Metadata Service (v1 vs v2)

### 13.11.1. What it is

IMDS serves metadata at the fixed link-local address **`169.254.169.254`**. Most importantly, it issues the **temporary credentials of the IAM role attached to the instance**.

```bash
# Get the role name
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Get the credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role
```

Credential output:

```json
{
  "Code": "Success",
  "AccessKeyId": "ASIA....",
  "SecretAccessKey": "....",
  "Token": "....",
  "Expiration": "2026-06-19T20:00:00Z"
}
```

### 13.11.2. IMDSv1 (simple request/response — and the SSRF vulnerability)

IMDSv1: a single HTTP GET to `169.254.169.254` is all it takes. NO token is needed. This is the root of countless SSRF incidents (the SSRF mechanism is covered in [Chapter 5 — Web Application Security](#sec-05)).

SSRF attack scenario via IMDSv1:

```
1. A web application has a parameter: https://app/fetch?url=<URL>  (the server fetches the URL itself).
2. The attacker sends: ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role
3. The server (running on EC2) fetches it on their behalf, returning ASIA/Secret/Token credentials.
4. The attacker uses the credentials from their own machine (outside AWS) -> GuardDuty
   InstanceCredentialExfiltration.OutsideAWS.
```

### 13.11.3. IMDSv2 — session token, step by step

IMDSv2 requires a two-step process: **PUT to obtain a token, then GET with the token**:

```bash
# Step 1: PUT to obtain a token (max TTL 21600s = 6h)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: GET with the token in the header
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ \
  -H "X-aws-ec2-metadata-token: $TOKEN"
```

| IMDSv2 protection mechanism | Why it blocks SSRF |
|---|---|
| Requires a **PUT** to obtain a token | Most SSRF vulnerabilities only allow GET, and cannot send an arbitrary PUT with headers |
| Requires a **custom header** `X-aws-ec2-metadata-token` | Basic SSRF cannot add this header |
| Default **`X-Forwarded-For` => reject** | Blocks requests that pass through a proxy/WAF/reverse proxy (a sign of SSRF/relay) |
| Limits the **PUT response hop limit = 1** | The token does not "hop" across containers/routes; a packet with a decremented IP-TTL is rejected |

Enforce IMDSv2 (fully disable v1):

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-0123456789 \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --http-endpoint enabled
```

`--http-tokens required` = require a token (disable v1). `--http-put-response-hop-limit 1` = the metadata response packet can travel only 1 hop (IP TTL), preventing a container on the instance or a reverse proxy from forwarding the metadata.

**Note:** blocking IMDS at the network layer should also be added — for example, an iptables drop of traffic to `169.254.169.254` for the web application user that does not need metadata.

---

## 13.12. AWS Organizations & SCP (Service Control Policy)

### 13.12.1. What it is

Organizations manage multiple accounts in an OU (Organizational Unit) tree. An SCP is a **guardrail** applied at the org/OU/account level — it sets the **maximum permission ceiling** and does NOT itself grant any permissions.

```
Root
 ├── OU: Security  (SCP: Deny disabling CloudTrail)
 ├── OU: Prod      (SCP: only regions us-east-1, eu-west-1)
 └── OU: Sandbox   (SCP: Deny expensive services)
```

### 13.12.2. SCP example — lock down regions and prevent disabling audit

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

**Why** `NotAction` contains `iam`/`sts`: these services are global (implicitly region `us-east-1`); blocking by region could accidentally lock them out. An SCP applies even to the **root user of a member account** — this is the only way to restrict root.

---

## 13.13. GCP — AWS equivalents

### 13.13.0. AWS ↔ GCP mapping table

A quick reference before the details: learn one platform, then infer the other.

| Concept | AWS | GCP |
|---|---|---|
| Human identity | IAM User | Google account / member |
| Workload identity | IAM Role | Service Account |
| Temporary token | STS | SA token via metadata / STS API |
| Virtual network | VPC (per-region) | VPC (global), subnets per region |
| Instance firewall | Security Group (stateful) | Firewall rule (stateful, with priority) |
| Stateless ACL | NACL | (no direct equivalent; use firewall priority) |
| Object storage | S3 | Cloud Storage |
| Key management | KMS | Cloud KMS |
| API audit | CloudTrail | Cloud Audit Logs |
| Metrics/logs | CloudWatch | Cloud Monitoring / Logging |
| Threat detection | GuardDuty | SCC / Event Threat Detection |
| Organization guardrail | SCP | Organization Policy |
| Secret management | Secrets Manager | Secret Manager |
| Metadata service | IMDS 169.254.169.254 | metadata.google.internal (169.254.169.254) |

### 13.13.1. GCP IAM

GCP IAM attaches permissions via the **binding** formula: who (member) + role + resource (through the hierarchy).

```
who   = member  (user:, serviceAccount:, group:, domain:, allUsers, allAuthenticatedUsers)
what  = role    (roles/storage.objectViewer ...)
where = resource (Organization > Folder > Project > Resource)  -- permissions are INHERITED downward
```

Role classification:

| Role type | Description | Example | Note |
|---|---|---|---|
| Primitive (basic) | Owner/Editor/Viewer applied to the whole project | `roles/owner` | Too broad — avoid |
| Predefined | Defined by Google, fine-grained per service | `roles/storage.objectAdmin` | Recommended |
| Custom | You combine permissions yourself | `projects/p/roles/myAuditor` | True least privilege |

Example IAM policy binding (the JSON format from `getIamPolicy`):

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

| Field | Meaning | Example |
|---|---|---|
| `version` | Policy schema version (3 to use conditions) | `3` |
| `bindings[].role` | The assigned role | `roles/storage.objectViewer` |
| `bindings[].members[]` | List of members (with a type prefix) | `user:`, `serviceAccount:` |
| `condition.expression` | A CEL (Common Expression Language) expression | a condition based on resource/time |
| `etag` | A key to prevent concurrent overwrites (optimistic locking) | base64 |

**Warning:** `allUsers` (anyone on the Internet) and `allAuthenticatedUsers` (any Google account) are the equivalent of "public" — the leading source of Cloud Storage leaks.

### 13.13.2. Service Account & Service Account Key

A Service Account (SA) is an identity for a workload. It has **two kinds of secrets**:

- **Google-managed key**: Google rotates it automatically, used when the workload runs on GCP (the metadata server issues tokens automatically — equivalent to an AWS IAM role).
- **User-managed key (JSON)**: a `.json` file you download — a long-lived secret, and the **biggest risk** if it leaks into git.

Structure of an SA key JSON file:

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

| Field | Meaning |
|---|---|
| `type` | always `service_account` — the identifier when scanning for secrets |
| `private_key` | RSA private key in PEM — the core secret |
| `client_email` | the SA identifier (check this email's permissions) |
| `token_uri` | the endpoint to exchange a JWT for an OAuth2 access token |

**Note:** you should **disable creation of user-managed keys** via the Org Policy `iam.disableServiceAccountKeyCreation` and use Workload Identity Federation instead of key files.

### 13.13.3. GCP VPC

A key difference from AWS: **a GCP VPC is global**, with subnets belonging to a region (AWS: a VPC is per-region, with subnets per AZ). Firewall rules are applied at the VPC level, by network tag/SA, with a priority (0-65535, lower = higher priority), and are stateful.

```bash
gcloud compute firewall-rules create allow-https \
  --network=prod-vpc --direction=INGRESS --action=ALLOW \
  --rules=tcp:443 --source-ranges=0.0.0.0/0 \
  --target-tags=web --priority=1000
```

### 13.13.4. Cloud Storage (equivalent to S3)

- Permissions: IAM (uniform bucket-level access — recommended) or ACL (fine-grained — should be disabled).
- Enable **Uniform bucket-level access** to drop ACLs and avoid public-ACL mistakes.
- Default encryption is Google-managed; choose CMEK (Customer-Managed Encryption Key via Cloud KMS) or CSEK.

```bash
gsutil uniformbucketlevelaccess set on gs://prod-data
# Detect public access:
gsutil iam get gs://prod-data | grep -E "allUsers|allAuthenticatedUsers"
```

### 13.13.5. Cloud Logging (equivalent to CloudTrail/CloudWatch Logs)

GCP records **Audit Logs** divided into types:

| Audit Log type | Content | Default |
|---|---|---|
| Admin Activity | configuration/IAM changes | Always on, cannot be disabled |
| Data Access | data reads/writes | OFF by default (except BigQuery) — must be enabled |
| System Event | Google's system actions | Always on |
| Policy Denied | denied by policy | Automatic |

A Cloud Audit Log entry (the `protoPayload` AuditLog format):

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

**Note:** Data Access logs are OFF by default — if you do not enable them, you have **no trail of who read which object** (unlike AWS, where you need to enable S3 data events). This is a common investigative blind spot.

### 13.13.6. Security Command Center (equivalent to GuardDuty + Security Hub + Config)

SCC is GCP's security posture management platform: it detects misconfigurations, vulnerabilities, and threats.

| Module | Role |
|---|---|
| Security Health Analytics | Scans for misconfigurations (public buckets, SA keys, open firewalls) — CSPM-style |
| Event Threat Detection | Analyzes logs to detect behavior (SSH brute force, anomalous IAM) |
| Container Threat Detection | Runtime detection in GKE |
| Web Security Scanner | Scans web apps |

Example findings: `PUBLIC_BUCKET_ACL`, `SERVICE_ACCOUNT_KEY_NOT_ROTATED`, `OPEN_FIREWALL`, `MFA_NOT_ENFORCED`.

---

## 13.14. OCI — Oracle Cloud Infrastructure

### 13.14.1. What it is and why I had to learn it

I run two clouds in practice: prod on AWS, and dev (plus part of prod) on OCI (Oracle Cloud Infrastructure). Why I have to know OCI: it is **not a renamed copy of AWS** — many foundational concepts are designed quite differently, and anyone used to AWS thinking can easily misunderstand them and then misconfigure. This section records exactly the spots where I stumbled, mapped 1-to-1 against AWS to switch mental models quickly.

The biggest difference to grasp up front: **AWS isolates with *accounts*, while OCI isolates with *compartments* inside a single *tenancy*.** Getting this wrong means getting OCI's entire permission model wrong.

### 13.14.2. Tenancy and Compartment — the logical permission tree

- **Tenancy**: the root of all of an organization's OCI resources — equivalent to "AWS Organizations + the root account" fused into one. Every OCI resource has an OCID (Oracle Cloud ID) of the form `ocid1.<type>.<realm>..<hash>` and always belongs to a tenancy.
- **Compartment**: a **logical folder tree** for grouping resources and applying permissions. This is where OCI differs most from AWS. On AWS, to separate environments/teams you typically split *accounts* and stitch them together with Organizations; on OCI, a single tenancy contains many nested compartments (`dev`, `prod`, `prod/db`, `shared-network`...), and permissions are granted *per compartment*.

```
Tenancy (root)
 ├── Compartment: network-shared      (shared VCN, subnets)
 ├── Compartment: dev                 (dev environment resources)
 │     └── Compartment: dev/app
 └── Compartment: prod                (prod resources running on OCI)
       ├── Compartment: prod/app
       └── Compartment: prod/data     (buckets, DB — most tightly locked)
```

**Why compartments are convenient:** permissions, quotas, and even cost-tracking are attached per compartment; deleting a compartment cleans out everything inside it. But precisely because it is "one tenancy, many compartments," the isolation boundary is **weaker than AWS account separation** — a loose policy written at the tenancy level can leak permissions down into every compartment. This is why the part of prod running on OCI must sit in its own compartment with policies scoped correctly (see 13.14.9).

### 13.14.3. IAM policy as statements (completely unlike AWS JSON)

This is what surprised me most coming from AWS. OCI IAM policy is **not a JSON document** with `Effect/Action/Resource` like AWS — it is **near-readable English sentences**:

```
Allow group <group-name> to <verb> <resource-type> in compartment <name> [where <condition>]
```

Real examples:

```
Allow group Developers to manage object-family in compartment dev
Allow group DBAdmins   to manage database-family in compartment prod:data
Allow group Auditors   to read all-resources in tenancy
Allow group AppOps     to use secret-family in compartment prod where request.region = 'ap-singapore-1'
```

The four **permission verbs**, ordered by increasing power (worth memorizing — different from AWS's enumeration of individual actions):

| Verb | Includes | AWS equivalent (conceptual) |
|---|---|---|
| `inspect` | list resources (metadata, no sensitive contents) | `List*` |
| `read` | inspect + read contents/details | `List* + Get*/Describe*` |
| `use` | read + operate on / update existing (no create/delete) | `Get* + Update*/runtime actions` |
| `manage` | use + create and delete | full control over the resource type |

`<resource-type>` uses pre-grouped "families": `object-family` (Object Storage), `instance-family` (Compute), `virtual-network-family` (VCN), `secret-family`, `vaults`, `keys`... The `where` clause attaches conditions (region, time, `target.compartment.name`, tags...) — equivalent to AWS `Condition` but written inline in the sentence.

**Why I like this syntax:** reading an OCI policy is almost like reading the policy in plain English, with far less of AWS's "syntactically valid JSON but wrong intent." **Where it trips you up:** there is no explicit `Deny` — OCI IAM only has Allow (implicit deny by default). To "forbid" something you must *not grant* it, or tighten by compartment scope, or use another mechanism (Network Sources, tag-based). The habit of writing `Deny` guardrails like AWS SCPs **does not port directly** — you have to rethink it as narrowing the scope of what you grant.

### 13.14.4. Dynamic Group + Instance/Resource Principal (workload identity, no static keys)

This is the part of OCI I value most, and it maps directly onto AWS's "IAM role attached to EC2": it lets compute/functions **obtain temporary credentials to call OCI APIs without embedding static keys in code**.

The mechanism has two steps:

1. **Dynamic Group**: groups *resources* (not users) by a *matching rule* — e.g. every instance in a compartment, or a specific function.

   ```
   # A dynamic group's matching rule
   ALL {instance.compartment.id = 'ocid1.compartment.oc1..aaaa....dev'}
   ```

2. **A policy granting permissions to that dynamic group** (written just like a normal policy, with `dynamic-group` as the subject):

   ```
   Allow dynamic-group DevInstances to read secret-family in compartment dev
   Allow dynamic-group DevInstances to use keys        in compartment dev
   ```

Then code running on the instance uses an **Instance Principal** to authenticate itself (the SDK fetches temporary certificates from the metadata endpoint), with no key file at all:

```python
import oci
signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
secrets = oci.secrets.SecretsClient(config={}, signer=signer)
# calls the API with the machine's identity — temporary, auto-rotated credentials, never on disk
```

- **Instance Principal**: for VMs/compute.
- **Resource Principal**: for serverless (OCI Functions) and some managed services — equivalent to a Lambda execution role.

**Why it matters:** as on AWS, the crux is **"machine identity, not a key file."** Even the "secret to fetch the secret" is not on disk: the app uses its Instance Principal to authenticate, then fetches the real secret from Vault at startup. This is the correct way for a service in the dev OCI environment to access Vault without hardcoding credentials.

### 13.14.5. OCI Vault — KMS + Secrets in one place

OCI Vault combines the two roles that AWS splits into **KMS** (keys) and **Secrets Manager** (secrets):

- **Keys (encryption keys)**: master keys protected in an HSM. Two vault types: *Default* (HSM partition shared with other tenants — cheaper, fine for most needs) and *Virtual Private Vault* (a dedicated HSM partition, stronger isolation, for stricter compliance requirements — pricing and limits need verification at time of use). Used for at-rest encryption of Block Volumes, Object Storage, databases. Supports rotation and envelope encryption on the same principle as KMS (section 13.7.2).
- **Secrets**: DB passwords, API keys... stored encrypted with a key in the Vault, managed as immutable *versions*.

```bash
# Read a secret (bundle) — the returned content is base64-encoded
oci secrets secret-bundle get-secret-bundle-by-name \
  --secret-name db-password --vault-id ocid1.vault.oc1..aaaa
```

My actual secrets architecture: **prod uses AWS Secrets Manager, the part running on OCI uses OCI Vault** — same principle: the app holds no static key to call the secret store, it uses an IAM role (AWS) / Instance Principal (OCI) to authenticate and then fetches secrets at runtime.

### 13.14.6. VCN — Security List (subnet level) vs NSG (VNIC level)

A VCN (Virtual Cloud Network) is OCI's isolated virtual network, equivalent to a VPC. But OCI's firewall mechanism has **two layers coexisting**, and the mapping to AWS is not perfectly 1-to-1, which makes it easy to confuse:

| Criterion | Security List (OCI) | Network Security Group / NSG (OCI) |
|---|---|---|
| Attached where | **Subnet** (applies to EVERY VNIC in the subnet) | Each resource's **VNIC** (grouped by function) |
| Closest AWS analog | close to **NACL** (subnet level) but **stateful by default** | close to **Security Group** (interface level) |
| Stateful? | per-rule choice: **stateful or stateless** | stateful by default (can choose stateless) |
| Source reference | CIDR, or Service (for a Service Gateway) | CIDR **or another NSG** (like AWS SG-to-SG) |

The easiest trap coming from AWS: on OCI a packet must pass **BOTH the subnet's Security List AND the VNIC's NSG** — both must allow it for the packet to flow (an AND intersection). People used to AWS often only adjust the NSG (thinking of it as a Security Group) and forget that the subnet's Security List is still blocking, or vice versa.

Another difference from AWS: a Security List is **stateful by default** (not stateless like a NACL), so you usually do not have to manually open the ephemeral port range for return traffic — unless you deliberately set a rule to stateless. Practical recommendation: prefer **NSGs** for functional network segmentation (NSG-to-NSG references, mirroring the SG-to-SG best practice), keeping Security Lists minimal/default.

### 13.14.7. Object Storage — private by default, PAR instead of public

Object Storage is OCI's object store (equivalent to S3). There is one point I consider a **design plus** compared to S3's history:

- **Buckets are private by default.** To make one public you must **actively** change its visibility to Public. Unlike early-days S3 (where loose configuration + public-read ACLs were the classic leak source), OCI's "accidentally public" risk is lower by default — but *you still have to check*, because someone can still switch it to public by mistake.
- **Pre-Authenticated Requests (PARs)** replace opening a bucket to the public: create a URL with an **expiry time** and a scope (a single object or the whole bucket, read/write) — equivalent to an S3 pre-signed URL. When you need to share a file, issue a time-limited PAR; do **not** make the bucket public.
- At-rest encryption is on by default (Oracle-managed key); sensitive data should move to a **customer-managed key in OCI Vault** to control rotation + audit who uses the key.

```bash
# Create a PAR to read one object, expiring in 24h — instead of making the bucket public
oci os preauth-request create --namespace <ns> --bucket-name reports \
  --name share-q1 --access-type ObjectRead \
  --object-name q1.pdf --time-expires 2026-08-15T00:00:00Z
```

**Cloud Guard** (section 13.14.8) automatically flags public buckets — so enable it as a detection layer.

### 13.14.8. Cloud Guard — OCI's CSPM

Cloud Guard is OCI's cloud security posture management (CSPM) service, equivalent to GuardDuty + Security Hub + Config combined (or GCP's SCC):

- **Detectors** scan for risky configuration/behavior and raise **Problems**: public buckets, security rules open to `0.0.0.0/0` on admin ports, overly broad IAM policies, unpatched instances, keys/secrets nearing expiry...
- **Responders** allow automated or semi-automated remediation (e.g. automatically closing a public bucket).
- Benchmarked against CIS OCI Foundations.

In the systems I operate, Cloud Guard plays the role for the OCI environment that AWS Config + GuardDuty play for the AWS environment: detecting configuration drift, public buckets, widened network rules, anomalous behavior — and pushing alerts to the ops channel instead of leaving one person to hand-audit monthly.

### 13.14.9. OCI metadata endpoint — IMDS v2 requires the `Authorization: Bearer Oracle` header

OCI also has a metadata service at the exact same link-local address **`169.254.169.254`** as AWS/GCP, and Instance Principals fetch their temporary certificates through it — so it presents **the same SSRF attack surface** as AWS IMDS (SSRF mechanism: [Chapter 5](#sec-05)).

The notable defensive difference — how each side blocks SSRF:

| | AWS IMDSv2 | OCI IMDS v2 |
|---|---|---|
| Path | `/latest/meta-data/...` | `/opc/v2/...` |
| Protection | **PUT** to fetch a token first, then GET with the token header | GET with a **fixed header** `Authorization: Bearer Oracle` |
| Why it blocks naive SSRF | basic SSRF can only do GET, cannot PUT a token | basic SSRF cannot add the `Authorization` header itself |

```bash
# OCI IMDS v2 — a missing header is rejected
curl -H "Authorization: Bearer Oracle" http://169.254.169.254/opc/v2/instance/
curl -H "Authorization: Bearer Oracle" http://169.254.169.254/opc/v2/identity/cert.pem
```

**Important note:** the `Authorization: Bearer Oracle` header is a **fixed constant**, not a secret — it only raises the bar against *naive* SSRF (the kind that can only inject a URL, not add a header). An SSRF that can control headers still gets through. So do not treat metadata v2 (whether AWS or OCI) as sufficient: you still have to apply the full SSRF defense set at the application layer (domain allowlist, block private/link-local IPs `169.254.0.0/16`, validate the IP after DNS resolution to defeat rebinding, disable/validate redirects). OCI v1 (`/opc/v1/`) requires no header — so enforce v2 just as you enforce IMDSv2 on AWS.

### 13.14.10. AWS ↔ OCI ↔ GCP mapping table

A quick lookup when jumping between the three platforms — learn one, infer the other two:

| Concept | AWS | OCI | GCP |
|---|---|---|---|
| Isolation boundary | Account (+ Organizations) | **Compartment** (within one tenancy) | Project (+ Folder/Org) |
| IAM policy syntax | JSON (`Effect/Action/Resource`) | **Statements** (`Allow group … to … in compartment …`) | JSON binding (member+role) |
| Workload identity | IAM Role on EC2 | **Instance/Resource Principal** (+ Dynamic Group) | Service Account (+ Workload Identity) |
| Org guardrail | SCP (has Deny) | *(no Deny; tighten via compartment scope / policy)* | Organization Policy |
| Virtual network | VPC | **VCN** | VPC (global) |
| Interface-level firewall | Security Group | **NSG** | Firewall rule (by tag/SA) |
| Subnet-level firewall | NACL (stateless) | **Security List** (stateful by default) | *(none; use priority)* |
| Object storage | S3 | **Object Storage** | Cloud Storage |
| Private-by-default bucket | BPA (on by default since 4/2023) | **Private by default already** | Uniform bucket-level access |
| Time-limited share URL | Pre-signed URL | **Pre-Authenticated Request (PAR)** | Signed URL |
| Key management | KMS | **Vault (Keys)** | Cloud KMS |
| Secret management | Secrets Manager | **Vault (Secrets)** | Secret Manager |
| API audit | CloudTrail | **Audit** (on by default) | Cloud Audit Logs |
| CSPM / threat detection | GuardDuty + Security Hub + Config | **Cloud Guard** | Security Command Center |
| Metadata endpoint | `169.254.169.254` `/latest/` (IMDSv2: PUT token) | `169.254.169.254` `/opc/v2/` (`Bearer Oracle` header) | `metadata.google.internal` |

### 13.14.11. Multi-cloud operating principles (practical experience)

Running AWS (prod) + OCI (dev and part of prod) side by side, I have distilled a few principles that theory rarely states bluntly:

- **The correct boundary is prod vs non-prod, NOT AWS vs OCI.** Having prod on AWS and dev on OCI is merely a *fortunate coincidence* (separating both provider and credentials, so the blast radius is small), but do not turn "provider" into a security-classification criterion.
- **The part of prod running on the "dev" cloud must meet the SAME tight standard as the main prod.** This is the most dangerous trap: a prod compartment sitting in the same tenancy as dev easily "inherits" dev's loose configuration habits (broad network rules, permissive buckets, tenancy-wide policies). Prod-OCI must have: least privilege by compartment, no public buckets, secrets in Vault, logging/Cloud Guard enabled — exactly like prod-AWS.
- **Separate credentials / network / permissions across environments.** A leaked dev credential must not open anything in prod. Any connection between the two clouds (if it exists, e.g. an AWS↔OCI VPN) opens only the ports genuinely needed.
- **Real data does not live in dev.** A dev environment being more loosely configured is normal — but only acceptable when dev *does not touch real data*. The biggest risk of the "dev on OCI" model is a loosely configured dev machine accidentally holding production data.
- **Standardize with IaC to manage two IAM/tooling stacks.** The price of multi-cloud is managing two IAM systems and two toolsets; offset it with Terraform/IaC + policy-as-code (Checkov/Trivy scanning both AWS and OCI config) so you don't have to remember two ways of configuring by hand.

---

## 13.15. Cloud attacks and how to detect them

### 13.15.1. Misconfiguration

The leading cause. Detected with CSPM (section 13.16). Forms include: public buckets, SGs open to `0.0.0.0/0` on administrative ports (22/3389/database), CloudTrail not enabled, encryption disabled, IMDSv1 still enabled, IAM policies with `"Action":"*","Resource":"*"`.

### 13.15.2. Credential leak — keys in git

AWS access keys have a clearly identifiable form:

```
AKIA[0-9A-Z]{16}        <- Access Key ID (20 characters, AKIA prefix)
40-character base64 secret   <- Secret Access Key
```

Scan git with real tools:

```bash
# trufflehog scans the entire repo history and verifies that keys are still live
trufflehog git file://./myrepo --only-verified

# gitleaks
gitleaks detect --source . --report-format json --report-path leaks.json
```

Sample gitleaks output:

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

**Why** scan the entire commit history: deleting a key in a new commit but leaving it in git history => an attacker can recover it with `git log -p`. You must both **revoke the key (disable it immediately)** and clean the history (or consider it permanently exposed).

GitHub Secret Scanning + push protection blocks it the moment you push; AWS has a mechanism that automatically attaches the `AWSCompromisedKeyQuarantine` policy when it detects a public key.

### 13.15.3. Privilege Escalation via `iam:PassRole`

This is one of the most dangerous and common privilege-escalation paths.

**Mechanism:** `iam:PassRole` allows a principal to "hand" a role to a service (EC2, Lambda...). If an attacker has:
- `iam:PassRole` for a high-privilege role (e.g. `AdminRole`), AND
- permission to create a resource that attaches that role (e.g. `ec2:RunInstances` or `lambda:CreateFunction`),

then they can escalate to Admin even though their own account is not an Admin.

Concrete exploitation steps (via Lambda):

```bash
# 1. Create a Lambda running under AdminRole (needs iam:PassRole + lambda:CreateFunction)
aws lambda create-function --function-name pwn \
  --runtime python3.12 --handler index.handler \
  --role arn:aws:iam::123456789012:role/AdminRole \
  --zip-file fileb://payload.zip

# 2. The Lambda code calls AWS APIs with AdminRole's permissions, e.g. create a new admin user
aws lambda invoke --function-name pwn out.json
```

Or via EC2 + IMDS:

```bash
# Launch an EC2 with AdminRole attached, then read the credentials from IMDS inside it
aws ec2 run-instances --image-id ami-xxx --instance-type t3.micro \
  --iam-instance-profile Name=AdminInstanceProfile
# Then SSH/SSM in and curl IMDS to obtain AdminRole's credentials.
```

**Defense:**
- Restrict `iam:PassRole` to a specific role via `Resource` (do not use `"Resource":"*"`).
- Use the `iam:PassedToService` condition to restrict the role to being passed only to the correct service.

```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::123456789012:role/app-limited-role",
  "Condition": { "StringEquals": { "iam:PassedToService": "lambda.amazonaws.com" } }
}
```

**Detection:** in CloudTrail, look for `RunInstances`/`CreateFunction` whose `requestParameters` contain a high-privilege role ARN, called by a non-admin principal. The Pacu tool (an AWS exploitation framework) has a module that enumerates escalation paths:

```bash
pacu
> run iam__enum_permissions
> run iam__privesc_scan
```

### 13.15.4. Exposed bucket — detection and exploitation

```bash
# Try anonymous listing
aws s3 ls s3://target-bucket --no-sign-request
aws s3 cp s3://target-bucket/secret.txt . --no-sign-request
```

`--no-sign-request` = do not send credentials => tests whether the bucket allows anonymous (public) access. Defensive detection: enable account-wide BPA, Macie to scan for PII, the Config rule `s3-bucket-public-read-prohibited`.

---

## 13.16. CSPM — Cloud Security Posture Management

### 13.16.1. What it is

CSPM automatically scans cloud configuration against benchmarks (CIS, PCI) and continuously detects deviations. Native: AWS Security Hub + Config, GCP SCC. Open source: **Prowler**, **ScoutSuite**.

### 13.16.2. Prowler — practical example

```bash
# Run all checks against the CIS benchmark, export HTML + JSON
prowler aws --compliance cis_2.0_aws --output-formats html json-ocsf
```

Sample output (abbreviated):

```
FAIL  s3_bucket_public_access  company-reports  Bucket allows public read
FAIL  iam_root_mfa_enabled     account 1234     Root account MFA not enabled
PASS  cloudtrail_multi_region  account 1234     Multi-region trail enabled
```

### 13.16.3. ScoutSuite

```bash
scout aws --report-dir ./scout-report
# Open ./scout-report/scoutsuite-results/...html to view the risk dashboard by service
```

### 13.16.4. AWS Config rule (native CSPM)

```bash
# Enable a managed rule that checks buckets are not public
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-no-public-read",
  "Source": { "Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED" }
}'
```

Config continuously evaluates resources as they change and flags them NON_COMPLIANT, and can auto-remediate via SSM Automation.

---

## 13.17. Secret Manager

### 13.17.1. AWS Secrets Manager

Stores secrets (DB passwords, API keys) encrypted with KMS, and supports **automatic rotation** via a Lambda rotation function.

```bash
aws secretsmanager create-secret --name prod/db/password \
  --secret-string '{"username":"app","password":"S3cr3t!"}' \
  --kms-key-id alias/app-cmk

aws secretsmanager get-secret-value --secret-id prod/db/password \
  --query SecretString --output text
```

Compared to Parameter Store: Secrets Manager has built-in rotation + charges per secret; SSM Parameter Store (SecureString) is cheaper but does not rotate automatically.

### 13.17.2. GCP Secret Manager

Versions are immutable; access is controlled via the IAM role `roles/secretmanager.secretAccessor`.

```bash
echo -n "S3cr3t!" | gcloud secrets create db-pass --data-file=-
gcloud secrets versions access latest --secret=db-pass
```

**Warning** (general security): (1) never pass a secret through an environment variable that shows up in logs/`ps`; prefer fetching it at runtime; (2) grant read access to secrets per least privilege and enable an audit log on every access; (3) enable periodic rotation.

---

## 13.18. Summary of core defensive principles

| Principle | Concrete application |
|---|---|
| Least privilege | Fine-grained IAM/roles, specific Resources/compartments, drop `*` |
| Explicit deny guardrail | SCP / Org Policy / permission boundary (OCI has no Deny — tighten via compartment scope) |
| Eliminate long-lived credentials | IAM Role/SA token/Instance Principal instead of access keys; WIF; IMDSv2 |
| Encryption by default | SSE-KMS/CMEK/OCI Vault key + block non-TLS |
| Observability | CloudTrail + Config + GuardDuty / Audit Logs + SCC / OCI Audit + Cloud Guard, immutable logs |
| Block public by default | S3 BPA / Uniform bucket-level access / OCI buckets private by default |
| Continuous detection | CSPM (Prowler/ScoutSuite/SCC/Cloud Guard) + secret scanning in CI |
| Environment boundary | Split by prod vs non-prod (not by provider); prod on the "dev" cloud locked as tightly as main prod |

All cloud security architecture reduces to: **tight identity control (IAM), eliminating long-lived secrets, encrypting everywhere, complete and immutable logging, blocking public access by default, and continuously scanning for misconfigurations.** Most real-world incidents lie within "IN the cloud" — that is, within your control and your responsibility.


---

## My notes

> *Personal notes: points I previously misunderstood, areas I'm still exploring, or lessons from hands-on practice — updated over time.*

**From AWS to OCI — the spots where my mental model failed me.** I learned cloud on AWS first, so when I had to also operate OCI (dev and part of prod) I tripped exactly on the concepts that look similar but aren't:

- **A compartment is not an account.** At first I kept looking for "create a sub-account" like AWS Organizations, and only later realized OCI isolates with compartments *inside a single tenancy*. The security consequence: the boundary is weaker than account separation, so a policy written at the tenancy level can leak permissions down into every compartment. Since then I carefully scope `in compartment <specific>` rather than `in tenancy` for convenience.
- **Policy as sentences, and NO Deny.** The `Allow group … to manage … in compartment …` syntax reads pleasantly, but it took me a while to internalize that there is *no explicit `Deny`* like an SCP. The AWS habit of building guardrails with explicit Deny doesn't carry straight over — you have to rethink it as "grant only the right scope," or use Network Sources/tags. This is something I'm still exploring: what to use as a tidy tenancy-level guardrail on OCI equivalent to an SCP.
- **Two firewall layers, Security List + NSG.** Once I changed a rule on an NSG and the packet still wouldn't flow; after debugging I remembered the subnet's Security List was still blocking — both must allow it (AND). And a Security List is **stateful by default** (unlike AWS NACLs, which are stateless), so don't mechanically open the ephemeral port range out of NACL habit. Now my rule of thumb: segment the network with NSGs (NSG-to-NSG references), keep Security Lists minimal.
- **Private-by-default buckets are a real plus.** After the classic "S3 public-read" trauma, OCI Object Storage being private by default is a relief — but I still enable Cloud Guard so it flags anything that gets flipped to public. To share a file I issue a time-limited Pre-Authenticated Request, never leaving a bucket public "for convenience."
- **The `Bearer Oracle` metadata header is not a secret.** At first I assumed the `Authorization: Bearer Oracle` header was some kind of token and felt reassured. It isn't — it's a fixed constant, blocking only *naive* SSRF (the kind that can't add a header). An SSRF that controls headers still gets through. So I still apply the full SSRF defense set at the app layer and treat metadata v2 (both AWS and OCI) as just one extra layer.

**The biggest multi-cloud lesson:** the real security boundary is **prod vs non-prod**, not AWS vs OCI. For prod running on OCI I enforce the same tight standard as prod on AWS — the trap is letting a prod compartment "inherit" dev's loose habits because they share a tenancy. Having prod-AWS and dev-OCI separate both provider and credentials is a *fortuitous* blast-radius advantage, but I don't lean on it in place of configuration discipline.

**Still exploring:** standardizing both clouds with Terraform + policy-as-code (Checkov/Trivy scanning both AWS and OCI) to avoid remembering two ways of configuring by hand; and how to funnel Cloud Guard (OCI) logs/alerts together with GuardDuty/Config (AWS) into one place so a single person can still keep up.
