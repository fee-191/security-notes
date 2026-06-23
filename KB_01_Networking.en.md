# Chapter 1 — Computer Networking (TCP/IP, OSI)

## Overview

This chapter explains how data is transmitted between computers across a network, from the moment a byte leaves an application process until it reaches its destination. This is foundational knowledge for information security work: most attack techniques (eavesdropping, spoofing, interception, denial of service) take place at a specific layer of the network stack. Understanding how each layer operates helps you identify the attack surface and the points that need to be defended.

Here is a quick map of the concepts in this chapter; the full definitions and mechanics live in each section below.

- **Layered models (OSI & TCP/IP)** — a network is organized into stacked layers, each serving the layer above through a fixed interface. OSI is the 7-layer theoretical model; TCP/IP is the 4-layer model that actually runs on the Internet.
- **Encapsulation / Decapsulation** — data is wrapped sequentially through the layers, each layer adding a header before passing it down; the receiver unwraps in reverse. Each header carries information that both analysis tools and attackers can read.
- **Layer 2 — Ethernet, MAC, VLAN, ARP, switch** — hardware identification and frame exchange within the same LAN.
- **Layer 3 — IP, ICMP, routing, NAT** — logical identification and routing across multiple networks to a destination.
- **Layer 4 — TCP and UDP** — transporting data and using ports to demultiplex to the correct application.
- **Common ports** — a host has one IP but many services; ports distinguish each service and reflect the attack surface.
- **Layer 7 — DNS, DHCP, HTTP, TLS** — the application protocols we meet every day.
- **Firewalls, DMZ, packet analysis tools** — filtering packets by policy, isolating the Internet-facing zone, and capturing/reading packets with tcpdump/Wireshark.

> This handbook is for people learning and doing information security (Blue Team / AppSec / DevSecOps). Each topic follows a familiar flow: what the concept is, the internal mechanics (down to the bit/byte/step/parameter), an example you can actually run, and then a few security notes. Data structures are described down to the individual field, its size, and offset; each tool comes with the commands, configuration, and sample output so you can type them out yourself.

---

## 1.1. Two reference models: the 7-layer OSI and TCP/IP

### 1.1.1. Why we need a layered model

Moving data across a network involves a lot of moving parts: representing bits on copper/fiber, addressing machines, routing through dozens of routers, ensuring reliability, encryption, and representing application data. Lump it all into a single monolithic block and it becomes nearly impossible to maintain — and impossible to swap out one piece of technology at a time (copper to fiber, IPv4 to IPv6) without breaking everything.

The solution is **layering**: each layer provides services to the layer above and uses the services of the layer below, through a fixed **interface**. The core principles:

- **Encapsulation**: the upper layer's data is treated by the lower layer as an opaque payload, wrapped with the lower layer's header (and sometimes trailer).
- **Separation of concerns**: TCP does not need to know whether the packet travels over Ethernet or Wi-Fi; IP does not need to know whether the payload is TCP or UDP.
- **Interchangeability**: you can replace the physical layer without changing the IP layer.

### 1.1.2. The OSI model (ISO/IEC 7498-1)

| Layer | Name | PDU | Core function | Example protocols/devices |
|------|-----|-----|-------------------|---------------------------|
| 7 | Application | Data | Interface for applications | HTTP, DNS, SMTP, FTP |
| 6 | Presentation | Data | Encoding, compression, data representation | TLS, ASCII/UTF-8, JPEG |
| 5 | Session | Data | Establishing/maintaining/terminating sessions | RPC, NetBIOS, SOCKS |
| 4 | Transport | Segment (TCP) / Datagram (UDP) | Ports, reliability, flow control | TCP, UDP, SCTP, QUIC |
| 3 | Network | Packet | Logical addressing, routing | IPv4, IPv6, ICMP, IPsec |
| 2 | Data Link | Frame | Physical addressing (MAC), media access | Ethernet, 802.11, ARP, VLAN |
| 1 | Physical | Bit/Symbol | Representing bits as signals | Copper, fiber, RF, NIC PHY |

> Note on PDUs — at Layer 4, TCP is called a *segment* and UDP a *datagram*; Layer 3 is a *packet*; Layer 2 is a *frame*; Layer 1 is a *bit/symbol*.

### 1.1.3. The TCP/IP model (RFC 1122)

TCP/IP is the de facto model of the Internet. RFC 1122 divides it into 4 layers:

| TCP/IP layer | OSI mapping | Representative protocols |
|-------------|------------|---------------------|
| Application | 7 + 6 + 5 | HTTP, DNS, TLS (usually grouped here), SMTP |
| Transport | 4 | TCP, UDP |
| Internet | 3 | IPv4, IPv6, ICMP, ARP (blurry boundary with L2) |
| Link / Network Access | 2 + 1 | Ethernet, Wi-Fi, PPP |

**Why two models?** OSI is a theoretical model (the 1984 specification) that is complete and used for teaching and standardizing terminology. TCP/IP came out of ARPANET, is simpler, and is what actually runs on the Internet. A security engineer must be fluent in both because tools and documentation mix the two conventions (for example "L7 firewall", "L2 attack", "L3/L4 ACL").

---

## 1.2. Encapsulation / Decapsulation byte-by-byte

### 1.2.1. The wrapping process when sending

Suppose a browser sends an HTTP `GET /` request to a web server on the same LAN over HTTP (without TLS, for simplicity).

```
Layer 7 (HTTP)  : [ "GET / HTTP/1.1\r\nHost: x\r\n\r\n" ]               <- App data (D)
Layer 4 (TCP)   : [ TCP header 20B | D ]                                <- Segment
Layer 3 (IP)    : [ IPv4 header 20B | TCP header 20B | D ]              <- Packet
Layer 2 (Eth)   : [ Eth header 14B | IPv4 20B | TCP 20B | D | FCS 4B ]  <- Frame
Layer 1 (PHY)   : [ Preamble 7B | SFD 1B | <Frame on the wire> ]        <- Bit stream
```

Each layer **adds only its own header** and treats everything received from the layer above as an opaque payload. This is why each header must have a "protocol/next header" field so the receiver knows which protocol the payload belongs to (see `EtherType`, the IPv4 `Protocol` field, and TCP ports).

### 1.2.2. The unwrapping process when receiving (decapsulation)

The receiver does the reverse: each layer reads its own header, checks it (checksum/FCS), strips it off, then pushes the payload up to the layer above based on the "next protocol" field:

```
PHY  : receive bits -> detect Preamble/SFD to sync clock -> obtain frame
L2   : check FCS (CRC32). EtherType=0x0800 -> push up to IPv4
L3   : check IP checksum, verify Dst IP is ours, Protocol=6 -> TCP
L4   : check TCP checksum, use Dst Port=80 -> push up to the process listening on port 80
L7   : web server parses "GET / HTTP/1.1"
```

### 1.2.3. Real-world example: viewing each layer with tcpdump

```bash
# -X prints hex+ASCII, -e prints the Ethernet header too, -nn skips name/port resolution
sudo tcpdump -i eth0 -e -nn -X 'tcp port 80 and host 93.184.216.34' -c 1
```

Sample output (abbreviated and annotated):

```
14:02:11.123456 aa:bb:cc:11:22:33 > de:ad:be:ef:00:01, ethertype IPv4 (0x0800), length 74:
    10.0.0.5.54321 > 93.184.216.34.80: Flags [S], seq 1001, win 64240,
    options [mss 1460,sackOK,TS val 1 ecr 0,nop,wscale 7], length 0
    0x0000:  dead beef 0001 aabb cc11 2233 0800 4500   <- Eth(14) + IP starts (45=Ver4,IHL5)
    0x0010:  003c 1c46 4000 4006 ...                    <- TotalLen 0x3c=60, Flags+FragOff, TTL=0x40=64, Proto=0x06=TCP
    ...
```

- `dead beef 0001` = Dst MAC; `aabb cc11 2233` = Src MAC; `0800` = EtherType IPv4.
- `45` = `0100 0101` -> Version 4, IHL 5 (5×4=20 bytes).
- `40` (at the TTL offset) = TTL 64; `06` = Protocol 6 = TCP.

---

## 1.3. Layer 2 — Ethernet, MAC, VLAN, ARP, switch

### 1.3.1. The Ethernet II frame — field-by-field layout

Ethernet II (DIX) is the most common format in use today (unlike IEEE 802.3, which uses a Length field instead of EtherType).

| Field | Size | Offset (in the frame on the wire) | Meaning | Example |
|--------|-----------|-------------------------------|---------|-------|
| Preamble | 7 bytes | 0 | 7 bytes of `0xAA` (`10101010…`) to sync the clock | `AA AA AA AA AA AA AA` |
| SFD (Start Frame Delimiter) | 1 byte | 7 | `0xAB` (`10101011`), final bit =1 signals the start of the frame | `AB` |
| Destination MAC | 6 bytes | 8 | Destination MAC | `de:ad:be:ef:00:01` |
| Source MAC | 6 bytes | 14 | Source MAC | `aa:bb:cc:11:22:33` |
| EtherType / Length | 2 bytes | 20 | ≥0x0600 = EtherType; <0x0600 = Length (802.3) | `0x0800` (IPv4) |
| Payload | 46–1500 bytes | 22 | Upper-layer data (IP packet) | … |
| FCS (Frame Check Sequence) | 4 bytes | end | CRC-32 over Dst..Payload | `0x1c2d3e4f` |

> **The Preamble + SFD (8 bytes) are not counted as part of the frame** when captured with tcpdump/Wireshark (the NIC strips them first). They are also not part of the MTU.

**Common EtherTypes:**

| EtherType | Protocol |
|-----------|-----------|
| 0x0800 | IPv4 |
| 0x0806 | ARP |
| 0x86DD | IPv6 |
| 0x8100 | VLAN tag 802.1Q |
| 0x8847 | MPLS unicast |

**MTU and sizes:**
- **Default Ethernet MTU = 1500 bytes** (maximum payload). Maximum frame (excluding preamble/SFD) = 14 (header) + 1500 + 4 (FCS) = **1518 bytes**. With a VLAN tag, add 4 bytes → 1522.
- **Minimum payload 46 bytes**: if smaller, it must be **padded** with zeros to reach the minimum. Why? So the minimum frame reaches 64 bytes (to ensure collision detection in old half-duplex Ethernet — the slot time).
- **Jumbo frame**: MTU 9000 (not an IEEE standard but common in datacenters/SANs).

**Structure of a MAC address (48 bits):**
```
AA:BB:CC:DD:EE:FF
└── OUI (24 bits) ──┘└── NIC-specific (24 bits) ──┘
First byte (AA): bit 0 (I/G) = 1 -> multicast; =0 -> unicast
                 bit 1 (U/L) = 1 -> locally administered; =0 -> universal (real OUI)
Broadcast = FF:FF:FF:FF:FF:FF
```

### 1.3.2. VLAN — IEEE 802.1Q tag (4 bytes)

When you need to logically separate multiple networks over the same physical infrastructure, the switch inserts a **4-byte 802.1Q tag** into the frame, immediately after the Source MAC.

```
[ Dst MAC 6B | Src MAC 6B | 802.1Q TAG 4B | EtherType 2B | Payload | FCS 4B ]
                                   │
                                   ▼
              ┌──────────────────────────────────────────┐
              │ TPID 16b | PCP 3b | DEI 1b | VID 12b       │
              └──────────────────────────────────────────┘
```

| Field | Size | Meaning | Example |
|--------|-----------|---------|-------|
| TPID (Tag Protocol ID) | 16 bits | `0x8100` signals this is 802.1Q | `0x8100` |
| PCP (Priority Code Point) | 3 bits | QoS priority (0–7) | `5` (voice) |
| DEI (Drop Eligible Indicator) | 1 bit | Marks the frame as droppable under congestion | `0` |
| VID (VLAN ID) | 12 bits | VLAN ID (0–4095; 0 and 4095 are reserved) | `100` |

- A 12-bit VID → up to **4094 usable VLANs**. **Native VLAN**: on a trunk port, the untagged VLAN.
- **Note: VLAN hopping.**
  - *Double tagging*: the attacker attaches 2 tags; the switch strips the outer tag (native VLAN) and forwards across the trunk still carrying the inner tag → the frame jumps to another VLAN. Mitigation: set the native VLAN to a "dead" unused VLAN, or tag the native VLAN as well (`vlan dot1q tag native`).
  - *Switch spoofing*: the attacker forges DTP to turn an access port into a trunk. Mitigation: disable DTP (`switchport mode access`, `switchport nonegotiate`).

### 1.3.3. ARP — Address Resolution Protocol (RFC 826)

ARP maps an IP address (L3) to a MAC address (L2) within the same broadcast domain. Before sending an IP packet to a host on the same subnet, a machine must know that host's MAC.

**ARP packet layout (28 bytes for IPv4-over-Ethernet), placed in the Ethernet payload with EtherType 0x0806:**

| Field | Size | Meaning | Example |
|--------|-----------|---------|-------|
| Hardware Type (HTYPE) | 2 bytes | L2 type; Ethernet = 1 | `0x0001` |
| Protocol Type (PTYPE) | 2 bytes | L3 type; IPv4 = 0x0800 | `0x0800` |
| Hardware Addr Len (HLEN) | 1 byte | MAC length = 6 | `0x06` |
| Protocol Addr Len (PLEN) | 1 byte | IP length = 4 | `0x04` |
| Operation (OPER) | 2 bytes | 1=request, 2=reply | `0x0001` |
| Sender Hardware Addr (SHA) | 6 bytes | Sender's MAC | `aa:bb:cc:11:22:33` |
| Sender Protocol Addr (SPA) | 4 bytes | Sender's IP | `10.0.0.5` |
| Target Hardware Addr (THA) | 6 bytes | Target MAC (0 in a request) | `00:00:00:00:00:00` |
| Target Protocol Addr (TPA) | 4 bytes | The IP being queried | `10.0.0.1` |

**Request/reply process:**
1. Host A (`10.0.0.5`) wants to send to `10.0.0.1`, which is not in its ARP cache.
2. A broadcasts an ARP request: Eth Dst = `ff:ff:ff:ff:ff:ff`, OPER=1, TPA=`10.0.0.1`, THA=0.
3. Every host in the broadcast domain receives it; only `10.0.0.1` replies.
4. B unicasts an ARP reply back to A: OPER=2, SHA = B's MAC, SPA=`10.0.0.1`.
5. A stores the pair `10.0.0.1 → MAC_B` in its ARP cache (timeout of tens of seconds to a few minutes).

**Real-world example:**
```bash
ip neigh show                 # View the ARP cache (modern Linux)
# 10.0.0.1 dev eth0 lladdr de:ad:be:ef:00:01 REACHABLE
arping -I eth0 10.0.0.1        # Send an ARP request manually
sudo tcpdump -i eth0 -nn arp  # Capture ARP packets
```

**ARP spoofing/poisoning.** **Note:** ARP has no authentication. The attacker continuously sends **fake ARP replies** (gratuitous ARP): "the gateway IP `10.0.0.1` has MAC = attacker's MAC". The victim overwrites its cache → all traffic destined for the gateway passes through the attacker's machine (Man-in-the-Middle).

```bash
# Demonstration (only in an authorized lab):
sudo arpspoof -i eth0 -t 10.0.0.5 10.0.0.1   # tell .5 that .1 is me
# Combine with enabling ip_forward so traffic is not interrupted:
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```
Defense: **Dynamic ARP Inspection (DAI)** on the switch (validating ARP against the DHCP snooping binding), static ARP for important gateways, port security, and monitoring mapping changes (arpwatch).

### 1.3.4. Switch CAM table (MAC address table)

A switch learns MACs by looking at the **Source MAC** of frames arriving on each port and storing them in the CAM table: `MAC → port`. When forwarding, it looks up the Dst MAC:
- Present in the CAM → send to the correct port (unicast).
- Absent (unknown unicast) or broadcast/multicast → flood out all ports except the ingress port.

**Security — CAM table overflow / MAC flooding:** the attacker pumps thousands of frames with random Source MACs (`macof`) to fill the CAM table. Once full, the switch floods all traffic like a hub → the attacker can sniff. Mitigation: **port security** limits the number of MACs per port.

```
Switch(config-if)# switchport port-security
Switch(config-if)# switchport port-security maximum 2
Switch(config-if)# switchport port-security violation shutdown
Switch(config-if)# switchport port-security mac-address sticky
```

---

## 1.4. Layer 3 — IPv4, IPv6, ICMP, routing, NAT

### 1.4.1. IPv4 header — 20-byte layout (without Options)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |DSCP   |ECN|         Total Length              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|    Fragment Offset      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  TTL          |   Protocol    |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source IP Address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination IP Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Options (if IHL>5)             |   Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Offset (byte) | Meaning | Example |
|--------|-----------|---------------|---------|-------|
| Version | 4 bits | 0 | IP version = 4 | `4` |
| IHL (Internet Header Length) | 4 bits | 0 | Header length in units of 4 bytes; min 5 (=20B), max 15 (=60B) | `5` |
| DSCP | 6 bits | 1 | Differentiated Services (QoS) | `0` |
| ECN | 2 bits | 1 | Explicit Congestion Notification | `0` |
| Total Length | 16 bits | 2 | Total length of header+payload (bytes); max 65535 | `60` |
| Identification | 16 bits | 4 | Datagram ID, used for reassembly | `0x1c46` |
| Flags | 3 bits | 6 | bit0=reserved(0), bit1=DF (Don't Fragment), bit2=MF (More Fragments) | `010` (DF) |
| Fragment Offset | 13 bits | 6 | Fragment position (in units of 8 bytes) | `0` |
| TTL (Time To Live) | 8 bits | 8 | Remaining hop count; each router −1; =0 means drop + ICMP | `64` |
| Protocol | 8 bits | 9 | Payload protocol: 1=ICMP,6=TCP,17=UDP | `6` |
| Header Checksum | 16 bits | 10 | Checksum of the header only | `0xb1e6` |
| Source IP | 32 bits | 12 | Source IP | `10.0.0.5` |
| Destination IP | 32 bits | 16 | Destination IP | `93.184.216.34` |
| Options | 0–40 bytes | 20 | Options (record route, timestamp…) | — |

**Why TTL?** It prevents a packet from circling forever during a routing loop. `traceroute` exploits the TTL: it sends packets with TTL=1,2,3…; each router that drops the packet at TTL=0 returns an ICMP Time Exceeded, revealing its IP.

**Header Checksum** uses the one's complement sum of the 16-bit half-words of the header. Because the TTL changes at every hop, each router must recompute the checksum at every hop (the reason IPv6 dropped this checksum to reduce load).

### 1.4.2. Fragmentation (IPv4 fragmentation)

When a packet is larger than the MTU of the next link and the DF flag is not set, the router splits it into multiple fragments.

Example: a datagram with a 4000-byte payload over a link with MTU 1500 (maximum IP payload = 1500−20 = 1480, which must be a multiple of 8 → use 1480).

| Fragment | Data bytes | Fragment Offset (units of 8B) | MF | Total Length |
|------|-----------|-----------------------------|----|--------------|
| 1 | 0–1479 | 0 | 1 | 1500 |
| 2 | 1480–2959 | 185 (=1480/8) | 1 | 1500 |
| 3 | 2960–3999 | 370 (=2960/8) | 0 | 1060 |

All fragments use the **same Identification**. The receiver reassembles them by offset. **Security:** overlapping fragment attacks (Teardrop), tiny fragments bypassing firewalls, fragment-based IDS evasion. Mitigation: have the firewall reassemble fragments before inspecting (virtual reassembly).

### 1.4.3. IPv6 header — fixed 40-byte layout

```
 0                   1                   2                   3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| Traffic Class |           Flow Label                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Payload Length        |  Next Header  |   Hop Limit   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                 Source Address (128 bits)                     +
|                      ... (16 bytes) ...                       |
+                                                               +
|                                                               |
+               Destination Address (128 bits)                  +
|                      ... (16 bytes) ...                       |
+                                                               +
```

| Field | Size | Meaning | Example |
|--------|-----------|---------|-------|
| Version | 4 bits | = 6 | `6` |
| Traffic Class | 8 bits | DSCP+ECN, similar to IPv4 | `0` |
| Flow Label | 20 bits | Marks a flow for QoS | `0x12345` |
| Payload Length | 16 bits | Payload length (excluding the 40B header) | `1280` |
| Next Header | 8 bits | Like the IPv4 Protocol field; also points to extension headers | `6` (TCP) |
| Hop Limit | 8 bits | Like TTL | `64` |
| Source Address | 128 bits | Source IPv6 | `2001:db8::1` |
| Destination Address | 128 bits | Destination IPv6 | `2001:db8::2` |

**Important design differences:** a fixed 40B header (no IHL/Options in the main header — uses chained *extension headers* via Next Header); no checksum (delegated to the L2 FCS and the L4 checksum); routers do not fragment (the host uses Path MTU Discovery instead); minimum MTU of 1280B. IPv6 does not use ARP but uses **NDP (Neighbor Discovery Protocol)** over ICMPv6.

### 1.4.4. ICMP (RFC 792)

Placed in the IP payload with Protocol=1. Common 8-byte header:

| Field | Size | Meaning | Example |
|--------|-----------|---------|-------|
| Type | 1 byte | Message type | `8` (Echo Request) |
| Code | 1 byte | Sub-code | `0` |
| Checksum | 2 bytes | ICMP checksum | `0xf7ff` |
| Rest of Header | 4 bytes | Depends on Type (Echo: Identifier 2B + Sequence 2B) | id=0x1234 seq=1 |

**Important Type/Code values:**

| Type | Code | Meaning |
|------|------|---------|
| 0 | 0 | Echo Reply (ping reply) |
| 3 | 0–15 | Destination Unreachable (3=port unreachable, 4=frag needed+DF) |
| 5 | 0–3 | Redirect |
| 8 | 0 | Echo Request (ping) |
| 11 | 0 | Time Exceeded (TTL=0, used for traceroute) |

```bash
ping -c 3 8.8.8.8
sudo tcpdump -i eth0 -nn icmp
# ICMP type 8 = request; type 0 = reply; type 11 = traceroute hops
```
**Security:** ICMP tunneling (smuggling data inside the Echo payload to bypass firewalls — `ptunnel`), ICMP redirect spoofing, smurf attack (broadcast amplification). Many places rate-limit/filter ICMP but you should NOT block `Type 3 Code 4`, as that would break PMTUD.

### 1.4.5. RFC 1918, CIDR, and manual subnetting

**RFC 1918 — private IP ranges:**

| Range | CIDR | Number of addresses |
|-----|------|------------|
| 10.0.0.0 – 10.255.255.255 | 10.0.0.0/8 | 16,777,216 |
| 172.16.0.0 – 172.31.255.255 | 172.16.0.0/12 | 1,048,576 |
| 192.168.0.0 – 192.168.255.255 | 192.168.0.0/16 | 65,536 |

Others: `127.0.0.0/8` loopback; `169.254.0.0/16` link-local (APIPA); `100.64.0.0/10` CGNAT (RFC 6598).

**CIDR (Classless Inter-Domain Routing):** the `/n` notation = the first n bits are the network portion (netmask). Example: `/24` → mask `255.255.255.0`, 8 host bits → `2^8 = 256` addresses, `256 − 2 = 254` usable hosts (minus the network address and the broadcast address).

**Manual subnetting — a step-by-step example:** divide `192.168.1.0/24` into 4 equal subnets.

1. We need 4 subnets → we need to borrow `log2(4) = 2` bits from the host portion. New prefix: `/24 + 2 = /26`.
2. The `/26` mask = `255.255.255.192` (last byte `11000000` = 192).
3. Block size (step) = `256 − 192 = 64`.
4. Enumerate:

| Subnet | Network | Usable host range | Broadcast |
|--------|---------|--------------------|-----------|
| 1 | 192.168.1.0/26 | .1 – .62 | 192.168.1.63 |
| 2 | 192.168.1.64/26 | .65 – .126 | 192.168.1.127 |
| 3 | 192.168.1.128/26 | .129 – .190 | 192.168.1.191 |
| 4 | 192.168.1.192/26 | .193 – .254 | 192.168.1.255 |

Each subnet: `2^(32−26) = 64` addresses, with `64 − 2 = 62` usable hosts.

**Determining whether an IP belongs to a subnet (bitwise AND):** IP `192.168.1.130` with the `/26` mask:
```
IP:    11000000.10101000.00000001.10000010
Mask:  11111111.11111111.11111111.11000000
AND:   11000000.10101000.00000001.10000000  = 192.168.1.128  -> Subnet 3
```

```bash
ipcalc 192.168.1.130/26     # quick calculation tool
sipcalc 192.168.1.0/24 -s 26
```

### 1.4.6. NAT / PAT / SNAT / DNAT

**NAT (Network Address Translation):** translates the IP (and port) when a packet passes through the border router. Reason for existence: IPv4 exhaustion; many private hosts share a single public IP.

| Type | What it translates | Used for |
|------|---------|----------|
| Static NAT (1:1) | 1 private ↔ 1 fixed public | Servers needing a stable public address |
| Dynamic NAT | private ↔ public from a pool | Many hosts, a public pool |
| **PAT / NAPT / Overload** | many private → 1 public, distinguished by **port** | The most common case at home/office |
| **SNAT** (Source NAT) | changes the Source IP (outbound) | LAN → Internet |
| **DNAT** (Destination NAT) | changes the Dst IP (inbound) | Port forwarding to an internal server |

**PAT translation table:**

| Inside Local | Inside Global | Outside | Protocol |
|--------------|---------------|---------|----------|
| 10.0.0.5:54321 | 203.0.113.10:40001 | 93.184.216.34:80 | TCP |
| 10.0.0.6:51000 | 203.0.113.10:40002 | 1.1.1.1:443 | TCP |

The router replaces the Source `10.0.0.5:54321` → `203.0.113.10:40001` on the way out, and does the reverse for the return packet based on port 40001.

**Real-world example — iptables/nftables:**
```bash
# SNAT/MASQUERADE: LAN 10.0.0.0/24 going out via eth0
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE

# DNAT: forward public:8080 -> internal server 10.0.0.50:80
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 8080 \
  -j DNAT --to-destination 10.0.0.50:80
sudo iptables -A FORWARD -p tcp -d 10.0.0.50 --dport 80 -j ACCEPT

# View the active NAT table
sudo conntrack -L
```
**Security:** NAT is not a firewall (a common misconception). NAT slipstreaming, hairpin NAT, and exposing ports to the Internet via DNAT are a large attack surface.

### 1.4.7. Basic routing

A router decides the next-hop using **longest prefix match** in the routing table.
```bash
ip route show
# default via 10.0.0.1 dev eth0
# 10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5
ip route get 8.8.8.8     # see which route a packet will take
```
The default route `0.0.0.0/0` is "match every destination" with the shortest prefix (used only when there is no more specific route).

---

## 1.5. Layer 4 — TCP and UDP

### 1.5.1. UDP header — 8-byte layout (RFC 768)

| Field | Size | Offset | Meaning | Example |
|--------|-----------|--------|---------|-------|
| Source Port | 16 bits | 0 | Source port | `54321` |
| Destination Port | 16 bits | 2 | Destination port | `53` |
| Length | 16 bits | 4 | Length of header+data (≥8) | `40` |
| Checksum | 16 bits | 6 | Checksum (optional in IPv4, mandatory in IPv6) | `0x1a2b` |

UDP has no handshake, no guarantee of ordering/reliability, and no flow control. Used for DNS, DHCP, VoIP, QUIC. **The UDP/TCP checksum** is computed over a **pseudo-header** consisting of the Src IP, Dst IP, Protocol, and Length from the IP layer — to detect packets delivered to the wrong address.

### 1.5.2. TCP header — 20-byte layout (without Options), RFC 9293

```
 0                   1                   2                   3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| DOff  |Rsv|N|C|E|U|A|P|R|S|F|         Window Size              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |        Urgent Pointer         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options (if DOff>5)          |   Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Offset | Meaning | Example |
|--------|-----------|--------|---------|-------|
| Source Port | 16 bits | 0 | Source port | `54321` |
| Destination Port | 16 bits | 2 | Destination port | `443` |
| Sequence Number | 32 bits | 4 | Sequence number of the first byte of the segment (or the ISN when SYN) | `1001` |
| Acknowledgment Number | 32 bits | 8 | Next byte expected to receive (valid when ACK=1) | `2001` |
| Data Offset (DOff) | 4 bits | 12 | TCP header length in units of 4 bytes (min 5=20B) | `5` |
| Reserved | 3 bits | 12 | =0 | `0` |
| Flags (9 bits) | 9 bits | 12–13 | See below | — |
| Window Size | 16 bits | 14 | Number of bytes in the receive window | `64240` |
| Checksum | 16 bits | 16 | Checksum (including the pseudo-header) | `0x4a8c` |
| Urgent Pointer | 16 bits | 18 | Offset of urgent data (when URG=1) | `0` |

**The 9 TCP flags (from high bit to low bit):**

| Flag | Name | Meaning |
|----|-----|---------|
| NS | Nonce Sum | ECN nonce (RFC 3540, rarely used) |
| CWR | Congestion Window Reduced | Signals that cwnd was reduced due to congestion |
| ECE | ECN-Echo | Signals that a congestion indication was received |
| URG | Urgent | The Urgent Pointer is valid |
| ACK | Acknowledgment | The Ack Number is valid |
| PSH | Push | Push data up to the app immediately, do not buffer |
| RST | Reset | Abruptly tear down the connection |
| SYN | Synchronize | Initiate a connection, synchronize the seq |
| FIN | Finish | End data transmission in one direction |

**Common TCP Options (in the Options region):**

| Option | Kind | Length | Meaning |
|--------|------|--------|---------|
| End of Option List | 0 | 1B | End of the options |
| No-Operation (NOP) | 1 | 1B | Padding to align to 4 bytes |
| MSS (Maximum Segment Size) | 2 | 4B | Maximum segment size, usually 1460 (1500−40) |
| Window Scale | 3 | 3B | Window scaling factor (left shift), up to ×2^14 |
| SACK Permitted | 4 | 2B | Permits Selective ACK |
| SACK | 5 | variable | Reports discontiguous received blocks |
| Timestamps | 8 | 10B | TSval/TSecr to measure RTT, protect against wrap (PAWS) |

### 1.5.3. The 3-way handshake — seq/ack values at each step

```
Client (10.0.0.5)                                  Server (1.2.3.4:443)
        |                                                  |
        |  1. SYN  seq=x (ISN_c=1000), ack=0               |
        |------------------------------------------------->|   Flags=[S]
        |                                                  |
        |  2. SYN-ACK  seq=y (ISN_s=5000), ack=x+1=1001    |
        |<-------------------------------------------------|   Flags=[S.]
        |                                                  |
        |  3. ACK  seq=x+1=1001, ack=y+1=5001              |
        |------------------------------------------------->|   Flags=[.]
        |                                                  |
   (connection ESTABLISHED, data begins at seq=1001/5001)
```

Detailed explanation:
1. The client chooses a random **ISN (Initial Sequence Number)** (=1000) and sends a SYN with seq=1000. A SYN consumes 1 sequence number (even though it carries no data).
2. The server chooses its own ISN (=5000) and sends a SYN-ACK: seq=5000, ack=1001 (acknowledging receipt of seq 1000, expecting the next byte to be 1001).
3. The client sends an ACK: seq=1001, ack=5001. The connection becomes ESTABLISHED.

**Why a random ISN?** To defend against the TCP sequence prediction attack (an outsider guessing the seq to inject/spoof). RFC 6528 requires the ISN to be a secret hash function.

**Security — SYN flood:** the attacker sends a burst of SYNs with spoofed Source IPs and never sends the step-3 ACK. The server holds many **half-open connections** in its backlog queue → resource exhaustion. Mitigation: **SYN cookies** (the server encodes the state into the ISN and does not store anything in the queue until it receives a valid ACK).
```bash
sysctl net.ipv4.tcp_syncookies=1
sysctl net.ipv4.tcp_max_syn_backlog=4096
```

### 1.5.4. The 4-way connection close

```
Client                                Server
  |  FIN seq=u                          |   (Client has no more data to send)
  |------------------------------------>|
  |  ACK ack=u+1                        |
  |<------------------------------------|
  |              ... (server may still send data) ...
  |  FIN seq=v                          |
  |<------------------------------------|
  |  ACK ack=v+1                        |
  |------------------------------------>|
  |  (Client enters TIME_WAIT ~2*MSL)   |
```

TCP is full-duplex, so each direction closes independently (half-close). **TIME_WAIT** (2×MSL, with MSL usually 30–120s depending on the OS) ensures: (1) the final ACK reaches the server, and (2) old delayed segments in the network expire before the port pair is reused. Too many TIME_WAIT entries on a heavily loaded server is a real-world problem (tune `tcp_tw_reuse`).

### 1.5.5. The complete TCP state machine (RFC 9293)

```
                              CLOSED
                                | (passive open: LISTEN) | (active open: send SYN)
                                v                         v
                             LISTEN                  SYN_SENT
                          recv SYN |                   | recv SYN-ACK / send ACK
                          send SYN-ACK                 v
                                v                  ESTABLISHED
                           SYN_RCVD --recv ACK------>  |
                                                       | (close: send FIN)
                        ┌──────────────────────────────┤
       recv FIN/send ACK│                              │ send FIN
                        v                              v
                   CLOSE_WAIT                       FIN_WAIT_1
                        | app close/send FIN     recv ACK | recv FIN+ACK
                        v                              v        \
                   LAST_ACK                       FIN_WAIT_2     CLOSING
                        | recv ACK                  | recv FIN       | recv ACK
                        v                           v send ACK       v
                     CLOSED                     TIME_WAIT  <----------
                                                    | (2*MSL timeout)
                                                    v
                                                 CLOSED
```

| State | Meaning |
|-------|---------|
| LISTEN | Server waiting for connections |
| SYN_SENT | Client has sent the SYN |
| SYN_RCVD | Received the SYN, sent the SYN-ACK |
| ESTABLISHED | Active connection, transferring data |
| FIN_WAIT_1/2 | The active-close side has sent its FIN |
| CLOSE_WAIT | The passive side received the FIN, the app has not closed yet |
| LAST_ACK | The passive side has sent its FIN, waiting for the final ACK |
| TIME_WAIT | Waiting 2×MSL before fully closing |

```bash
ss -tan          # view TCP states (ESTAB, TIME-WAIT, CLOSE-WAIT...)
ss -tanp state syn-recv   # detect a SYN flood
```
**Port-scanning security (nmap) relies on the state machine:**
- *SYN scan* (`-sS`): send a SYN; receiving a SYN-ACK → open (then send an RST to abort); receiving an RST → closed.
- *NULL/FIN/Xmas scan*: send unusual flag combinations; per the RFC, a closed port replies with RST while an open port stays silent → infer the state (bypassing some stateless firewalls).

### 1.5.6. Sliding window, flow control, congestion control

**Flow control:** the receiver advertises a **Window Size** (combined with Window Scale) = the number of bytes still free in its buffer. The sender does not send more than the `Window`. If the buffer is full → it advertises window=0 → the sender stops and periodically sends a *window probe*.

**Sliding window:** the byte stream is divided into 4 regions: (1) sent & acked, (2) sent but not yet acked, (3) not yet sent but within the window, (4) outside the window. When an ack arrives, the "window" slides to the right.

**Congestion control — the classic algorithms:**
- *Slow start*: cwnd starts at 1–10 MSS and doubles every RTT until `ssthresh`.
- *Congestion avoidance*: after ssthresh, it grows linearly (+1 MSS/RTT).
- *Fast retransmit*: receiving 3 duplicate ACKs → retransmit immediately without waiting for a timeout.
- *Fast recovery*: halve the cwnd instead of dropping back to 1.
- Modern: **CUBIC** (the Linux default), **BBR** (Google, measures bandwidth×RTT).
```bash
sysctl net.ipv4.tcp_congestion_control   # view the algorithm
ss -ti                                    # view cwnd, rtt, retrans per-socket
```

**Retransmission:** based on the **RTO (Retransmission Timeout)** computed from the measured RTT (Jacobson/Karels: `RTO = SRTT + 4*RTTVAR`). When the RTO expires without an ack → retransmit, and the RTO doubles (exponential backoff).

---

## 1.6. Common ports

| Port | Protocol | Service | Security notes |
|------|----------|---------|-----------------|
| 20/21 | TCP | FTP data/control | Plaintext, use FTPS/SFTP |
| 22 | TCP | SSH | Encrypted remote administration |
| 23 | TCP | Telnet | Plaintext — do not use |
| 25 | TCP | SMTP | Mail, check for open relay |
| 53 | TCP/UDP | DNS | UDP for queries, TCP for zone transfers/large responses |
| 67/68 | UDP | DHCP server/client | DORA |
| 80 | TCP | HTTP | Plaintext |
| 110/143 | TCP | POP3/IMAP | Mail client |
| 123 | UDP | NTP | Amplification DDoS |
| 161/162 | UDP | SNMP | Default community strings are dangerous |
| 389/636 | TCP | LDAP/LDAPS | Directory |
| 443 | TCP/UDP | HTTPS / QUIC(UDP) | TLS |
| 445 | TCP | SMB | EternalBlue, do not expose to the Internet |
| 3306 | TCP | MySQL | DB should not be public |
| 3389 | TCP | RDP | Brute-force, BlueKeep |
| 5432 | TCP | PostgreSQL | DB |
| 6379 | TCP | Redis | No auth by default — dangerous |

Port ranges: **0–1023 well-known** (requires root privileges to bind on Linux), **1024–49151 registered**, **49152–65535 ephemeral/dynamic** (assigned by the client).

---

## 1.7. Layer 7 — DNS, DHCP, HTTP, TLS

### 1.7.1. DNS — Domain Name System (RFC 1035)

**DNS message header — 12 bytes:**

| Field | Size | Meaning | Example |
|--------|-----------|---------|-------|
| Transaction ID | 16 bits | Matches query/response | `0x1a2b` |
| Flags | 16 bits | QR(1b),Opcode(4b),AA,TC,RD,RA,Z,RCODE(4b) | see below |
| QDCOUNT | 16 bits | Number of questions | `1` |
| ANCOUNT | 16 bits | Number of answer records | `2` |
| NSCOUNT | 16 bits | Number of authority records | `0` |
| ARCOUNT | 16 bits | Number of additional records | `0` |

**The Flags field (16 bits) in detail:**

| Bit | Name | Meaning |
|-----|-----|---------|
| QR (1) | Query/Response | 0=query, 1=response |
| Opcode (4) | | 0=standard query |
| AA (1) | Authoritative Answer | the server is authoritative |
| TC (1) | Truncated | the response was truncated (switch to TCP) |
| RD (1) | Recursion Desired | the client wants recursion |
| RA (1) | Recursion Available | the server supports recursion |
| Z (3) | reserved/AD/CD | in DNSSEC: AD=Authenticated Data, CD=Checking Disabled |
| RCODE (4) | Response code | 0=NOERROR,2=SERVFAIL,3=NXDOMAIN |

**Question section:** `QNAME` (a string of labels in the form `[len][label]...0`, e.g. `3www7example3com0`), `QTYPE` (2B, A=1, AAAA=28, MX=15, CNAME=5, NS=2, TXT=16, SOA=6, PTR=12), `QCLASS` (2B, IN=1).

**Resource Record (answer):** `NAME` (usually a 2B compression pointer `0xc00c`), `TYPE` (2B), `CLASS` (2B), `TTL` (4B), `RDLENGTH` (2B), `RDATA` (variable — 4 bytes of IPv4 for an A record).

**Recursive vs iterative:**
- *Recursive resolver* (8.8.8.8): the client asks once, and the resolver does the lookups on its behalf and returns the final result.
- *Iterative*: the resolver queries root → TLD (`.com`) → authoritative, receiving a referral to the next server at each step.

```bash
dig +trace example.com A      # view the entire iterative chain from root
dig @1.1.1.1 example.com MX
dig -x 93.184.216.34          # reverse (PTR)
sudo tcpdump -i eth0 -nn 'udp port 53'
```

Sample `dig` output (annotated):
```
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 6789
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; ANSWER SECTION:
example.com.    3600   IN   A   93.184.216.34
```

**DNSSEC:** adds the `RRSIG` record (signature), `DNSKEY` (public key), `DS` (delegation signer), and `NSEC/NSEC3` (proof of non-existence). The `AD` bit (Authenticated Data) in the flags indicates the resolver has validated the signature. Goal: defend against cache poisoning/spoofing with digital signatures (it does not encrypt the content).

**Security — DNS tunneling:** encodes exfiltration data into the QNAME (`base64data.attacker.com`) or TXT records → bypasses firewalls because DNS is rarely blocked. Detection: unusually long QNAMEs with high entropy, a large volume of TXT queries.

**Cache poisoning (Kaminsky):** guessing the Transaction ID (16 bits) + source port to inject a fake answer before the real one. Mitigation: random source ports (more entropy), DNSSEC, DNS-over-TLS/HTTPS.

### 1.7.2. DHCP — DORA (RFC 2131)

The four-step dynamic IP allocation (UDP, server 67, client 68):

```
Client (0.0.0.0)                         DHCP Server
   | 1. DISCOVER (broadcast ff:ff..)        |   "Are there any servers out there?"
   |--------------------------------------->|
   | 2. OFFER (proposes IP, lease, gateway) |
   |<---------------------------------------|
   | 3. REQUEST (request the offered IP)     |
   |--------------------------------------->|
   | 4. ACK (confirm, finalize the lease)    |
   |<---------------------------------------|
```

| Step | Type | Src IP | Dst IP | Purpose |
|------|------|--------|--------|----------|
| D | DISCOVER | 0.0.0.0 | 255.255.255.255 | Client looks for a server (no IP yet) |
| O | OFFER | server IP | broadcast/unicast | Server proposes an IP |
| R | REQUEST | 0.0.0.0 | 255.255.255.255 | Client accepts (broadcast so other servers know) |
| A | ACK | server IP | client | Confirm, grant the lease + options (DNS, gateway, mask) |

Important options (DHCP options in the BOOTP packet): Option 53 (message type), 51 (lease time), 1 (subnet mask), 3 (router/gateway), 6 (DNS), 50 (requested IP).

```bash
sudo dhclient -v eth0
sudo tcpdump -i eth0 -nn 'udp port 67 or udp port 68'
```
**Security:** a *rogue DHCP server* hands out a fake gateway/DNS → MITM. *DHCP starvation* (`yersinia`) floods DISCOVERs to exhaust the pool. Mitigation: **DHCP snooping** on the switch (only trust the port connected to the legitimate server).

### 1.7.3. HTTP — raw request/response

**Request (HTTP/1.1):**
```http
GET /index.html HTTP/1.1\r\n
Host: example.com\r\n
User-Agent: curl/8.0\r\n
Accept: */*\r\n
\r\n
```
Structure: `Method SP Request-URI SP HTTP-Version CRLF`, then the headers `Name: Value CRLF`, an empty line `CRLF`, then the body (if present). CRLF = `\r\n` (0x0D 0x0A).

**Response:**
```http
HTTP/1.1 200 OK\r\n
Content-Type: text/html; charset=UTF-8\r\n
Content-Length: 138\r\n
Connection: keep-alive\r\n
\r\n
<html>...</html>
```
`Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase`. Codes: 1xx info, 2xx success, 3xx redirect, 4xx client error, 5xx server error.

```bash
# Send a raw request, hiding none of the details:
printf 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n' \
  | ncat example.com 80
curl -v http://example.com/      # -v prints both request and response headers
```
**Security:** security headers — `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options: nosniff`. Attacks: request smuggling (a conflict between `Content-Length` and `Transfer-Encoding`), host header injection.

### 1.7.4. TLS — 1.2 and 1.3

**TLS Record layer — 5-byte header (wraps every TLS message):**

| Field | Size | Meaning | Example |
|--------|-----------|---------|-------|
| Content Type | 1 byte | 20=ChangeCipherSpec,21=Alert,22=Handshake,23=Application Data | `22` |
| Version | 2 bytes | `0x0303`=TLS1.2 (1.3 pretends to be 1.2 at the record layer for compatibility) | `0x0303` |
| Length | 2 bytes | Payload length (≤16384) | `0x0200` |

**TLS 1.2 handshake — message by message:**
```
Client                                       Server
  | 1. ClientHello (random_c, cipher list, SNI, sessionID)
  |------------------------------------------------->|
  | 2. ServerHello (random_s, cipher chosen)         |
  |    Certificate (X.509 chain)                     |
  |    ServerKeyExchange (ECDHE params)              |
  |    ServerHelloDone                               |
  |<-------------------------------------------------|
  | 3. ClientKeyExchange (ECDHE public)              |
  |    ChangeCipherSpec                              |
  |    Finished (encrypted)                          |
  |------------------------------------------------->|
  | 4. ChangeCipherSpec                              |
  |    Finished (encrypted)                          |
  |<-------------------------------------------------|
  (2 RTT before sending application data)
```

**TLS 1.3 handshake — reduced to 1 RTT (RFC 8446):**
```
Client                                       Server
  | ClientHello (+ key_share, supported_versions, SNI)
  |------------------------------------------------->|
  |          ServerHello (+ key_share)               |
  |          {EncryptedExtensions}                   |
  |          {Certificate}{CertificateVerify}        |
  |          {Finished}                              |
  |<-------------------------------------------------|
  | {Finished}                                       |
  |------------------------------------------------->|
  (1 RTT; 0-RTT if using PSK/resumption)
```

Differences in TLS 1.3: weak ciphersuites removed (static RSA key exchange, RC4, CBC, SHA-1), mandatory **forward secrecy** (ECDHE), most of the handshake encrypted (the Certificate is encrypted), and only AEAD ciphersuites remain (e.g. `TLS_AES_128_GCM_SHA256`).

**X.509 certificate — the main fields:**

| Field | Meaning | Example |
|--------|---------|-------|
| Version | v3 | `2` (=v3) |
| Serial Number | a unique identifier from the CA | `0x0a1b...` |
| Signature Algorithm | the signing algorithm | `sha256WithRSAEncryption` |
| Issuer | the DN of the issuing CA | `CN=R3, O=Let's Encrypt` |
| Validity | notBefore / notAfter | `2026-01-01 .. 2026-04-01` |
| Subject | the subject's DN | `CN=example.com` |
| Subject Public Key Info | the algorithm + public key | `RSA 2048` / `EC P-256` |
| Extensions | SAN, Key Usage, EKU, Basic Constraints, AIA, CRL/OCSP | SAN: `example.com, www.example.com` |
| Signature | the CA's signature over the TBS | … |

```bash
# View the real handshake and certificate:
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null
echo | openssl s_client -connect example.com:443 2>/dev/null \
  | openssl x509 -noout -text -dates -subject -issuer -ext subjectAltName

# Wireshark filters for the handshake:
#   tls.handshake.type == 1   (ClientHello)
#   tls.handshake.type == 2   (ServerHello)
#   tls.handshake.extensions_server_name == "example.com"
```
**Security:** SNI (Server Name Indication) leaks the domain name despite encryption → ECH (Encrypted Client Hello) addresses this. Verify the chain of trust, revocation (OCSP stapling), cipher downgrade, Heartbleed (CVE-2014-0160 — reading memory via the heartbeat).

---

## 1.8. Firewalls, DMZ, and packet analysis tools

### 1.8.1. Stateless vs stateful firewalls

| Criterion | Stateless (packet filter) | Stateful |
|----------|---------------------------|----------|
| Decision based on | Each packet individually (IP/port/flags) | Connection state (conntrack) |
| Allowing return packets | Must open rules for both directions manually | Automatic (RELATED, ESTABLISHED) |
| Resistance to flag spoofing | Weak | Good (only accepts packets consistent with state) |
| Memory load | Low | High (maintains a connection table) |

**Stateful example with iptables:**
```bash
# Default DROP, allow only inbound SSH and all established outbound
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
iptables -P OUTPUT ACCEPT
```
`-m conntrack --ctstate ESTABLISHED,RELATED` is precisely the "stateful" point: the kernel tracks connections, so return packets (e.g. an SSH response) are automatically accepted without needing a separate rule.

### 1.8.2. DMZ (Demilitarized Zone)

A DMZ is a buffer network zone between the Internet and the internal LAN, containing servers that need to be reachable from outside (web, mail). The two-firewall architecture:
```
Internet --[outer FW]-- DMZ (web, mail) --[inner FW]-- internal LAN
```
Principle: Internet → DMZ is permitted (specific ports); DMZ → LAN is restricted as much as possible; if a DMZ server is compromised, the attacker still finds it hard to pivot into the LAN.

### 1.8.3. tcpdump / Wireshark — practical filters

**tcpdump (BPF filter — capture filter):**
```bash
# Capture SYN-only (detect scans): SYN flag set, ACK off
sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn'

# Capture HTTP GET (first payload bytes = 'G','E','T',' ')
sudo tcpdump -i eth0 'tcp port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'

# DNS query to a domain, write to a pcap file to open in Wireshark
sudo tcpdump -i eth0 -nn -w /tmp/dns.pcap 'udp port 53'

# One host, no name resolution, print hex/ascii payload, 100 packets
sudo tcpdump -i eth0 -nn -X host 10.0.0.50 -c 100
```
Parameters: `-i` interface, `-nn` no name/port resolution, `-e` print the L2 header, `-X` hex+ascii, `-w` write pcap, `-c` packet count, `-s 0` capture the full packet.

**Wireshark (display filter — different syntax from BPF):**
```
ip.addr == 10.0.0.50
tcp.flags.syn == 1 && tcp.flags.ack == 0      # SYN scan
tcp.analysis.retransmission                   # detect packet loss
http.request.method == "POST"
dns.qry.name contains "example"
tls.handshake.type == 1                       # ClientHello
tcp.port == 443 && tls.record.content_type == 23   # encrypted app data
ip.ttl < 5                                    # traceroute / unusually low hop
```
A typical investigation workflow: capture with tcpdump on a headless server (`-w file.pcap`), transfer it to an analysis machine, open Wireshark, use "Follow TCP Stream" to reassemble the session, and "Statistics → Conversations" to see the top talkers.

---

## 1.9. Key numbers to memorize

| Item | Value |
|----------|---------|
| Ethernet header / FCS / MTU / max frame | 14B / 4B / 1500B / 1518B (1522 with VLAN) |
| Ethernet payload min/max | 46B / 1500B |
| 802.1Q tag | 4B (TPID 16b + PCP 3b + DEI 1b + VID 12b) |
| ARP packet (IPv4) | 28B |
| IPv4 header min/max | 20B / 60B |
| IPv6 header | 40B fixed, min MTU 1280B |
| TCP header min / UDP header | 20B / 8B |
| ICMP header | 8B |
| DNS header | 12B |
| TLS record header | 5B |
| IPv4 Total Length max | 65535B |
| Port ranges | 0–1023 / 1024–49151 / 49152–65535 |

> The RFC numbers above are stable standards. For implementation-dependent details (MSL, backlog size, the default congestion algorithm), verify them on the specific system using `sysctl`/`ss`, as the values vary by OS and kernel version.
