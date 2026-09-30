# AWS VPC Foundation — Hybrid Enterprise Cybersecurity Architecture with AI-Assisted SOC Triage

**Scope:** VPC, Internet Gateway, Subnets, Route Tables, Route Table Associations, NAT Gateway, Security Groups. Everything else (ALB, WAF, EC2, CloudTrail, Config, GuardDuty, CloudWatch, Flow Logs, Wazuh, TheHive, Cortex, MISP, AI Agent, VPN, on-prem) is documented separately.

**Rule followed throughout:** every value below comes directly from a screenshot. Anything not visible in a screenshot is marked **Not confirmed from the provided screenshots** — nothing is inferred or assumed.

---

## 1. VPC

**What:** A Virtual Private Cloud is a logically isolated, privately addressed network within AWS.

**Why:** `hybrid-soc-vpc` is the address space for the cloud side of the hybrid SOC. `10.20.0.0/16` was chosen to avoid overlapping with the on-premise `192.168.x.0/24` ranges used elsewhere in the project.

**Configured:**

| Field | Value |
|---|---|
| Name tag | `hybrid-soc-vpc` |
| VPC ID | `vpc-0b06cb133a0952c81` |
| IPv4 CIDR | `10.20.0.0/16` |
| IPv6 CIDR block | None selected |
| Resources to create | VPC only |
| State | Available |
| Region | Not explicitly shown; AZ selector later displays `us-east-1a`, implying **us-east-1** |
| DNS settings | Not confirmed from the provided screenshots |

![VPC creation form](figures/Capture%20d'écran%202026-09-30%20210659.png)
*Figure 1 — VPC creation form: name, CIDR, IPv6 option.*

![VPC created](figures/Capture%20d'écran%202026-09-30%20210734.png)
*Figure 2 — Confirmation: `hybrid-soc-vpc` / `vpc-0b06cb133a0952c81`, State = Available.*

**Validation:** Confirmed.

---

## 2. Internet Gateway

**What:** A horizontally scaled, AWS-managed gateway attached to a VPC that allows communication between the VPC and the internet.

**Why:** Required as the exit/entry point for any subnet or NAT Gateway in this VPC that needs internet reachability.

**Configured:**

| Field | Value |
|---|---|
| Name tag | `hybrid-soc-igw` |
| Internet Gateway ID | `igw-02e58b1ae6dcbdd9f` |
| Attached VPC | `vpc-0b06cb133a0952c81` |
| Current state | Not confirmed from the provided screenshots |

![IGW creation form](figures/Capture%20d'écran%202026-09-30%20210828.png)
*Figure 3 — Internet Gateway creation form: `hybrid-soc-igw`.*

![IGW attach to VPC](figures/Capture%20d'écran%202026-09-30%20210901.png)
*Figure 4 — Attaching `igw-02e58b1ae6dcbdd9f` to `vpc-0b06cb133a0952c81`.*

**How it fits:** This IGW is the confirmed route target in two route tables (Section 4): Public-RT and Honeypot-RT.

**Important:** its existence does **not** alone grant any instance internet access — that also depends on the subnet's route table actually pointing to it, the subnet-to-route-table association being in place, the instance having a public IP, and Security Group rules. Only the route table side is confirmed here.

**Validation:** Confirmed (creation + attachment). State: not confirmed.

---

## 3. Subnets

**What:** A subnet is a range of IP addresses within the VPC's CIDR, tied to one Availability Zone.

**Why:** Four subnets were created to segment the environment by function — public tier, application tier, security tier, honeypot tier — consistent with the project's segmentation-by-trust-zone principle.

| Subnet | CIDR | AZ | Subnet ID |
|---|---|---|---|
| `public-a` | `10.20.1.0/24` | us-east-1a | Not confirmed from the provided screenshots |
| `application-a` | `10.20.2.0/24` | us-east-1a | Not confirmed from the provided screenshots |
| `security-a` | `10.20.3.0/24` | us-east-1a | Not confirmed from the provided screenshots |
| `honeypot-a` | `10.20.4.0/24` | us-east-1a | Not confirmed from the provided screenshots |

![Subnet public-a](figures/Capture%20d'écran%202026-09-30%20211049.png)
*Figure 5 — `public-a`, 10.20.1.0/24, us-east-1a.*

![Subnet application-a](figures/Capture%20d'écran%202026-09-30%20211208.png)
*Figure 6 — `application-a`, 10.20.2.0/24, us-east-1a.*

![Subnet security-a](figures/Capture%20d'écran%202026-09-30%20211254.png)
*Figure 7 — `security-a`, 10.20.3.0/24, us-east-1a.*

![Subnet honeypot-a](figures/Capture%20d'écran%202026-09-30%20211357.png)
*Figure 8 — `honeypot-a`, 10.20.4.0/24, us-east-1a.*

**Validation:** Confirmed (CIDR + AZ for all four). Subnet IDs and actual public/private status: not confirmed (depends on Section 5).

---

## 4. Route Tables

**What:** A route table holds the rules that determine where traffic from an associated subnet is sent.

**Why:** One dedicated route table per trust zone, instead of one shared table, so each zone's routing can change independently without affecting the others.

### 4.1 — Public-RT

| Destination | Target | Status |
|---|---|---|
| `10.20.0.0/16` | local | Active |
| `0.0.0.0/0` | Internet Gateway `igw-02e58b1ae6dcbdd9f` | — |

Route Table ID: `rtb-0c43cc83a7ce3304c`

![Create Public-RT](figures/Capture%20d'écran%202026-09-30%20211606.png)
*Figure 9 — Creating route table `Public-RT`.*

![Public-RT routes](figures/Capture%20d'écran%202026-09-30%20211640.png)
*Figure 10 — `Public-RT` (`rtb-0c43cc83a7ce3304c`): local + 0.0.0.0/0 → igw-02e58b1ae6dcbdd9f.*

### 4.2 — Application-RT

![Create Application-RT](figures/Capture%20d'écran%202026-09-30%20211711.png)
*Figure 11 — Creating route table `Application-RT`, VPC `vpc-0b06cb133a0952c81`.*

Routes: **Not confirmed from the provided screenshots** — no route-detail screenshot was provided for this table.

### 4.3 — Security-RT

| Destination | Target | Status |
|---|---|---|
| `10.20.0.0/16` | local | Active |
| `0.0.0.0/0` | NAT Gateway `nat-193f09d8911575331` | — |

Route Table ID: `rtb-03e8cca502a094eac`

![Create Security-RT](figures/Capture%20d'écran%202026-09-30%20211750.png)
*Figure 12 — Creating route table `Security-RT`.*

![Security-RT routes](figures/Capture%20d'écran%202026-10-01%20011537.png)
*Figure 13 — `Security-RT` (`rtb-03e8cca502a094eac`): local + 0.0.0.0/0 → nat-193f09d8911575331.*

### 4.4 — Honeypot-RT

| Destination | Target | Status |
|---|---|---|
| `10.20.0.0/16` | local | Active |
| `0.0.0.0/0` | Internet Gateway `igw-02e58b1ae6dcbdd9f` | — |

Route Table ID: `rtb-0282e23e81091e8fb`

![Create Honeypot-RT](figures/Capture%20d'écran%202026-09-30%20212043.png)
*Figure 14 — Creating route table `Honeypot-RT`.*

![Honeypot-RT routes](figures/Capture%20d'écran%202026-09-30%20212107.png)
*Figure 15 — `Honeypot-RT` (`rtb-0282e23e81091e8fb`): local + 0.0.0.0/0 → igw-02e58b1ae6dcbdd9f.*

**How traffic moves:** Public-RT and Honeypot-RT both send internet-bound traffic straight to the IGW. Security-RT sends internet-bound traffic to the NAT Gateway instead — the private-subnet pattern. Application-RT's behavior is unknown from the screenshots provided.

**Validation:** Public-RT, Honeypot-RT, Security-RT — confirmed. Application-RT — route table object confirmed, routes not confirmed.

---

## 5. Route Table Associations

**What:** The link between a subnet and a route table. A route table has no effect on a subnet until this association exists.

**Why it matters:** Two subnets with identical CIDRs could behave completely differently — one public, one private — purely based on which route table each is associated with.

| Subnet | Route Table (by naming) | Association |
|---|---|---|
| `public-a` | Public-RT | **Not confirmed from the provided screenshots** |
| `application-a` | Application-RT | **Not confirmed from the provided screenshots** |
| `security-a` | Security-RT | **Not confirmed from the provided screenshots** |
| `honeypot-a` | Honeypot-RT | **Not confirmed from the provided screenshots** |

No "Subnet associations" tab or "Edit subnet associations" screen was provided for any route table. The naming pattern strongly suggests the intended pairing, but per the source-of-truth rule this cannot be marked as confirmed without a screenshot showing the actual association.

**Validation:** Not confirmed from the provided screenshots (all four).

---

## 6. NAT Gateway

**What:** A managed AWS service letting private-subnet resources initiate outbound internet connections without accepting unsolicited inbound ones.

**Why:** Security-RT (Section 4.3) routes its `0.0.0.0/0` traffic through this NAT Gateway — the mechanism intended to let the security subnet reach external endpoints (updates, threat-intel feeds) without being directly internet-facing.

**Configured:**

| Field | Value |
|---|---|
| Name tag | `hybrid-soc-nat` |
| NAT Gateway ID | `nat-193f09d8911575331` (visible as Security-RT's route target) |
| Availability mode | Regional |
| VPC | `vpc-0b06cb133a0952c81` |
| Connectivity type | Public |
| Elastic IP allocation | Automatic |
| Subnet | Not confirmed from the provided screenshots |
| Elastic IP address | Not confirmed from the provided screenshots |
| State | Not confirmed from the provided screenshots |

![NAT Gateway creation form](figures/Capture%20d'écran%202026-10-01%20011357.png)
*Figure 16 — Creating `hybrid-soc-nat` in `vpc-0b06cb133a0952c81`, Regional, Public, Automatic EIP.*

**Traffic flow (per confirmed Security-RT route):**

```
security-a (if associated with Security-RT)
   → NAT Gateway (nat-193f09d8911575331)
   → Internet Gateway (igw-02e58b1ae6dcbdd9f)
   → Internet
```

Outbound-only by design: the NAT Gateway allows connections initiated from the private side out, and their return traffic, but nothing initiated from the internet inbound.

**Validation:** Creation settings confirmed. Subnet placement, EIP, and state — not confirmed.

---

## 7. Security Groups

**Not confirmed from the provided screenshots.** No Security Group list, rule detail, or creation screen was provided. This section cannot be documented until those screenshots are supplied.

---

## Traffic Flow Summary (Confirmed Configuration Only)

**Public-tier flow** (if `public-a`/`honeypot-a` are associated with their like-named tables):
```
Internet → igw-02e58b1ae6dcbdd9f → Public-RT / Honeypot-RT (0.0.0.0/0 → igw) → subnet
```

**Security-tier flow** (if `security-a` is associated with Security-RT):
```
security-a → Security-RT (0.0.0.0/0 → NAT) → nat-193f09d8911575331 → igw-02e58b1ae6dcbdd9f → Internet
```

**Intra-VPC flow** (confirmed `local` route on all four tables):
```
Any subnet in 10.20.0.0/16 → local → any other subnet in 10.20.0.0/16
```

All three flows depend on the subnet-to-route-table association actually existing (Section 5, not confirmed) and on Security Group rules permitting the traffic (Section 7, not confirmed).

---

## VPC Foundation Architecture (Confirmed Configuration Only)

```text
                              INTERNET
                                 |
                        Internet Gateway
                        (igw-02e58b1ae6dcbdd9f)
                                 |
        +------------------------+------------------------+
        |                                                   |
  Public-RT                                            Honeypot-RT
  (0.0.0.0/0 -> igw)                                   (0.0.0.0/0 -> igw)
        |                                                   |
  [public-a] 10.20.1.0/24                            [honeypot-a] 10.20.4.0/24
  (association not confirmed)                         (association not confirmed)


  Security-RT (0.0.0.0/0 -> NAT Gateway)
        |
  [security-a] 10.20.3.0/24 (association not confirmed)
        |
  NAT Gateway (nat-193f09d8911575331)
        |
  Internet Gateway (igw-02e58b1ae6dcbdd9f) -> INTERNET


  Application-RT (routes not confirmed)
        |
  [application-a] 10.20.2.0/24 (association not confirmed)


  VPC: hybrid-soc-vpc (vpc-0b06cb133a0952c81) — 10.20.0.0/16
```

---

## Validation Checklist

| Item | Status |
|---|---|
| VPC created with correct CIDR | **Confirmed** |
| Internet Gateway created and attached | **Confirmed** |
| Four subnets created (public-a, application-a, security-a, honeypot-a) | **Confirmed** |
| Subnet IDs documented | Not confirmed |
| Route Tables created (all four) | **Confirmed** |
| Public-RT routes | **Confirmed** |
| Honeypot-RT routes | **Confirmed** |
| Security-RT routes | **Confirmed** |
| Application-RT routes | Not confirmed |
| Route Table ↔ Subnet associations | Not confirmed (all four) |
| NAT Gateway created | **Confirmed** |
| NAT Gateway subnet / EIP / state | Not confirmed |
| NAT Gateway used as Security-RT target | **Confirmed** |
| Security Groups configured | Not confirmed |
| End-to-end public/private segmentation verified | Not confirmed — route-level design is consistent with intent, but associations and SG rules are still needed |

---

## Still Needed to Reach Full Confirmation

1. Subnets list view showing Subnet IDs for all four subnets.
2. "Subnet associations" tab for each route table.
3. Application-RT route detail screen.
4. NAT Gateway detail screen (subnet, EIP, state).
5. Security Group list and rule screens.

---

**Note:** three additional screenshots provided (VPC Flow Log settings, destination, and IAM service role) describe VPC Flow Logs, which the task scope explicitly excludes from this document. They are not included here and belong in the separate monitoring/logging document.
