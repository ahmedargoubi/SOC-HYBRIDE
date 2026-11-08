# Snort 3 NIDS — Installation, Configuration and Validation

**Project:** Hybrid Enterprise Cybersecurity Architecture with AI-Assisted SOC Triage (PFE, TEK-UP)
**Component:** Independent passive Network Intrusion Detection System (Snort 3) fed by OPNsense packet mirroring
**Lab:** VMware Workstation — OPNsense firewall + Ubuntu 24.04 "Security-Core" VM
**Document date:** 2026-11-08

---

## How to read this document

Every command block in this document carries a status label, so a reader can tell what was actually done from what is only suggested.

| Label | Meaning |
|---|---|
| ✅ **Executed** | The command was run on the lab machine and reported as successful in the project record supplied by the team. |
| 🔁 **Re-run to verify** | A read-only command for checking the current state. It is **not** claimed to have been run historically unless a figure says so. |
| 🧩 **Optional / future** | Not implemented. Shown only as a possible next step. |
| ❓ **Needs confirmation** | A detail that could not be established from the supplied evidence and must be checked on the real machine. |

Evidence is referenced as **Figure N** (see [Section 12](#12-evidence-and-screenshots)). A statement is only called "confirmed by screenshot" when a figure in this repository shows it.

> **Two findings the reader should know up front**
> 1. **`ens41` currently has an IPv4 address (`192.168.15.2/24`)** in Figure 2, although the design requires no IP on the monitoring interface. See [Section 9.4](#94-known-discrepancy-ens41-has-an-ip-address).
> 2. **Persistence after reboot has not been proven**, either on OPNsense (mirror graph) or on Ubuntu (Snort start). See [Section 14](#14-current-status-limitations-and-next-steps).

---

## Table of Contents

1. [Introduction and objectives](#1-introduction-and-objectives)
2. [Architecture and network topology](#2-architecture-and-network-topology)
3. [Prerequisites](#3-prerequisites)
4. [Snort 3 and LibDAQ installation](#4-snort-3-and-libdaq-installation)
5. [Snort configuration](#5-snort-configuration)
6. [Community and local rules](#6-community-and-local-rules)
7. [OPNsense Netgraph packet mirroring](#7-opnsense-netgraph-packet-mirroring)
8. [OPNsense persistence](#8-opnsense-persistence)
9. [Ubuntu monitoring interface persistence](#9-ubuntu-monitoring-interface-persistence)
10. [End-to-end testing](#10-end-to-end-testing)
11. [Verification commands](#11-verification-commands)
12. [Evidence and screenshots](#12-evidence-and-screenshots)
13. [Troubleshooting](#13-troubleshooting)
14. [Current status, limitations and next steps](#14-current-status-limitations-and-next-steps)
15. [Future integration with Wazuh and AI-assisted SOC triage](#15-future-integration-with-wazuh-and-ai-assisted-soc-triage)
16. [References](#16-references)
17. [Final verification checklist](#17-final-verification-checklist)

---

## 1. Introduction and objectives

### 1.1 Context

The project builds a hybrid SOC: an on-premises network (OPNsense, Active Directory, Windows/Linux endpoints, Velociraptor, Snort) connected to an AWS VPC hosting Wazuh, TheHive, Cortex, MISP and a public honeypot. Wazuh is the SIEM; an AI-assisted triage layer is planned on top.

Figure 0 shows the overall project architecture (it is the project-level diagram, not a Snort-specific one — it does not draw the mirror link described below).

![Figure 0 — Project architecture overview](images/fig00-project-architecture-overview.png)

### 1.2 Why a separate Snort sensor

OPNsense already routes and filters traffic. The team chose to monitor traffic **independently of the firewall**, on a dedicated VM, so that detection does not depend on the device being monitored. Snort runs on a separate Ubuntu VM. **Suricata on OPNsense is not used as a replacement for this sensor.**

### 1.3 Objectives

| # | Objective | Status |
|---|---|---|
| O1 | Build Snort 3.12.4.0 and LibDAQ 3.0.28 from source on Ubuntu 24.04 | Reported done (version identified); build outputs not captured as screenshots |
| O2 | Copy traffic from OPNsense interfaces em2/em3/em4 to em5 using FreeBSD Netgraph | Done — Figures 9, 10, 11 |
| O3 | Deliver the mirrored traffic to Ubuntu `ens41` over VMware VMnet11 | Done — Figures 3, 14 |
| O4 | Run Snort passively on `ens41` and produce alerts | Done — Figures 13, 14 |
| O5 | Prove the whole data path with a controlled test | Done for ICMP from `192.168.8.143` — Figure 14 |
| O6 | Make the setup survive reboots | **Scripts and units exist; reboot behaviour not proven** |
| O7 | Forward alerts to Wazuh and AI triage | **Not implemented** |

### 1.4 Scope statement

Snort here is a **passive IDS**. It observes copies of packets and writes alerts. It does **not** block traffic (it is not an IPS), and the only local rule is a **test rule** that proves packet visibility. This document does not claim broad attack-detection coverage.

---

## 2. Architecture and network topology

### 2.1 Segments

| Network | Subnet | OPNsense interface | OPNsense address | Mirrored? |
|---|---|---|---|---|
| Security LAN | 192.168.9.0/24 | em1 | — (not stated) | No |
| Server LAN | 192.168.7.0/24 | em2 | 192.168.7.1 | Yes |
| User LAN | 192.168.8.0/24 | em3 | 192.168.8.1 | Yes |
| Target / DMZ | 192.168.11.0/24 | em4 | 192.168.11.1 | Yes |
| Mirror output | none (no IP) | em5 | none | Output only |

Figure 7 confirms em2/em3/em4 addresses; Figure 8 confirms em5 is up with no IPv4 address.

### 2.2 Ubuntu Security-Core interfaces

| Interface | Purpose | Address |
|---|---|---|
| ens33 | VMware NAT / Internet | 192.168.163.132 |
| ens34 | Security LAN | 192.168.9.115 |
| ens38 | User LAN monitoring connection | none required |
| ens39 | Target/DMZ monitoring connection | none required |
| ens40 | Server LAN monitoring connection | none required |
| **ens41** | **Dedicated mirrored-traffic input for Snort** | **none by design — see 9.4** |

`ens41` MAC address: `00:0c:29:d9:e8:13` (matches Figure 3).

### 2.3 Data path

```text
 Windows VM 192.168.8.143
        │  ICMP echo request
        ▼
 OPNsense em3 (User LAN, 192.168.8.1)
        │  ng_tee copies both directions
        ▼
 ng_one2many node "mirror_out"
        │
        ▼
 OPNsense em5 (no IP)
        │  VMware VMnet11
        ▼
 Ubuntu ens41 (UP, PROMISC)
        │
        ▼
 Snort 3  (pcap DAQ, passive)
        │
        ▼
 /var/log/snort/alert_fast.txt
```

### 2.4 Netgraph topology (as built)

```text
        em2 ◄──► tee_em2 ──┐ (many2, many3)
        em3 ◄──► tee_em3 ──┼─► mirror_out (one2many) ── one ──► em5.lower
        em4 ◄──► tee_em4 ──┘ (many0/1 from em3, many4/5 from em4)
```

Each `ng_tee` sits between the physical `ether` node and the OPNsense stack, so normal traffic continues unchanged while a copy of each direction is sent to `mirror_out`.

### 2.5 What this mirror can and cannot see

- ✅ It copies traffic that **traverses OPNsense** on em2, em3 or em4.
- ❌ It does **not** capture traffic between two VMs on the **same VMware virtual LAN** if that traffic never goes through OPNsense (it is switched by the VMware virtual switch).
- ❌ It does not mirror the Security LAN (em1).

---

## 3. Prerequisites

### 3.1 Ubuntu Security-Core VM

| Item | Value | Evidence |
|---|---|---|
| OS | Ubuntu 24.04.5 LTS (noble) | Figure 1 |
| CPU / RAM / Swap | 2 vCPU / 7.7 GiB / 4 GiB | Project record (not screenshotted — re-run `nproc`, `free -h`) |
| Snort | 3.12.4.0 | Project record (not screenshotted — re-run `snort -V`) |
| LibDAQ | 3.0.28 | Project record (not screenshotted) |
| Prefix | `/usr/local` | Figure 4 (`/usr/local/bin/snort`) |
| Source dirs | `/usr/local/src/snort3`, `/usr/local/src/libdaq` | Project record |
| Config | `/usr/local/etc/snort/snort.lua` | Figure 5 |
| Rules dir | `/usr/local/etc/snort/rules` | Figures 5, 6 |
| Log dir | `/var/log/snort` | Figure 14 |

### 3.2 VMware requirements

1. A host-only/custom network **VMnet11** with no DHCP service on it that both OPNsense `em5` and Ubuntu `ens41` are attached to. *(VMnet11 DHCP setting is not stated in the project record — see 9.4.)*
2. OPNsense VM with five NICs: em0 (WAN/NAT, assumed), em1–em4 (LANs), em5 (mirror output).
3. Ubuntu VM with six NICs as in 2.2.
4. Root/sudo access on both VMs.

### 3.3 Knowledge assumed

Basic Linux and FreeBSD shell use, and familiarity with VMware virtual networks.

---

## 4. Snort 3 and LibDAQ installation

Snort 3 was **built from source**. `apt install snort` was **not** used.

### 4.1 Install build dependencies — ✅ Executed

```bash
sudo apt update

sudo apt install -y build-essential cmake git autoconf libtool bison flex \
  pkg-config libpcap-dev libpcre2-dev libdumbnet-dev libhwloc-dev \
  libluajit-5.1-dev libssl-dev zlib1g-dev liblzma-dev libunwind-dev
```

| Package | Why it is needed |
|---|---|
| `build-essential`, `cmake` | C/C++ compiler toolchain and the build system used by `configure_cmake.sh` |
| `git` | Clone the LibDAQ and Snort 3 repositories |
| `autoconf`, `libtool` | Generate/handle LibDAQ's autotools build (`./bootstrap`, `./configure`) |
| `bison`, `flex` | Parser generators used while building |
| `pkg-config` | Locates installed libraries during configuration |
| `libpcap-dev` | Packet capture library (used by the pcap DAQ) |
| `libpcre2-dev` | Regular-expression support for rule matching |
| `libdumbnet-dev` | Network utility library required by Snort 3 |
| `libhwloc-dev` | Hardware topology / CPU affinity support |
| `libluajit-5.1-dev` | LuaJIT — Snort 3 configuration is written in Lua |
| `libssl-dev` | TLS/crypto support |
| `zlib1g-dev`, `liblzma-dev` | Decompression support (LZMA was reported ON) |
| `libunwind-dev` | Stack unwinding for diagnostics (reported ON) |

> ⚠ No screenshot of this step exists yet (checklist item 2).

### 4.2 Source directory — ✅ Executed

```bash
cd /usr/local/src
```

### 4.3 LibDAQ — ✅ Executed

**Role.** LibDAQ is the *Data Acquisition* library. Snort 3 does not read packets from the network itself; it asks a DAQ module (pcap, afpacket, savefile, …) to deliver them. Snort 3 therefore needs LibDAQ installed **before** it is configured. In this lab the **pcap** DAQ module is used (Figure 13: "pcap DAQ configured to passive").

```bash
cd /usr/local/src
sudo git clone https://github.com/snort3/libdaq.git
cd /usr/local/src/libdaq
sudo ./bootstrap
sudo ./configure
sudo make -j2
sudo make install
sudo ldconfig
```

`sudo ldconfig` refreshes the dynamic linker cache so Snort can find the new libraries. Libraries are installed under `/usr/local/lib` and DAQ modules under `/usr/local/lib/daq`. The LibDAQ version identified in the environment is **3.0.28**.

### 4.4 Clone Snort 3 — ✅ Executed

```bash
cd /usr/local/src
sudo git clone https://github.com/snort3/snort3.git
```

Result: `/usr/local/src/snort3`.

> Note: cloning the default branch gives a moving target. The installed version reported is **3.12.4.0**. For exact reproducibility, check out the matching tag (🧩 optional — tag name to be confirmed with `git -C /usr/local/src/snort3 describe --tags`).

### 4.5 Configure the build — ✅ Executed

```bash
cd /usr/local/src/snort3
sudo ./configure_cmake.sh --prefix=/usr/local
```

The configuration completed successfully and generated build files in `/usr/local/src/snort3/build`. The summary reported:

| Item | State |
|---|---|
| DAQ modules | afpacket, bpf, dump, fst, gwlb, pcap, savefile, trace |
| Hyperscan | **OFF** |
| libunwind | ON |
| LZMA | ON |
| NUMA | ON |

Hyperscan being OFF means Snort uses its default search engine (Figure 13 shows `search engine (ac_bnfa)`).

### 4.6 Compile — ✅ Executed

```bash
cd /usr/local/src/snort3/build
sudo make -j2
```

`-j2` matches the 2 vCPUs. Compilation reached **100%** and produced the targets `snort`, `preprocessor_states` and `snort2lua`.

### 4.7 Install — ✅ Executed

```bash
sudo make install
```

Installed under `/usr/local`. Figure 4 confirms the binary path `/usr/local/bin/snort`. The reported version is **Snort 3.12.4.0**.

### 4.8 Confirm the installation — 🔁 Re-run to verify

```bash
command -v snort
snort -V
ldconfig -p | grep daq
ls -l /usr/local/lib/daq/
```

Only `command -v snort` is confirmed by a screenshot (Figure 4). The others are listed as missing evidence in Section 12.

---

## 5. Snort configuration

Main file: `/usr/local/etc/snort/snort.lua`.

### 5.1 HOME_NET and EXTERNAL_NET

```lua
HOME_NET = '[192.168.7.0/24,192.168.8.0/24,192.168.9.0/24,192.168.11.0/24]'
EXTERNAL_NET = '!$HOME_NET'
```

Figure 5 shows both lines in the file (line 24 and line 28).

![Figure 5](images/fig05-snort-config-dir-and-home-net.png)

**Why `HOME_NET` must be the protected networks.** Rules use `$HOME_NET` and `$EXTERNAL_NET` to express direction ("traffic from outside to our servers"). If `HOME_NET` is wrong, rules written for "attacker → protected host" will not match, or will match the wrong side, producing missed detections or noise. Here it lists the four internal subnets (Server, User, Security, Target/DMZ).

**Why `EXTERNAL_NET` is the complement.** `!$HOME_NET` means "anything that is not internal". This is the simplest correct definition: every address is either internal or external, so no traffic falls in a gap.

> Consequence: the community/stock rules use these variables. The single local rule below uses `any any -> any any` and does not depend on them.

### 5.2 Configuration directory

Figure 5 shows the installed files in `/usr/local/etc/snort/`: `balanced.lua`, `connectivity.lua`, `file_magic.rules`, `inline.lua`, `max_detect.lua`, `rules/` (directory), `security.lua`, `sensitive_data.rules`, `snort_defaults.lua`, `snort.lua`, `talos.lua`.

### 5.3 Validate the configuration — 🔁 Re-run to verify (output not captured)

Snort 3 has a test mode (`-T`) that loads and validates the configuration, then exits.

```bash
sudo snort -c /usr/local/etc/snort/snort.lua -T
```

No output of this command was supplied, so **do not treat configuration validation as proven** until a screenshot of it exists.

### 5.4 How the local rules file is loaded — ❓ Needs confirmation

The launch command (5.5) does not pass `-R`, yet alerts for `local.rules` fire (Figure 14). The rules must therefore be referenced from `snort.lua` (typically in the `ips` table). The exact lines were not supplied. Check them:

```bash
sudo grep -n -B2 -A12 "^ips" /usr/local/etc/snort/snort.lua
```

For reference only, the general form in Snort 3 is:

```lua
-- 🧩 Illustration of the usual pattern — verify against your actual snort.lua
ips =
{
    enable_builtin_rules = true,
    variables = default_variables,
    include = '/usr/local/etc/snort/rules/local.rules',
}
```

### 5.5 Running Snort — ✅ Executed

```bash
sudo snort -c /usr/local/etc/snort/snort.lua -i ens41 -A alert_fast -l /var/log/snort
```

| Option | Meaning |
|---|---|
| `-c` | Path to the configuration file |
| `-i ens41` | Interface to read from (the mirror input) |
| `-A alert_fast` | One-line alert output format |
| `-l /var/log/snort` | Directory for output files |

Snort ran in **passive** mode — Figure 13 shows `pcap DAQ configured to passive.` / `Commencing packet processing` / `++ [0] ens41`.

![Figure 13](images/fig13-snort-startup-on-ens41.png)

The command runs in the foreground (the terminal is occupied). It is **not** a service; see Section 14 for the auto-start gap.

Alerts are written to `/var/log/snort/alert_fast.txt`.

---

## 6. Community and local rules

### 6.1 Community rules

Community rules are a free, community-maintained rule set that ships ready-made detections so the sensor does more than the test rule. The project record states that community rules were loaded and that about **4,244 rules** were reported "during a later test".

- That count is from the project record; **no screenshot shows it**.
- The command used to download/extract the community rules is **not in the supplied evidence**. It is deliberately **not** reproduced here.

❓ **Needs confirmation from the actual machine.** To find out what is present and how it is referenced:

```bash
sudo ls -l /usr/local/etc/snort/rules/
sudo grep -n "rules" /usr/local/etc/snort/snort.lua
sudo find / -iname "*community*" -path "*rules*" 2>/dev/null
```

Note that Figure 5 lists `file_magic.rules` and `sensitive_data.rules` in `/usr/local/etc/snort/`, but the contents of the `rules/` subdirectory were not shown, so the presence of a community rules file is not visible in any figure.

### 6.2 Local test rule — ✅ Created

File: `/usr/local/etc/snort/rules/local.rules`

```text
alert icmp any any -> any any (msg:"LOCAL TEST - ICMP Echo Request"; itype:8; sid:1000001; rev:2;)
```

![Figure 6](images/fig06-local-rules-icmp-test.png)

| Field | Meaning |
|---|---|
| `alert` | Action: generate an alert and log it (no blocking) |
| `icmp` | Protocol to match |
| `any any -> any any` | Any source address/port to any destination address/port, one direction |
| `msg:"…"` | Text shown in the alert |
| `itype:8` | ICMP type 8 = Echo Request (a ping) |
| `sid:1000001` | Unique rule ID; IDs from 1,000,000 upward are reserved for local rules |
| `rev:2` | Revision number of this rule (second version) |

**Limitation.** This rule detects ICMP Echo Requests only. It is a controlled test rule that proves packet visibility and alert generation. **It does not detect attacks.**

---

## 7. OPNsense Netgraph packet mirroring

OPNsense (FreeBSD) has no one-click port mirror here, so a mirror was built with **Netgraph**:

- `ng_tee` — passes traffic through and sends a copy to a second hook.
- `ng_one2many` — merges several inputs onto one output (`one`), which is attached to `em5`.

Run as root in the OPNsense shell. All commands below are ✅ **Executed** and produced the working topology.

### 7.1 Step 1 — mirror output node

```sh
ngctl mkpeer em5: one2many lower one
ngctl name em5:lower mirror_out
```

Creates a `one2many` node connected to `em5` and names it `mirror_out`.

### 7.2 Step 2 — tee on Server LAN (em2)

```sh
ngctl mkpeer em2: tee lower right
ngctl connect em2: lower upper left
ngctl name em2:lower tee_em2
```

### 7.3 Step 3 — tee on User LAN (em3)

```sh
ngctl mkpeer em3: tee lower right
ngctl connect em3: lower upper left
ngctl name em3:lower tee_em3
```

### 7.4 Step 4 — tee on Target/DMZ (em4)

```sh
ngctl mkpeer em4: tee lower right
ngctl connect em4: lower upper left
ngctl name em4:lower tee_em4
```

For each interface, the tee is placed between the NIC (`lower`) and the OPNsense stack (`upper`), so normal traffic keeps flowing.

### 7.5 Step 5 — connect both directions to the mirror output

```sh
# User LAN
ngctl connect tee_em3: right2left mirror_out: many0
ngctl connect tee_em3: left2right mirror_out: many1

# Server LAN
ngctl connect tee_em2: right2left mirror_out: many2
ngctl connect tee_em2: left2right mirror_out: many3

# Target/DMZ
ngctl connect tee_em4: right2left mirror_out: many4
ngctl connect tee_em4: left2right mirror_out: many5
```

Six links in total: two directions × three interfaces. `mirror_out.one` connects to `em5.lower`.

### 7.6 Verification on OPNsense

```sh
ngctl types
ngctl list
ngctl dot
ngctl msg mirror_out: getconfig
ngctl msg mirror_out: getstats
ifconfig em2
ifconfig em3
ifconfig em4
ifconfig em5
tcpdump -ni em5
```

What the screenshots show:

| Check | Result | Figure |
|---|---|---|
| `ngctl types` | 4 types: `one2many` (1 node), `tee` (3), `ether` (6), `socket` (1) | Figure 9 |
| `ngctl list` | 11 nodes incl. `tee_em2`, `tee_em3`, `tee_em4`, `mirror_out` (7 hooks), `em5` (1 hook); `em2`/`em3`/`em4` have 2 hooks each | Figure 10 |
| `getconfig` | `enabledLinks=[ 1 1 1 1 1 1 ]` → all six links enabled | Figure 11 |
| `ifconfig em2/em3/em4` | UP, RUNNING, addresses 192.168.7.1 / 192.168.8.1 / 192.168.11.1 | Figure 7 |
| `ifconfig em5` | UP, RUNNING, status active, no IPv4 address | Figure 8 |

![Figure 9](images/fig09-opnsense-ngctl-types.png)
![Figure 10](images/fig10-opnsense-ngctl-list.png)
![Figure 11](images/fig11-opnsense-mirror-out-getconfig.png)
![Figure 7](images/fig07-opnsense-ifconfig-em2-em3-em4.png)
![Figure 8](images/fig08-opnsense-ifconfig-em5.png)

**Interpretation.** `mirror_out` has 7 hooks (six `many` + `one`) and each tee has 4 hooks, which is **consistent with** the intended topology. The project record states the topology was confirmed with `ngctl dot` (tee_em2/3/4 on both directions, `mirror_out.one` → `em5.lower`), but **no `ngctl dot` screenshot was supplied**; it is listed as missing evidence.

`getconfig` also shows `xmitAlg=1 failAlg=1`. These govern the *one → many* direction and are not relevant to a mirror that only sends *many → one*; consult `ng_one2many(4)` before changing them.

**Scope reminder.** The mirror copies traffic traversing em2/em3/em4 only (Section 2.5).

---

## 8. OPNsense persistence

Netgraph nodes created by `ngctl` live in memory and are lost when OPNsense restarts. A startup script was created to rebuild the graph.

### 8.1 Files

| Item | Path |
|---|---|
| Startup script | `/usr/local/etc/rc.syshook.d/start/50-packet-mirror` |
| Backup | `/root/50-packet-mirror.backup` |

### 8.2 Script content — ✅ Created

```sh
#!/bin/sh

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin

# Enable mirror output interface
ifconfig em5 up || exit 1

# Load Netgraph modules
kldload ng_tee 2>/dev/null || true
kldload ng_one2many 2>/dev/null || true

# Avoid duplicate graph creation
if ngctl list | grep -q 'mirror_out'; then
    logger "Packet mirror: graph already exists"
    exit 0
fi

# Create mirror output node
ngctl mkpeer em5: one2many lower one || exit 1
ngctl name em5:lower mirror_out || exit 1

# Mirror Server LAN (em2)
ngctl mkpeer em2: tee lower right || exit 1
ngctl connect em2: lower upper left || exit 1
ngctl name em2:lower tee_em2 || exit 1

# Mirror User LAN (em3)
ngctl mkpeer em3: tee lower right || exit 1
ngctl connect em3: lower upper left || exit 1
ngctl name em3:lower tee_em3 || exit 1

# Mirror Target LAN (em4)
ngctl mkpeer em4: tee lower right || exit 1
ngctl connect em4: lower upper left || exit 1
ngctl name em4:lower tee_em4 || exit 1

# Connect both traffic directions to mirror output
ngctl connect tee_em3: right2left mirror_out: many0 || exit 1
ngctl connect tee_em3: left2right mirror_out: many1 || exit 1

ngctl connect tee_em2: right2left mirror_out: many2 || exit 1
ngctl connect tee_em2: left2right mirror_out: many3 || exit 1

ngctl connect tee_em4: right2left mirror_out: many4 || exit 1
ngctl connect tee_em4: left2right mirror_out: many5 || exit 1

logger "Packet mirror: graph created successfully"

exit 0
```

How it works: it brings `em5` up, loads the two Netgraph modules, **exits early if `mirror_out` already exists** (prevents duplicates), then rebuilds the same graph as Section 7. Any failed `ngctl` aborts with a non-zero exit.

### 8.3 Permissions and syntax check — ✅ Executed

```sh
chmod 755 /usr/local/etc/rc.syshook.d/start/50-packet-mirror
sh -n /usr/local/etc/rc.syshook.d/start/50-packet-mirror
ls -l /usr/local/etc/rc.syshook.d/start/50-packet-mirror
ls -l /root/50-packet-mirror.backup
```

`sh -n` parses without executing; it returned `SYNTAX OK` per the project record (no screenshot yet).

### 8.4 What is and is not proven

| Claim | Status |
|---|---|
| Script exists, executable, syntax OK | Reported by the team; **no screenshot** |
| Script rebuilds the graph after an OPNsense reboot | ❌ **Not proven** — no reboot test and no post-reboot `ngctl list` / `getconfig` were supplied |

### 8.5 Reboot test to run — 🔁 Re-run to verify

1. Reboot OPNsense.
2. After it is back, run:

```sh
ngctl list
ngctl msg mirror_out: getconfig
ifconfig em5
grep -i "packet mirror" /var/log/system/latest.log   # path may differ; ❓ confirm on your OPNsense version
```

3. On Ubuntu, run `sudo tcpdump -ni ens41 -c 20` and confirm mirrored frames arrive.

---

## 9. Ubuntu monitoring interface persistence

`ens41` must be: **UP**, **PROMISC**, **without an IP address**, and available after reboot.

### 9.1 Netplan — ✅ Executed

File: `/etc/netplan/60-snort-monitor.yaml`. The `ens41` section added:

```yaml
ens41:
  dhcp4: false
  dhcp6: false
  accept-ra: false
  link-local: []
  optional: true
```

(The full file, including the `network:` / `version:` / `ethernets:` wrapper, was not supplied — ❓ see it with `sudo cat /etc/netplan/60-snort-monitor.yaml`.)

`optional: true` prevents boot from waiting for this interface. Permissions and validation:

```bash
sudo chmod 600 /etc/netplan/50-cloud-init.yaml
sudo chmod 600 /etc/netplan/60-snort-monitor.yaml
sudo netplan generate
```

Netplan 0.106+ warns when configuration files are world-readable, hence `chmod 600`.

### 9.2 systemd service — ✅ Executed

File: `/etc/systemd/system/ens41-mirror.service`

```ini
[Unit]
Description=Enable promiscuous mode on mirror interface ens41
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set dev ens41 up
ExecStart=/usr/sbin/ip link set dev ens41 promisc on
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable ens41-mirror.service
sudo systemctl start ens41-mirror.service
```

### 9.3 Verification

```bash
ip -br link show ens41
systemctl status ens41-mirror.service --no-pager
```

![Figure 3](images/fig03-ubuntu-ip-br-link-ens41-promisc.png)
![Figure 12](images/fig12-ens41-mirror-service-status.png)

- Figure 3: `ens41 UP 00:0c:29:d9:e8:13 <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP>` — PROMISC is set; the other interfaces are not in PROMISC.
- Figure 12: `Loaded … enabled`, `Active: active (exited) since Sun 2026-11-08 21:22:40 UTC`, both `ExecStart` entries `status=0/SUCCESS`.

**What this proves:** the service is enabled and ran successfully once. **What it does not prove:** that Snort starts after a reboot (Snort is not a service), nor that the settings survive a reboot (no reboot test supplied).

> Observation: the service's start time (21:22:40 UTC) is later than the alert timestamps in Figure 14 (20:47). The alert test therefore ran before this service was created/started, so PROMISC was set some other way at that time. The mechanism is not documented in the evidence.

### 9.4 Known discrepancy: ens41 has an IP address

![Figure 2](images/fig02-ubuntu-ip-br-addr.png)

Figure 2 (`ip -br addr`) shows:

```text
ens38   UP
ens39   UP
ens40   UP
ens41   UP    192.168.15.2/24 metric 100  fe80::20c:29ff:fed9:e813/64
```

Interfaces ens38–ens40 have no address, as designed, but **`ens41` has `192.168.15.2/24` and an IPv6 link-local address**. The design requires **no DHCP and no IP on ens41**, and the Netplan block above (`dhcp4: false`, `link-local: []`) should not produce either. So at the time of the screenshot the Netplan block either was not applied or another configuration provides the address. The source of `192.168.15.2` was **not established**.

Why it matters: an address on the sensor interface makes the Ubuntu VM a participant on the mirror segment (it can answer ARP/ping and is reachable), which contradicts a purely passive input. Snort can still read packets, so capture is not broken by this.

Investigate and fix (🔁 diagnostic first, then change):

```bash
ip -4 addr show ens41
sudo cat /etc/netplan/*.yaml
sudo netplan get
networkctl status ens41
sudo grep -rn "192.168.15" /etc/netplan /etc/systemd/network /run/systemd/network 2>/dev/null
```

Once the source is found and removed from its configuration file:

```bash
sudo netplan apply
ip -br addr show ens41     # expected: no IPv4 and no IPv6 address
ip -br link show ens41     # expected: ...PROMISC,UP,LOWER_UP
```

Do **not** configure DHCP or an IP on ens41. Replace Figure 2 with a screenshot taken after the fix.

---

## 10. End-to-end testing

### 10.1 Test setup

| Item | Value |
|---|---|
| Source | Windows VM on User LAN, `192.168.8.143` |
| Destination | OPNsense User LAN gateway, `192.168.8.1` |
| Traffic | ICMP echo request (ping) |
| Rule | `LOCAL TEST - ICMP Echo Request`, sid 1000001 |

### 10.2 Procedure

1. **OPNsense:** confirm the graph (`ngctl list`, `getconfig`) and that `em5` is UP.
2. **Ubuntu:** confirm `ens41` is UP and PROMISC.
3. **Ubuntu — packet capture** (✅ executed per project record; **no screenshot supplied**):

```bash
sudo tcpdump -ni ens41 -e
sudo tcpdump -ni ens41 icmp
```

   The first command showed mirrored Layer 2 traffic including ARP, DNS and DHCP. The second showed `192.168.8.143 > 192.168.8.1: ICMP echo request`.

4. **Ubuntu — start Snort** (✅):

```bash
sudo snort -c /usr/local/etc/snort/snort.lua -i ens41 -A alert_fast -l /var/log/snort
```

5. **Windows:** `ping 192.168.8.1` (✅ per project record; **no screenshot supplied**).
6. **Ubuntu — read alerts** (✅):

```bash
sudo tail -n 30 /var/log/snort/alert_fast.txt
```

Live view, shown in Figure 14:

```bash
sudo tail -f /var/log/snort/alert_fast.txt
```

### 10.3 Result

![Figure 14](images/fig14-snort-alert-fast-icmp-alerts.png)

Figure 14 shows repeated alerts, about every 5 seconds, from `11/08-20:47:09` onward:

```text
11/08-20:47:09.170983 [**] [1:1000001:2] "LOCAL TEST - ICMP Echo Request" [**] [Priority: 0] {ICMP} 192.168.8.143 -> 192.168.8.1
```

The project record quotes an earlier alert at `11/08-20:46:13`; it is the same rule and same hosts — the timestamp differs only because the figure captured later alerts in a continuous stream.

### 10.4 What the test proves

- The tested packet traversed the monitored OPNsense interface (em3).
- The Netgraph mirror delivered a copy to `em5`.
- Ubuntu `ens41` received the mirrored packet.
- Snort inspected the packet and the local ICMP rule matched.
- Snort wrote an alert to `alert_fast.txt`.

### 10.5 What it does not prove

- That Snort detects arbitrary attacks (only one ICMP test rule is demonstrated).
- That the community rules detect anything in this lab (no community-rule alert was shown).
- That all east-west traffic is visible (Section 2.5).
- That Snort blocks malicious traffic (it does not — it is passive).
- That the setup survives reboots.
- That the packet came *through the mirror and not from another path*: the strongest evidence is the alert on `ens41` for a packet between hosts that are not on that segment; a `tcpdump` screenshot should accompany the alert to document it.

---

## 11. Verification commands

These are **🔁 re-run** commands. They are not claimed as historical unless a figure is cited.

### 11.1 OS and system (Ubuntu)

```bash
lsb_release -a      # Figure 1
uname -a
nproc
free -h
ip -br addr         # Figure 2
ip -br link         # Figure 3
```

### 11.2 Snort and LibDAQ

```bash
command -v snort    # Figure 4
snort -V
snort --help
ldconfig -p | grep daq
ls -l /usr/local/lib/daq/
```

### 11.3 Configuration and rules

```bash
sudo ls -l /usr/local/etc/snort/                       # Figure 5
sudo ls -l /usr/local/etc/snort/rules/
sudo grep -n "HOME_NET\|EXTERNAL_NET" /usr/local/etc/snort/snort.lua   # Figure 5
sudo cat /usr/local/etc/snort/rules/local.rules        # Figure 6
sudo snort -c /usr/local/etc/snort/snort.lua -T        # validation; output not yet captured
```

### 11.4 Interface

```bash
ip -br link show ens41
ip addr show ens41
sudo tcpdump -ni ens41 -e -c 20
```

### 11.5 Logs

```bash
sudo ls -lh /var/log/snort/
sudo tail -n 30 /var/log/snort/alert_fast.txt
sudo grep -n "LOCAL TEST" /var/log/snort/alert_fast.txt
```

### 11.6 OPNsense

```sh
ngctl list
ngctl dot
ngctl msg mirror_out: getconfig
ngctl msg mirror_out: getstats
ifconfig em5
```

---

## 12. Evidence and screenshots

### 12.1 Screenshots supplied

Images are stored in `images/`. Figures are numbered in the order they appear below. "Original file" is the capture name supplied by the team.

| Figure | File | Original file | Shows | What it proves |
|---|---|---|---|---|
| 0 | `fig00-project-architecture-overview.png` | `Untitled_Diagram_drawio_5_1_1_5.png` | Project architecture diagram (cloud + on-prem) | Overall context only. Does **not** show the em5→VMnet11→ens41 mirror path; in it Snort is drawn beside Velociraptor on the Security side. |
| 1 | `fig01-ubuntu-os-version-lsb-release.png` | `Capture_décran_2026-11-08_223350.png` | `lsb_release -a` | Ubuntu 24.04.5 LTS (noble). |
| 2 | `fig02-ubuntu-ip-br-addr.png` | `…_223407.png` | `ip -br addr` | ens33 192.168.163.132/24; ens34 192.168.9.115/24; ens38/39/40 no IP; **ens41 192.168.15.2/24 — discrepancy (9.4)**. |
| 3 | `fig03-ubuntu-ip-br-link-ens41-promisc.png` | `…_223419.png` | `ip -br link` | ens41 MAC 00:0c:29:d9:e8:13 and flags `PROMISC,UP,LOWER_UP`. |
| 4 | `fig04-snort-binary-path.png` | `…_223433.png` | `command -v snort` | Snort binary at `/usr/local/bin/snort`. (Not a version proof.) |
| 5 | `fig05-snort-config-dir-and-home-net.png` | `…_223521.png` | `ls -l /usr/local/etc/snort/` + `grep HOME_NET\|EXTERNAL_NET` | Config files present; HOME_NET (line 24) lists the four subnets; EXTERNAL_NET = `!$HOME_NET` (line 28). |
| 6 | `fig06-local-rules-icmp-test.png` | `…_223533.png` | `cat local.rules` | The ICMP test rule, sid 1000001 rev 2. |
| 7 | `fig07-opnsense-ifconfig-em2-em3-em4.png` | `…_223125.png` | `ifconfig em2/em3/em4` | Mirrored interfaces up, with 192.168.7.1 / 192.168.8.1 / 192.168.11.1. |
| 8 | `fig08-opnsense-ifconfig-em5.png` | `…_223142.png` | `ifconfig em5` | em5 UP, active, MAC 00:0c:29:77:d3:b8, no IPv4 address. |
| 9 | `fig09-opnsense-ngctl-types.png` | `…_223211.png` | `ngctl types` | `one2many`, `tee`, `ether`, `socket` types; 3 tee nodes, 1 one2many. |
| 10 | `fig10-opnsense-ngctl-list.png` | `…_223158.png` | `ngctl list` | 11 nodes: tee_em2/3/4, mirror_out (7 hooks), em5 (1 hook). Consistent with the intended graph; not a topology drawing. |
| 11 | `fig11-opnsense-mirror-out-getconfig.png` | `…_223246.png` | `ngctl msg mirror_out: getconfig` | `enabledLinks=[ 1 1 1 1 1 1 ]` — six links enabled. |
| 12 | `fig12-ens41-mirror-service-status.png` | `…_223717.png` | `systemctl status ens41-mirror.service` | Service enabled, `active (exited)` since 21:22:40 UTC, both commands succeeded. |
| 13 | `fig13-snort-startup-on-ens41.png` | `…_223643.png` | Snort startup output | `pcap DAQ configured to passive`, `Commencing packet processing`, `++ [0] ens41`; `ac_bnfa` search engine. |
| 14 | `fig14-snort-alert-fast-icmp-alerts.png` | `…_223630.png` | `tail -f alert_fast.txt` | Repeated `LOCAL TEST - ICMP Echo Request` alerts 192.168.8.143 → 192.168.8.1. |

### 12.2 Coverage against the evidence checklist

| # | Required screenshot | Status | Figure |
|---|---|---|---|
| 1 | Ubuntu OS version and system resources | 🟡 Partial — OS only; `nproc`/`free -h` missing | 1 |
| 2 | Installed build dependencies | ❌ Missing | — |
| 3 | LibDAQ build and install | ❌ Missing | — |
| 4 | Snort build configuration output | ❌ Missing | — |
| 5 | Compilation at 100% | ❌ Missing | — |
| 6 | `make install` output | ❌ Missing | — |
| 7 | `snort -V` showing 3.12.4.0 | ❌ Missing (Figure 4 shows only the path) | — |
| 8 | LibDAQ version / module verification | ❌ Missing | — |
| 9 | `snort.lua` HOME_NET / EXTERNAL_NET | ✅ | 5 |
| 10 | `local.rules` | ✅ | 6 |
| 11 | `ngctl dot` topology | ❌ Missing (Figure 10 is a partial substitute) | (10) |
| 12 | `getconfig` six links | ✅ | 11 |
| 13 | OPNsense `em5` status | ✅ | 8 |
| 14 | `ens41` UP/PROMISC, no IP | 🟡 PROMISC shown (Fig. 3); **IP present in Fig. 2** — retake after fix | 2, 3 |
| 15 | `tcpdump` on `ens41` | ❌ Missing | — |
| 16 | Snort running on `ens41` | ✅ | 13 |
| 17 | `alert_fast.txt` alerts | ✅ | 14 |
| 18 | Windows ping test | ❌ Missing | — |
| 19 | Netplan configuration for `ens41` | ❌ Missing | — |
| 20 | `ens41-mirror.service` status | ✅ | 12 |
| 21 | OPNsense startup script + syntax check | ❌ Missing | — |

**Still missing: 13 of 21** (items 2–8, 11, 15, 18, 19, 21), plus a corrected item 14.

Additional evidence worth capturing: `snort -c … -T` output; `ls -l /usr/local/etc/snort/rules/`; the `ips` section of `snort.lua`; a post-reboot check on both VMs.

### 12.3 Suggested naming convention for new screenshots

```text
images/figNN-<system>-<what-it-shows>.png
```

- `NN`: two-digit figure number; `<system>`: `ubuntu`, `opnsense` or `windows`.
- Lower case, hyphens, no spaces or accents.

| Missing item | Suggested file name |
|---|---|
| 2 | `fig15-ubuntu-build-dependencies-install.png` |
| 3 | `fig16-ubuntu-libdaq-build-install.png` |
| 4 | `fig17-ubuntu-snort3-cmake-configure-output.png` |
| 5 | `fig18-ubuntu-snort3-compile-100-percent.png` |
| 6 | `fig19-ubuntu-snort3-make-install.png` |
| 7 | `fig20-ubuntu-snort-version.png` |
| 8 | `fig21-ubuntu-libdaq-modules.png` |
| 11 | `fig22-opnsense-ngctl-dot-topology.png` |
| 15 | `fig23-ubuntu-tcpdump-ens41-mirrored-traffic.png` |
| 18 | `fig24-windows-ping-192-168-8-1.png` |
| 19 | `fig25-ubuntu-netplan-ens41.png` |
| 21 | `fig26-opnsense-50-packet-mirror-syntax-ok.png` |

Do not reference these file names in the document until the files exist.

---

## 13. Troubleshooting

> These are general diagnostic steps for this design, not problems recorded during the lab.

| Symptom | Check | Command |
|---|---|---|
| No traffic on `ens41` | Is `em5` UP and the graph present? | OPNsense: `ifconfig em5`, `ngctl list` |
| | Are `em5` and `ens41` on the same VMnet11? | VMware VM settings → network adapters |
| | Is `ens41` UP and PROMISC? | `ip -br link show ens41` |
| | Is the host-side vmnet allowed to deliver promiscuous traffic? | Host-dependent — ❓ verify for your host OS |
| `mirror_out` missing after OPNsense reboot | Did the startup script run? | `ls -l /usr/local/etc/rc.syshook.d/start/50-packet-mirror`; run it manually: `/usr/local/etc/rc.syshook.d/start/50-packet-mirror` |
| Script says "graph already exists" | Normal: it exits early when `mirror_out` exists | `ngctl list` |
| `ngctl: ... already connected` / name exists | A previous manual attempt left nodes | Remove a node with `ngctl shutdown <node>:` and re-run |
| Snort starts but no alerts | Is `local.rules` loaded? | See 5.4; run `snort -c … -T` |
| | Is the packet type visible? | `sudo tcpdump -ni ens41 icmp` |
| | Snort bound to the wrong interface | Confirm `++ [0] ens41` at startup (Figure 13) |
| `snort: command not found` | PATH / not installed | `command -v snort`; check `/usr/local/bin` |
| Missing shared library (`libdaq`) | Linker cache not refreshed | `sudo ldconfig`; `ldconfig -p \| grep daq` |
| Permission denied writing logs | Log directory ownership | `sudo ls -ld /var/log/snort` |
| Only partial traffic seen | Traffic never crosses OPNsense (same VMware LAN) | See 2.5 |
| `ens41` has an IP | Leftover/other netplan source | See 9.4 |
| Packet anomalies / oversize packets reported | NIC offload features can alter captured packets | 🧩 `sudo ethtool -K ens41 gro off lro off` — not applied in this lab; test before adopting |

---

## 14. Current status, limitations and next steps

### 14.1 Status table

| Capability | Status | Basis |
|---|---|---|
| Snort 3.12.4.0 built and installed | ✅ Reported | Project record; binary path Fig. 4 |
| OPNsense Netgraph mirror (em2/em3/em4 → em5) | ✅ Working | Figs. 9–11 + alert in Fig. 14 |
| Mirror delivered to `ens41` | ✅ Working | Fig. 14 (alert), Fig. 3 |
| Snort passive detection on `ens41` | ✅ Working (test rule) | Figs. 13, 14 |
| Local ICMP test rule | ✅ Working | Figs. 6, 14 |
| Community rules loaded (~4,244) | 🟡 Reported, not evidenced | Project record only |
| Config validation (`-T`) | ❓ Not captured | — |
| OPNsense mirror survives reboot | ❌ **Not proven** | Script exists; no reboot test |
| `ens41` PROMISC survives reboot | 🟡 Service enabled; no reboot test | Fig. 12 |
| `ens41` has no IP | ❌ **Contradicted** by Fig. 2 | See 9.4 |
| Snort auto-start after reboot | ❌ **Not implemented / not confirmed** | Run manually in foreground |
| Snort → Wazuh forwarding | ❌ **Not implemented** | — |
| AI-assisted triage | ❌ **Not implemented** | — |

### 14.2 Limitations

- Snort is a **passive NIDS, not an IPS**: it alerts, it never blocks.
- It only sees what is on `ens41` and only alerts on enabled rules.
- It does not replace endpoint detection (Wazuh agents, Velociraptor).
- em2/em3/em4 mirroring does **not** capture VM-to-VM traffic on the same VMware LAN that does not traverse OPNsense, and em1 (Security LAN) is not mirrored.
- Encrypted traffic payloads are not inspectable.
- The only locally written rule is a test rule.

### 14.3 Next steps

1. Fix and document the `ens41` IP discrepancy (9.4).
2. Run `snort -T`; capture the output.
3. Confirm how `local.rules` and community rules are referenced; document the community-rules installation (5.4, 6.1).
4. Reboot OPNsense and Ubuntu; capture post-reboot evidence (8.5).
5. Create a systemd unit for Snort so it starts after `ens41-mirror.service` (🧩 not implemented).
6. Capture the missing screenshots (12.2).
7. Plan alert forwarding to Wazuh (Section 15).

---

## 15. Future integration with Wazuh and AI-assisted SOC triage

> **Not implemented.** This section describes intent only.

### 15.1 Snort → Wazuh (planned)

Snort writes alerts to files; a Wazuh agent on the Security-Core VM could read the alert file and ship events to the Wazuh manager in AWS. Candidate approaches:

| Option | Notes |
|---|---|
| Wazuh agent `localfile` on `/var/log/snort/alert_fast.txt` | Simplest; fast-alert format is plain text, needs a decoder/rule on the manager |
| Switch Snort to JSON output (`alert_json`) | Easier parsing; requires changing the launch command / config |

Wazuh's official documentation contains an integration guide for Snort; **verify its Snort 3 compatibility before relying on it**. The chosen option and its configuration are ❓ undecided.

### 15.2 Path to AI-assisted triage (planned)

Planned chain: Snort alert → Wazuh (normalisation, correlation, severity) → AI triage agent (read-only enrichment via Cortex/MISP, MITRE ATT&CK mapping) → TheHive case → human analyst decision. Snort's role is to supply network-level detections; the AI layer does **not** exist yet. The network connection between on-prem and AWS (VPN) is itself still an open project decision.

---

## 16. References

Official Snort documentation and sources:

- Snort 3 project site and documentation: <https://www.snort.org/snort3>
- Snort 3 documentation (manual): <https://docs.snort.org/>
- Snort 3 source repository: <https://github.com/snort3/snort3>
- LibDAQ source repository: <https://github.com/snort3/libdaq>
- Snort rules and community rules download page: <https://www.snort.org/downloads>

FreeBSD / OPNsense / system documentation:

- `ng_tee(4)` and `ng_one2many(4)` and `ngctl(8)` manual pages: <https://man.freebsd.org/>
- OPNsense documentation: <https://docs.opnsense.org/>
- Netplan documentation: <https://netplan.readthedocs.io/>

URLs were not re-fetched when this document was written; verify them when publishing.

---

## 17. Final verification checklist

Tick only what you have verified with captured output.

**Installation**
- [ ] Build dependencies installed (screenshot missing)
- [ ] LibDAQ built, installed, `ldconfig` run (screenshot missing)
- [ ] Snort configured, compiled to 100%, installed (screenshots missing)
- [x] Snort binary at `/usr/local/bin/snort` (Fig. 4)
- [ ] `snort -V` shows 3.12.4.0 (screenshot missing)
- [ ] LibDAQ 3.0.28 and modules verified (screenshot missing)

**Configuration**
- [x] `HOME_NET` lists the four subnets; `EXTERNAL_NET = '!$HOME_NET'` (Fig. 5)
- [x] `local.rules` contains the ICMP test rule (Fig. 6)
- [ ] `snort -c … -T` passes (output not captured)
- [ ] Rules loading mechanism for `local.rules` / community rules confirmed
- [ ] Community-rules install command confirmed and documented

**OPNsense**
- [x] em2/em3/em4 up with expected addresses (Fig. 7)
- [x] em5 up, no IP (Fig. 8)
- [x] 3 tee nodes + `mirror_out` + em5 present (Figs. 9, 10)
- [x] `enabledLinks=[ 1 1 1 1 1 1 ]` (Fig. 11)
- [ ] `ngctl dot` topology captured
- [ ] Startup script present with `SYNTAX OK` captured
- [ ] Mirror graph rebuilt after OPNsense reboot

**Ubuntu**
- [x] Ubuntu 24.04.5 LTS (Fig. 1)
- [x] `ens41` UP and PROMISC (Fig. 3)
- [ ] **`ens41` has no IPv4/IPv6 address** (Fig. 2 shows `192.168.15.2/24` — fix and retake)
- [x] `ens41-mirror.service` enabled and active (exited) (Fig. 12)
- [ ] Netplan file for `ens41` captured
- [ ] `ens41` PROMISC/UP after Ubuntu reboot
- [ ] `tcpdump` on `ens41` shows mirrored traffic (screenshot missing)

**Detection**
- [x] Snort runs passively on `ens41` (Fig. 13)
- [x] `LOCAL TEST - ICMP Echo Request` alerts for 192.168.8.143 → 192.168.8.1 (Fig. 14)
- [ ] Windows ping screenshot captured
- [ ] Snort starts automatically after reboot (not implemented)

**Integration (future)**
- [ ] Snort alerts reach Wazuh
- [ ] AI-assisted triage consumes Snort-derived alerts
