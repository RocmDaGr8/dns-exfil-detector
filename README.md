# dns-exfil-detector

> Detect DNS-based data exfiltration in real time using Shannon entropy, encoding pattern analysis, and beaconing detection.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python) ![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-green) ![License](https://img.shields.io/badge/License-MIT-yellow)

---

## What Is DNS Exfiltration?

Most firewalls block HTTP/FTP/ICMP — but almost nobody blocks DNS (port 53), because it's required for everything to work. Attackers exploit this by encoding stolen data inside DNS subdomain queries:

```
# Normal DNS query
www.google.com

# Data exfiltration via DNS
dGhpcyBpcyBzdG9sZW4gZGF0YQ==.attacker.com
# ^^^ base64 for "this is stolen data"
```

The query travels out to the attacker's DNS server, completely bypassing most network controls. This tool catches it.

---

## Detection Methods

| Method | What It Catches | How |
|---|---|---|
| **Shannon Entropy** | Encoded / compressed data | Entropy > 3.5 bits/char signals randomness |
| **Base64 Pattern** | Base64-encoded payloads | Regex: 20+ chars of `[A-Za-z0-9+/]` |
| **Hex Pattern** | Hex-encoded payloads | Regex: 20+ hex chars |
| **Label Length** | Oversized subdomain labels | Labels > 40 chars are unusual |
| **Beaconing** | C2 malware callbacks | ≥10 queries to same domain in 60s |

---

## Quick Start

```bash
# Install dependency
pip install -r requirements.txt

# Live capture on interface eth0 (requires root)
sudo python3 detector.py -i eth0

# Verbose: show every DNS query, not just alerts
sudo python3 detector.py -i eth0 -v

# Analyse an existing pcap file (no root required)
python3 detector.py -r suspicious_traffic.pcap

# Tune the entropy threshold (lower = more sensitive)
python3 detector.py -r capture.pcap --entropy-threshold 3.0
```

---

## Example Output

```
  dns-exfil-detector  |  github.com/RocmDaGr8
  ─────────────────────────────────────────────
  Entropy threshold  : 3.5 bits/char
  Max label length   : 40 chars
  Beacon window      : 60s / 10 queries
  Source             : eth0
  BPF filter         : udp port 53

  Listening for DNS queries … (Ctrl+C to stop)

==============================================================
  [!] ALERT #1  @  14:32:07
  Source  : 192.168.1.105
  Query   : dGhpcyBpcyBzdG9sZW4gZGF0YQ==.evil.com
  Reasons :
    - High entropy (5.81 bits) on label 'dGhpcyBpcyBzdG9sZW'
    - Base64 pattern on label 'dGhpcyBpcyBzdG9sZW'
==============================================================

  ──────────────────────────────────────────────────────────
  DNS Exfil Detector  —  Session Summary
  ──────────────────────────────────────────────────────────
  Packets analysed : 1204
  Alerts fired     : 3

  Top suspicious domains:
       2x  dGhpcyBpcyBzdG9sZW4gZGF0YQ==.evil.com
       1x  636f6e666964656e7469616c.data-out.net
  ──────────────────────────────────────────────────────────
```

---

## Project Structure

```
dns-exfil-detector/
├── detector.py        # Main detector — all logic lives here
├── requirements.txt   # Python dependencies (scapy)
└── README.md
```

---

## How Shannon Entropy Works

Shannon entropy measures **information density** in bits per character:

- `"mail"` → ~2.0 bits (low, repetitive)
- `"api.prod"` → ~2.8 bits (normal hostname)
- `"dGVzdA=="` → ~4.9 bits (high — base64 payload)
- `"4a6f686e"` → ~3.32 bits (moderate — short hex)

Formula: **H = −∑ p(c) · log₂(p(c))** for each unique character *c*

The default threshold of **3.5 bits** catches most encoded payloads while keeping false positives low on typical network traffic.

---

## Tuning for Your Environment

| Flag | Default | Adjust when… |
|---|---|---|
| `--entropy-threshold` | 3.5 | Getting too many false positives → raise; missing attacks → lower |
| `--max-label-len` | 40 | Your infra uses long subdomains legitimately |
| `BEACON_COUNT` (in code) | 10 | Your environment makes many repeat DNS queries |

---

## Skills Demonstrated

- **Network packet analysis** with Scapy (BPF filters, DNS layer parsing)
- **Information theory** — Shannon entropy applied to subdomain labels
- **Regex-based IOC detection** — base64 and hex encoding patterns
- **Sliding-window beaconing detection** — stateful time-series analysis
- **CLI tool design** — argparse with runtime threshold overrides
- **PCAP replay** — offline forensic analysis support

---

## Author

**Roshim Bhatta** — Rowan University, B.S. Computer Science (Dec 2027)  
GitHub: [@RocmDaGr8](https://github.com/RocmDaGr8)  
Email: bhatta45@students.rowan.edu

---

*Part of a 12-week cybersecurity portfolio project targeting SOC / junior security analyst roles.*
