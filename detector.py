#!/usr/bin/env python3
"""
DNS Exfiltration Detector
Author: Roshim Bhatta
GitHub: github.com/RocmDaGr8

Detects DNS-based data exfiltration by analyzing:
  - Shannon entropy of subdomain labels (encoded data = high entropy)
  - Base64 / hex encoding patterns
  - Unusually long subdomain labels
  - Beaconing: high-frequency queries to the same domain (C2 pattern)

Usage:
  sudo python3 detector.py -i eth0          # live capture
  sudo python3 detector.py -i eth0 -v       # verbose (show every query)
  python3 detector.py -r capture.pcap       # offline pcap analysis
"""

import re
import math
import time
import argparse
from collections import defaultdict, Counter
from datetime import datetime

from scapy.all import sniff, DNS, DNSQR, IP, rdpcap

# ─── Detection thresholds (tune these for your environment) ───────────────────
ENTROPY_THRESHOLD   = 3.5   # bits/char; above this = suspiciously random
MAX_LABEL_LEN       = 40    # chars; labels longer than this are unusual
BEACON_COUNT        = 10    # queries to same domain within BEACON_WINDOW → alert
BEACON_WINDOW       = 60    # seconds

# ─── Regex patterns ───────────────────────────────────────────────────────────
# Base64: 20+ chars of [A-Za-z0-9+/] optionally padded with =
BASE64_RE = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
# Hex: 20+ hex chars (even length = likely encoded bytes)
HEX_RE    = re.compile(r'^[0-9a-fA-F]{20,}$')


# ─── Shannon Entropy ──────────────────────────────────────────────────────────
def shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string (bits per character).

    WHY THIS MATTERS:
    Normal hostnames like 'mail' or 'api' have low entropy (~2-3 bits)
    because letters repeat and follow English patterns.

    Encoded payloads like 'dGhpcyBpcyBzdG9sZW4=' are nearly random —
    every character is equally likely — so entropy climbs to 4-6 bits.

    Formula: H = -sum( p(c) * log2(p(c)) ) for each unique char c
    Maximum possible: log2(charset_size)  e.g. log2(64) = 6 bits for base64
    """
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ─── Subdomain extraction ─────────────────────────────────────────────────────
def extract_subdomain(fqdn: str) -> str:
    """
    Strip the registered domain and TLD to get the subdomain portion.

    'dGVzdA==.evil.com.'  ->  'dGVzdA=='
    'mail.google.com'     ->  'mail'
    'google.com'          ->  ''   (no subdomain)
    """
    fqdn = fqdn.rstrip('.')
    parts = fqdn.split('.')
    if len(parts) > 2:
        return '.'.join(parts[:-2])
    return ''


# ─── Per-label analysis ───────────────────────────────────────────────────────
def analyse_subdomain(subdomain: str) -> list:
    """
    Examine each dot-separated label of a subdomain for exfil indicators.
    Returns a list of human-readable reason strings (empty = clean).

    Attackers split data across labels to stay under the 63-char DNS label
    limit, so we check label-by-label.
    """
    if not subdomain:
        return []

    reasons = []
    for label in subdomain.split('.'):
        if not label:
            continue

        # 1. Shannon entropy
        h = shannon_entropy(label)
        if h > ENTROPY_THRESHOLD:
            reasons.append(
                f"High entropy ({h:.2f} bits) on label '{label[:24]}'"
            )

        # 2. Base64-like pattern
        if BASE64_RE.match(label):
            reasons.append(f"Base64 pattern on label '{label[:24]}'")

        # 3. Hex-encoded data
        if HEX_RE.match(label):
            reasons.append(f"Hex-encoded data on label '{label[:24]}'")

        # 4. Unusually long label
        if len(label) > MAX_LABEL_LEN:
            reasons.append(
                f"Long label ({len(label)} chars): '{label[:24]}...'"
            )

    return reasons


# ─── Main detector class ──────────────────────────────────────────────────────
class DNSExfilDetector:
    """
    Stateful DNS packet analyser.

    Maintains a sliding-window query log per domain to detect beaconing,
    and calls analyse_subdomain() on every DNS query it sees.
    """

    def __init__(self, verbose: bool = False):
        self.verbose       = verbose
        self.query_log     = defaultdict(list)  # domain -> [timestamps]
        self.alert_count   = 0
        self.packet_count  = 0
        self.alerts        = []

    # ── Beaconing detection ────────────────────────────────────────────────
    def _check_beaconing(self, domain: str) -> str:
        """
        Slide a time window and count how often this domain is queried.

        Legitimate resolvers query a domain a handful of times (TTL cache).
        Malware doing C2 over DNS will query every few seconds — that pattern
        stands out immediately in a frequency count.

        Returns a reason string if threshold exceeded, else empty string.
        """
        now = time.time()
        # Prune entries older than BEACON_WINDOW
        self.query_log[domain] = [
            t for t in self.query_log[domain] if now - t <= BEACON_WINDOW
        ]
        self.query_log[domain].append(now)
        count = len(self.query_log[domain])
        if count >= BEACON_COUNT:
            return (
                f"Beaconing: {count} queries to '{domain}' "
                f"in {BEACON_WINDOW}s"
            )
        return ''

    # ── Packet handler (called by Scapy for every captured packet) ─────────
    def process_packet(self, pkt) -> None:
        """
        Scapy calls this for every packet that matches the BPF filter.

        We only care about DNS QUERY packets (qr=0).  DNS responses (qr=1)
        are answers — the data goes OUT in the query, not the response.
        """
        self.packet_count += 1

        # Layer check: must have DNS and a question record
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
            return
        # qr flag: 0 = query, 1 = response
        if pkt[DNS].qr != 0:
            return

        try:
            qname = pkt[DNSQR].qname.decode('utf-8', errors='replace')
        except Exception:
            return

        domain    = qname.rstrip('.')
        subdomain = extract_subdomain(qname)
        src_ip    = pkt[IP].src if pkt.haslayer(IP) else 'unknown'
        ts        = datetime.now().strftime('%H:%M:%S')

        if self.verbose:
            print(f"  [.] {ts}  {src_ip:>15}  {domain}")

        reasons = []

        # Check 1: subdomain encoding indicators
        reasons.extend(analyse_subdomain(subdomain))

        # Check 2: beaconing
        beacon_reason = self._check_beaconing(domain)
        if beacon_reason:
            reasons.append(beacon_reason)

        if reasons:
            self.alert_count += 1
            alert = {
                'id':      self.alert_count,
                'time':    ts,
                'src':     src_ip,
                'domain':  domain,
                'reasons': reasons,
            }
            self.alerts.append(alert)
            self._print_alert(alert)

    # ── Alert formatting ───────────────────────────────────────────────────
    def _print_alert(self, a: dict) -> None:
        print(f"\n{'=' * 62}")
        print(f"  [!] ALERT #{a['id']}  @  {a['time']}")
        print(f"  Source  : {a['src']}")
        print(f"  Query   : {a['domain']}")
        print(f"  Reasons :")
        for r in a['reasons']:
            print(f"    - {r}")
        print(f"{'=' * 62}")

    # ── Session summary ────────────────────────────────────────────────────
    def print_summary(self) -> None:
        print(f"\n{'─' * 62}")
        print(f"  DNS Exfil Detector  —  Session Summary")
        print(f"{'─' * 62}")
        print(f"  Packets analysed : {self.packet_count}")
        print(f"  Alerts fired     : {self.alert_count}")
        if self.alerts:
            print(f"\n  Top suspicious domains:")
            for domain, cnt in Counter(
                a['domain'] for a in self.alerts
            ).most_common(5):
                print(f"    {cnt:>4}x  {domain}")
        print(f"{'─' * 62}\n")


# ─── CLI entry point ──────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='Detect DNS exfiltration via entropy, pattern & beacon analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 detector.py -i eth0
  sudo python3 detector.py -i eth0 -c 1000 -v
  python3 detector.py -r suspicious.pcap
  python3 detector.py -r suspicious.pcap --entropy-threshold 3.0
        """,
    )
    parser.add_argument('-i', '--interface',
                        help='Network interface for live capture (e.g. eth0, en0)')
    parser.add_argument('-r', '--read',
                        help='Read packets from a .pcap file')
    parser.add_argument('-c', '--count', type=int, default=0,
                        help='Packets to capture (0 = unlimited, live only)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Print every DNS query, not just alerts')
    parser.add_argument('--entropy-threshold', type=float,
                        default=ENTROPY_THRESHOLD,
                        help=f'Entropy bits/char alert threshold (default {ENTROPY_THRESHOLD})')
    parser.add_argument('--max-label-len', type=int,
                        default=MAX_LABEL_LEN,
                        help=f'Max subdomain label length before alert (default {MAX_LABEL_LEN})')
    args = parser.parse_args()

    if not args.interface and not args.read:
        parser.error('Specify -i <interface> for live capture or -r <file> for pcap replay')

    # Allow runtime threshold overrides
    global ENTROPY_THRESHOLD, MAX_LABEL_LEN
    ENTROPY_THRESHOLD = args.entropy_threshold
    MAX_LABEL_LEN     = args.max_label_len

    detector   = DNSExfilDetector(verbose=args.verbose)
    bpf_filter = 'udp port 53'

    print(f"\n  dns-exfil-detector  |  github.com/RocmDaGr8")
    print(f"  ─────────────────────────────────────────────")
    print(f"  Entropy threshold  : {ENTROPY_THRESHOLD} bits/char")
    print(f"  Max label length   : {MAX_LABEL_LEN} chars")
    print(f"  Beacon window      : {BEACON_WINDOW}s / {BEACON_COUNT} queries")
    print(f"  Source             : {args.interface or args.read}")
    print(f"  BPF filter         : {bpf_filter}")
    print(f"\n  Listening for DNS queries … (Ctrl+C to stop)\n")

    try:
        if args.read:
            pkts = rdpcap(args.read)
            print(f"  Loaded {len(pkts)} packets from {args.read}\n")
            for pkt in pkts:
                detector.process_packet(pkt)
        else:
            sniff(
                iface=args.interface,
                filter=bpf_filter,
                prn=detector.process_packet,
                count=args.count,
                store=False,
            )
    except KeyboardInterrupt:
        print('\n  [*] Stopped by user.')
    except PermissionError:
        print('\n  [!] Permission denied — run with sudo for live capture.')
    except Exception as exc:
        print(f'\n  [!] Error: {exc}')
    finally:
        detector.print_summary()


if __name__ == '__main__':
    main()
