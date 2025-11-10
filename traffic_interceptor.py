#!/usr/bin/env python3
"""
traffic_interceptor.py
"""
import sys
import os
import csv
import re
from collections import Counter, defaultdict
from scapy.all import rdpcap, DNS, DNSQR, TCP, Raw, IP, UDP, Ether

HTTP_RE = re.compile(rb'^(GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+(\S+)\s+HTTP/', re.I | re.M)
HOST_RE = re.compile(rb'Host:\s*([^\r\n]+)', re.I)

def extract_http_from_payload(payload_bytes):
    """Return (method, path, host) or None."""
    if not payload_bytes:
        return None
    m = HTTP_RE.search(payload_bytes)
    if not m:
        return None
    method = m.group(1).decode(errors='ignore')
    path = m.group(2).decode(errors='ignore')
    host_m = HOST_RE.search(payload_bytes)
    host = host_m.group(1).decode(errors='ignore') if host_m else ''
    return method, path, host

def protocol_label(pkt):
    if pkt.haslayer(DNS):
        return 'DNS'
    if pkt.haslayer(TCP):
        # Common port based labeling
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport == 80 or sport == 80:
            return 'HTTP'
        if dport == 443 or sport == 443:
            return 'TLS'
        if dport == 22 or sport == 22:
            return 'SSH'
        if dport == 21 or sport == 21:
            return 'FTP'
        return 'TCP'
    if pkt.haslayer(UDP):
        return 'UDP'
    if pkt.haslayer(Ether) and pkt.type == 0x0806:
        return 'ARP'
    return 'OTHER'

def main(pcap_path):
    if not os.path.exists(pcap_path):
        print("PCAP not found:", pcap_path); sys.exit(1)

    print("Reading", pcap_path, " (this can be slow for large files)...")
    packets = rdpcap(pcap_path)

    # Outputs
    os.makedirs('evidence', exist_ok=True)
    urls_file = open('evidence/urls.csv', 'w', newline='', encoding='utf-8')
    dns_file = open('evidence/dns_queries.csv', 'w', newline='', encoding='utf-8')
    talkers_file = open('evidence/top_talkers.csv', 'w', newline='', encoding='utf-8')
    proto_file = open('evidence/protocol_counts.csv', 'w', newline='', encoding='utf-8')

    url_writer = csv.writer(urls_file)
    url_writer.writerow(['timestamp','src_ip','dst_ip','method','host','path'])

    dns_writer = csv.writer(dns_file)
    dns_writer.writerow(['timestamp','src_ip','qname','qtype'])

    proto_writer = csv.writer(proto_file)
    proto_writer.writerow(['protocol','packets'])

    # stats
    ip_pkt_counter = Counter()
    ip_byte_counter = Counter()
    proto_counter = Counter()

    http_seen = 0
    dns_seen = 0

    for pkt in packets:
        ts = pkt.time
        # IP layer check
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            # update talkers
            ip_pkt_counter[src] += 1
            ip_byte_counter[src] += len(pkt)
        else:
            # non-IP, skip top-talkers counting for IP
            src = dst = ''

        # DNS
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            # query
            q = pkt[DNSQR].qname
            try:
                qname = q.decode().rstrip('.')
            except Exception:
                qname = str(q)
            qtype = pkt[DNSQR].qtype
            dns_writer.writerow([ts, src, qname, qtype])
            proto_counter['DNS'] += 1
            dns_seen += 1
            continue

        # HTTP extraction (naive): check Raw payload for GET/Host
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            http = extract_http_from_payload(payload)
            if http:
                method, path, host = http
                url_writer.writerow([ts, src, dst, method, host, path])
                proto_counter['HTTP'] += 1
                http_seen += 1
                continue

        # heuristics for protocol counts
        label = protocol_label(pkt)
        proto_counter[label] += 1

    # write top talkers
    talk_writer = csv.writer(talkers_file)
    talk_writer.writerow(['ip','packets','bytes'])
    for ip, cnt in ip_pkt_counter.most_common(50):
        talk_writer.writerow([ip, cnt, ip_byte_counter[ip]])

    # write protocol counts
    for proto, cnt in proto_counter.most_common():
        proto_writer.writerow([proto, cnt])

    urls_file.close()
    dns_file.close()
    talkers_file.close()
    proto_file.close()
    print("Done. Outputs written to evidence/")
    print(f"HTTP entries: {http_seen}, DNS entries: {dns_seen}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 traffic_interceptor.py capture.pcap")
        sys.exit(1)
    main(sys.argv[1])

