# ARP Spoofing

## What is included
- `arp_spoof.py` : Python script (Scapy) to poison ARP caches of victim and gateway.
- `pcap_files/attacker_capture.pcap` : capture recorded during attack.
- `evidence/` : screenshots (ARP before/during/after, attacker iface, Wireshark proofs).
- `requirements.txt` : python dependencies.

## Usage (how I executed the experiment)
Environment:
- Topology: Gateway 10.0.0.1 (enp0s3), Victim 10.0.0.2 (enp0s3), Attacker 10.0.0.3 (eth0, Kali)
- Lab isolated (internal network). Snapshots taken prior to experiments.

Commands run:
1. Start capture on attacker:
   `sudo tcpdump -i eth0 -w pcap_files/attacker_capture.pcap`
2. (If needed) enable forwarding on attacker **manually**:
   `sudo sysctl -w net.ipv4.ip_forward=1`
   Verify: `cat /proc/sys/net/ipv4/ip_forward` -> `1`
3. Launch ARP spoof:
   `sudo python3 arp_spoof.py -t 10.0.0.2 -g 10.0.0.1 -f 2`
   - The script prints resolved MACs and a packet counter (verbose).
4. Generate traffic on victim (browser / curl / dig).
5. Stop the script (Ctrl+C) to trigger ARP restore.
6. Stop tcpdump (Ctrl+C).

## Evidence included
See `evidence/` for screenshots and `pcap_files/attacker_capture.pcap` for full packet capture. Wireshark screenshots show ARP replies advertising attacker's MAC for both 10.0.0.1 and 10.0.0.2, plus IP packets between victim and gateway observed on attacker (MitM).



# Traffic Capture & Analysis

## What is included
- `traffic_interceptor.py` : parser that reads a pcap and exports CSVs (URLs, DNS queries, top talkers, protocol counts).  
- `pcap_files/attacker_capture.pcap` : pcap recorded during the attack (input).  
- `evidence/` : parser outputs and annotated Wireshark screenshots.

## Environment (assumption)
- Use attacker VM capture from Task 1: `pcap_files/attacker_capture.pcap`.  
- Dependencies are listed in `requirements.txt`.

## Exact steps (copy‑paste)
1. Confirm `pcap_files/attacker_capture.pcap` is present.  
2. Run the parser:
```bash
python3 traffic_interceptor.py pcap_files/attacker_capture.pcap
```
3. Expected outputs (written to evidence/)
- urls.csv — timestamp, src_ip, dst_ip, method, host, path
- dns_queries.csv — timestamp, src_ip, qname, qtype
- top_talkers.csv — ip, packets, bytes
- protocol_counts.csv — protocol, count



# Selective DNS Spoofing

## What is included
- `dns_spoof.py` : script to intercept DNS queries and reply with attacker-controlled IPs for selected domains.  
- `configs/hosts.json` : domain → spoofed IP mapping.  
- `pcap_files/` : capture(s) recorded during DNS MitM test.  
- `evidence/` : browser screenshot, webserver log, Wireshark annotated screenshot.

## Assumptions
- Attacker is already in MitM position (Task 1 ARP spoof running / attacker sees victim traffic).  
- Use the attacker capture interface (e.g. `eth0`).  
- Dependencies are in `requirements.txt`.

## Exact steps (copy‑paste, run in order)

1. Prepare `configs/hosts.json` (example):
```json
{"example.com":"10.0.0.3","test.local":"10.0.0.3"}
```
2. Start attacker web server that will serve the fake page:
```bash
sudo python3 -m http.server 80
```
3. Ensure ARP spoof from Task 1 is active so attacker is MitM (if not, start arp_spoof.py first).
4. Start a packet capture for DNS test:
```bash
sudo tcpdump -i eth0 -w pcap_files/dns_attack.pcap
```
5. Run DNS spoofer:
```bash
sudo python3 dns_spoof.py -i eth0 -t 10.0.0.2 -c hosts.json -r 6 -d 0.01
```
6. From the victim machine, request the target domain (browser or curl).


