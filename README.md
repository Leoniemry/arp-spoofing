# ARP Spoofing — Task 1 (Lab)

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
   `sudo sysctl -w net.ipv4.ip_forward=1`  # I enabled this manually for traffic forwarding
   Verify: `cat /proc/sys/net/ipv4/ip_forward` -> `1`
3. Launch ARP spoof:
   `sudo python3 arp_spoof.py -t 10.0.0.2 -g 10.0.0.1 -f 2`
   - The script prints resolved MACs and a packet counter (verbose).
4. Generate traffic on victim (browser / curl / dig).
5. Stop the script (Ctrl+C) to trigger ARP restore.
6. Stop tcpdump (Ctrl+C).

## Evidence included
See `evidence/` for screenshots and `pcap_files/attacker_capture.pcap` for full packet capture. Wireshark screenshots show ARP replies advertising attacker's MAC for both 10.0.0.1 and 10.0.0.2, plus IP packets between victim and gateway observed on attacker (MitM).
