#!/usr/bin/env python3
"""
attack_orchestrator_3tier.py

3-tier Mininet topology + benign traffic + labelled attack scenarios.

Features:
 - Core (s1) -> Spine (s2) -> Leaves (s3,s4,s5)
 - 6 hosts: h1,h2 (clients on leaf1), h3,h4 (servers on leaf2), h5,h6 (mixed on leaf3)
 - Benign services started on servers (HTTP, iperf, echo, small UDP)
 - Benign traffic loops (curl, iperf bursts, small UDP queries, pings)
 - Attack scenarios (SYN flood, UDP flood, ICMP flood, nmap scan, ssh brute-sim, botnet sim)
 - Writes /tmp/current_label with numeric labels during attack windows
 - Copies /tmp/insdn_features.csv -> ./collected_<ts>.csv at the end
 - Use `--cli` to drop into Mininet CLI at the end

Requirements on host: mininet, hping3, iperf3, socat, nmap, python3, netcat (nc)

Run:
  sudo python3 attack_orchestrator_3tier.py --benign --attacks --cli
"""

import os
import time
import subprocess
import argparse
import random
from pathlib import Path

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI

# ---- Config ----
LABEL_FILE = '/tmp/current_label'
CSV_IN = '/tmp/insdn_features.csv'         # produced by your Ryu app
COLLECT_PREFIX = './collected'
DEFAULT_DWELL = 14                         # seconds per attack
DEFAULT_CONTROLLER_IP = '127.0.0.1'
DEFAULT_CONTROLLER_PORT = 6653

# ---- helpers ----
def write_label(v: int):
    try:
        with open(LABEL_FILE, 'w') as fh:
            fh.write(str(int(v)))
    except Exception as e:
        info(f"*** Warning: cannot write label file: {e}\n")

def clear_label():
    write_label(0)

def sh(host, cmd: str):
    """
    Run a command inside a Mininet host in a non-blocking way.
    Use nohup + redirection + & so host.cmd doesn't block.
    Returns immediately.
    """
    # wrap the command to be run via bash; ensure it backgrounds
    wrapped = f"nohup bash -c \"{cmd}\" >/tmp/{host.name}_orch.log 2>&1 &"
    try:
        host.cmd(wrapped)
    except Exception as e:
        info(f"*** Warning: failed to exec on {host.name}: {e}\n")

def copy_csv_if_exists():
    if os.path.exists(CSV_IN):
        ts = int(time.time())
        dst = f"{COLLECT_PREFIX}_{ts}.csv"
        try:
            subprocess.run(['cp', CSV_IN, dst], check=True)
            info(f"*** CSV copied -> {dst}\n")
        except Exception as e:
            info(f"*** Failed copying CSV: {e}\n")
    else:
        info(f"*** No CSV found at {CSV_IN}\n")

# ---- topology ----
def build_net(controller_ip=DEFAULT_CONTROLLER_IP, controller_port=DEFAULT_CONTROLLER_PORT):
    """
    Build a 3-tier topology:
      s1 (core)
       └─ s2 (spine)
          ├─ s3 (leaf1) -> h1,h2 (clients)
          ├─ s4 (leaf2) -> h3,h4 (servers)
          └─ s5 (leaf3) -> h5,h6 (mixed/attackers)
    """
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True, autoStaticArp=True)
    c0 = RemoteController('c0', ip=controller_ip, port=controller_port)
    net.addController(c0)

    # switches (use canonical names to avoid dpid issues)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')   # core
    s2 = net.addSwitch('s2', protocols='OpenFlow13')   # spine
    s3 = net.addSwitch('s3', protocols='OpenFlow13')   # leaf1
    s4 = net.addSwitch('s4', protocols='OpenFlow13')   # leaf2
    s5 = net.addSwitch('s5', protocols='OpenFlow13')   # leaf3

    # hosts
    h1 = net.addHost('h1', ip='10.0.1.1/24')   # client
    h2 = net.addHost('h2', ip='10.0.1.2/24')   # client
    h3 = net.addHost('h3', ip='10.0.2.3/24')   # server
    h4 = net.addHost('h4', ip='10.0.2.4/24')   # server (iperf)
    h5 = net.addHost('h5', ip='10.0.3.5/24')   # mixed
    h6 = net.addHost('h6', ip='10.0.3.6/24')   # attacker/mixed

    # links: core <-> spine, spine <-> leaves, hosts <-> leaves
    net.addLink(s1, s2, cls=TCLink, bw=1000, delay='1ms')
    net.addLink(s2, s3, cls=TCLink, bw=500, delay='2ms')
    net.addLink(s2, s4, cls=TCLink, bw=500, delay='2ms')
    net.addLink(s2, s5, cls=TCLink, bw=500, delay='2ms')

    net.addLink(h1, s3, cls=TCLink, bw=100, delay='3ms')
    net.addLink(h2, s3, cls=TCLink, bw=100, delay='3ms')
    net.addLink(h3, s4, cls=TCLink, bw=100, delay='3ms')
    net.addLink(h4, s4, cls=TCLink, bw=100, delay='3ms')
    net.addLink(h5, s5, cls=TCLink, bw=100, delay='3ms')
    net.addLink(h6, s5, cls=TCLink, bw=100, delay='3ms')

    net.build()
    c0.start()
    for sw in (s1, s2, s3, s4, s5):
        sw.start([c0])

    # set simple default routes (makes some host utilities happy)
    for h in (h1, h2, h3, h4, h5, h6):
        try:
            h.setDefaultRoute('dev ' + h.defaultIntf().name)
        except Exception:
            pass

    info("*** Fabric and services ready\n")
    return net

# ---- benign services + traffic ----
def start_benign_services(net):
    """
    Start background benign servers on hosts:
      - h3: http (80), socat echo (2222)
      - h4: http (8080), iperf3 server
      - h5: UDP echo (simulate DNS on 5353)
    """
    h3 = net.get('h3'); h4 = net.get('h4'); h5 = net.get('h5')

    # HTTP servers
    sh(h3, 'python3 -m http.server 80')
    sh(h4, 'python3 -m http.server 8080')

    # TCP echo on 2222 via socat
    sh(h3, 'socat TCP-LISTEN:2222,reuseaddr,fork EXEC:/bin/cat')

    # iperf3 server
    sh(h4, 'iperf3 -s')

    # UDP echo (simple netcat loop)
    # Use a small loop to keep process light
    sh(h5, "bash -c 'while true; do nc -u -l -p 5353 -c \"cat\"; done'")

    info("*** Benign services started on h3/h4/h5\n")

def start_benign_traffic(net):
    """
    Launch live benign traffic loops on clients:
     - h1/h2/h6: repeated curl to servers
     - iperf bursts from h1/h2/h5 toward h4
     - small UDP queries (h1,h2)
     - light ping background
    All are backgrounded so this function returns quickly.
    """
    h1 = net.get('h1'); h2 = net.get('h2'); h6 = net.get('h6'); h4 = net.get('h4'); h5 = net.get('h5')

    # curl loops
    sh(h1, f"bash -c 'while true; do curl -m 2 -s http://10.0.2.3/ >/dev/null; sleep 0.2; done'")
    sh(h2, f"bash -c 'while true; do curl -m 2 -s http://10.0.2.3/ >/dev/null; sleep 0.4; done'")
    sh(h6, f"bash -c 'while true; do curl -m 2 -s http://10.0.2.4:8080/ >/dev/null; sleep 0.6; done'")

    # iperf bursts
    sh(h1, f"bash -c 'while true; do iperf3 -c 10.0.2.4 -t 5 -b 20M >/tmp/{h1.name}_iperf.log 2>&1; sleep 15; done'")
    sh(h2, f"bash -c 'while true; do iperf3 -c 10.0.2.4 -t 5 -b 10M >/tmp/{h2.name}_iperf.log 2>&1; sleep 20; done'")
    sh(h5, f"bash -c 'while true; do iperf3 -c 10.0.2.4 -t 4 -b 5M >/tmp/{h5.name}_iperf.log 2>&1; sleep 25; done'")

    # UDP tiny queries (simulate DNS-like lookups)
    for h in (h1, h2, h6):
        sh(h, f"bash -c 'while true; do echo -n \"q$(shuf -i1-100000 -n1)\" | nc -u -w 1 10.0.3.5 5353 >/dev/null 2>&1; sleep 0.5; done'")

    # pings
    sh(h1, 'bash -c "while true; do ping -c 1 -W 1 10.0.2.4; sleep 1; done"')
    sh(h2, 'bash -c "while true; do ping -c 1 -W 1 10.0.2.3; sleep 1.3; done"')

    info("*** Benign background traffic started\n")

def stop_benign(net):
    for h in net.hosts:
        sh(h, "pkill -f 'http.server' || true")
        sh(h, "pkill -f 'iperf3' || true")
        sh(h, "pkill -f 'socat' || true")
        sh(h, "pkill -f 'nc -u' || true")
        sh(h, "pkill -f 'curl -m' || true")
        sh(h, "pkill -f 'ping -c' || true")
    info("*** Stopped benign processes (best-effort)\n")

# ---- attacks ----
def syn_flood(attacker, target, dur=10):
    sh(attacker, f"timeout {dur} hping3 --flood -S -p 80 --rand-source {target}")

def udp_flood(attacker, target, dur=10):
    # Use scapy one-liner inside host (backgrounded by sh wrapper)
    script = (
        "from scapy.all import IP,UDP,Raw,send\n"
        f"for i in range(1000): send(IP(dst='{target}')/UDP(dport=53)/Raw(b'X'*1200), verbose=False)\n"
    )
    sh(attacker, f"python3 - <<PY\n{script}\nPY")

def icmp_flood(attacker, target, dur=10):
    sh(attacker, f"timeout {dur} hping3 --flood --icmp {target}")

def nmap_scan(attacker, target):
    sh(attacker, f"nmap -sS -p 1-1024 {target}")

def ssh_bruteforce_sim(attacker, target, tries=300):
    # lightweight TCP connect attempts (no external hydra dependency)
    sh(attacker, f"bash -c 'for i in $(seq 1 {tries}); do timeout 1 bash -c \"</dev/tcp/{target}/2222\" >/dev/null 2>&1 || true; sleep 0.05; done'")

def botnet_sim(attackers, target, dur=15):
    for a in attackers:
        bot_cmd = (
            "python3 - <<PY\n"
            "from scapy.all import IP,UDP,Raw,send\n"
            f"for i in range(400): send(IP(dst='{target}')/UDP(dport=80)/Raw(b'B'*200), verbose=False)\n"
            "PY\n"
        )
        sh(a, bot_cmd)

# ---- orchestrator sequence ----
def run_scenarios(net, with_attacks=True, dwell=DEFAULT_DWELL):
    h1 = net.get('h1'); h3 = net.get('h3'); h4 = net.get('h4'); h5 = net.get('h5'); h6 = net.get('h6')
    target = '10.0.2.3'  # h3 as main victim

    if not with_attacks:
        info("*** Attacks skipped (benign-only run)\n")
        return

    info(f"*** Running attack scenarios (dwell={dwell}s each)\n")

    # 1) SYN flood (label=1)
    write_label(1)
    syn_flood(h1, target, dur=max(1, dwell-2))
    time.sleep(dwell)
    clear_label()
    time.sleep(1)

    # 2) UDP flood (label=2)
    write_label(2)
    udp_flood(h3, target, dur=max(1, dwell-2))
    time.sleep(dwell)
    clear_label()
    time.sleep(1)

    # 3) ICMP flood (label=3)
    write_label(3)
    icmp_flood(h4, target, dur=max(1, dwell-2))
    time.sleep(dwell)
    clear_label()
    time.sleep(1)

    # 4) nmap scan (label=4)
    write_label(4)
    nmap_scan(h5, target)
    time.sleep(dwell)
    clear_label()
    time.sleep(1)

    # 5) ssh brute-sim (label=5)
    write_label(5)
    ssh_bruteforce_sim(h6, '10.0.2.3', tries=500)
    time.sleep(dwell)
    clear_label()
    time.sleep(1)

    # 6) botnet sim (label=6)
    write_label(6)
    botnet_sim([h1, h3, h4], target, dur=max(1, dwell-2))
    time.sleep(dwell)
    clear_label()
    time.sleep(1)

    info("*** Attack scenarios finished\n")

# ---- main ----
def main():
    parser = argparse.ArgumentParser(description="3-tier Mininet attack orchestrator")
    parser.add_argument("--controller-ip", default=DEFAULT_CONTROLLER_IP)
    parser.add_argument("--controller-port", type=int, default=DEFAULT_CONTROLLER_PORT)
    parser.add_argument("--benign", action="store_true", help="start benign background traffic")
    parser.add_argument("--attacks", action="store_true", help="run labelled attack scenarios")
    parser.add_argument("--dwell", type=int, default=DEFAULT_DWELL, help="seconds per attack")
    parser.add_argument("--cli", action="store_true", help="enter Mininet CLI at end")
    args = parser.parse_args()

    setLogLevel('info')
    clear_label()

    # Build and start network
    net = build_net(args.controller_ip, args.controller_port)
    try:
        if args.benign:
            start_benign_services(net)
            start_benign_traffic(net)
            time.sleep(6)  # warm-up

        if args.attacks:
            run_scenarios(net, with_attacks=True, dwell=args.dwell)

        # final wait to allow Ryu to flush flows
        time.sleep(4)
        copy_csv_if_exists()

        if args.cli:
            info("*** Entering CLI (Ctrl-D to quit)\n")
            CLI(net)

    finally:
        info("*** Cleaning up: clearing label, stopping benign processes, stopping network\n")
        clear_label()
        stop_benign(net)
        net.stop()

if __name__ == "__main__":
    main()
