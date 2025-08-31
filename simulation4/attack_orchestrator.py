#!/usr/bin/env python3
"""
attack_orchestrator_3tier.py

3-tier Mininet topology with mixed benign and attack traffic for all 7 attack types.
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
CSV_IN = '/tmp/insdn_features.csv'
COLLECT_PREFIX = './collected'
DEFAULT_DWELL = 10  # Longer dwell time for mixed traffic
DEFAULT_CONTROLLER_IP = '127.0.0.1'
DEFAULT_CONTROLLER_PORT = 6653

# ---- helpers ----
def write_label(label: str):
    try:
        with open(LABEL_FILE, 'w') as fh:
            fh.write(str(label))
    except Exception as e:
        info(f"*** Warning: cannot write label file: {e}\n")

def clear_label():
    write_label("benign")

def sh(host, cmd: str, background=False):
    """Run a command inside a Mininet host."""
    if background:
        cmd = cmd + " &"
    try:
        return host.cmd(cmd)
    except Exception as e:
        info(f"*** Warning: failed to exec on {host.name}: {e}\n")
        return None
    
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
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True, autoStaticArp=True)
    c0 = RemoteController('c0', ip=controller_ip, port=controller_port)
    net.addController(c0)

    # switches
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')
    s4 = net.addSwitch('s4', protocols='OpenFlow13')
    s5 = net.addSwitch('s5', protocols='OpenFlow13')

    # hosts
    h1 = net.addHost('h1', ip='10.0.1.1/24')
    h2 = net.addHost('h2', ip='10.0.1.2/24')
    h3 = net.addHost('h3', ip='10.0.2.3/24')
    h4 = net.addHost('h4', ip='10.0.2.4/24')
    h5 = net.addHost('h5', ip='10.0.3.5/24')
    h6 = net.addHost('h6', ip='10.0.3.6/24')

    # links
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

    for h in (h1, h2, h3, h4, h5, h6):
        try:
            h.setDefaultRoute('dev ' + h.defaultIntf().name)
        except Exception:
            pass

    info("*** Fabric and services ready\n")
    return net

# ---- benign services + traffic ----
def start_benign_services(net):
    h3 = net.get('h3'); h4 = net.get('h4'); h5 = net.get('h5')

    # HTTP servers
    sh(h3, 'python3 -m http.server 80', background=True)
    sh(h4, 'python3 -m http.server 8080', background=True)

    # TCP echo
    sh(h3, 'socat TCP-LISTEN:2222,reuseaddr,fork EXEC:/bin/cat', background=True)

    # iperf3 server
    sh(h4, 'iperf3 -s', background=True)

    # UDP echo
    sh(h5, "while true; do nc -u -l -p 5353 -c 'cat'; done", background=True)

    info("*** Benign services started on h3/h4/h5\n")

def start_benign_traffic(net):
    h1 = net.get('h1'); h2 = net.get('h2'); h6 = net.get('h6'); h4 = net.get('h4'); h5 = net.get('h5')

    # curl loops
    sh(h1, "while true; do curl -m 2 -s http://10.0.2.3/ >/dev/null; sleep 0.2; done", background=True)
    sh(h2, "while true; do curl -m 2 -s http://10.0.2.3/ >/dev/null; sleep 0.4; done", background=True)
    sh(h6, "while true; do curl -m 2 -s http://10.0.2.4:8080/ >/dev/null; sleep 0.6; done", background=True)

    # iperf bursts
    sh(h1, "while true; do iperf3 -c 10.0.2.4 -t 5 -b 20M >/tmp/h1_iperf.log 2>&1; sleep 15; done", background=True)
    sh(h2, "while true; do iperf3 -c 10.0.2.4 -t 5 -b 10M >/tmp/h2_iperf.log 2>&1; sleep 20; done", background=True)
    sh(h5, "while true; do iperf3 -c 10.0.2.4 -t 4 -b 5M >/tmp/h5_iperf.log 2>&1; sleep 25; done", background=True)

    # UDP queries
    for h in (h1, h2, h6):
        sh(h, "while true; do echo -n 'q$(shuf -i1-100000 -n1)' | nc -u -w 1 10.0.3.5 5353 >/dev/null 2>&1; sleep 0.5; done", background=True)

    # pings
    sh(h1, "while true; do ping -c 1 -W 1 10.0.2.4; sleep 1; done", background=True)
    sh(h2, "while true; do ping -c 1 -W 1 10.0.2.3; sleep 1.3; done", background=True)

    info("*** Benign background traffic started\n")

def stop_benign(net):
    for h in net.hosts:
        sh(h, "pkill -f 'python3 -m http.server'")
        sh(h, "pkill -f 'iperf3'")
        sh(h, "pkill -f 'socat'")
        sh(h, "pkill -f 'nc -u'")
        sh(h, "pkill -f 'curl'")
        sh(h, "pkill -f 'ping'")
        sh(h, "pkill -f 'hping3'")
        sh(h, "pkill -f 'nmap'")
        sh(h, "pkill -f 'hydra'")
    info("*** Stopped benign processes\n")

# ---- attack functions ----
def run_attack(attacker, cmd, duration):
    """Run attack command with proper backgrounding and cleanup"""
    try:
        # Use cmd() instead of popen for better compatibility
        attacker.cmd(f"timeout {duration} {cmd} &")
        time.sleep(duration)
    except Exception as e:
        info(f"*** Attack failed on {attacker.name}: {e}\n")

def dos_syn_flood(attacker, target, dur=5):
    """DoS: SYN Flood"""
    run_attack(attacker, f"hping3 --flood -S -p 80 {target}", dur)

def dos_udp_flood(attacker, target, dur=5):
    """DoS: UDP Flood"""
    run_attack(attacker, f"hping3 --flood --udp -p 53 {target}", dur)

def dos_icmp_flood(attacker, target, dur=5):
    """DoS: ICMP Flood"""
    run_attack(attacker, f"hping3 --flood --icmp {target}", dur)

def ddos_syn_flood(attackers, target, dur=5):
    """DDoS: Multi-source SYN Flood"""
    for i, attacker in enumerate(attackers):
        base_port = 50000 + (i * 1000)
        run_attack(attacker, f"hping3 --flood -S -p 80 --baseport {base_port} {target}", dur)

def probe_nmap_stealth(attacker, target):
    """Probe: Stealth Scan"""
    # Use direct cmd execution for nmap
    attacker.cmd(f"nmap -sS -T4 -p 1-1024 {target} >/dev/null 2>&1 &")

def probe_nmap_version(attacker, target):
    """Probe: Version Detection"""
    attacker.cmd(f"nmap -sV -T4 -p 80,443,2222 {target} >/dev/null 2>&1 &")

def bruteforce_ssh(attacker, target, tries=100):
    """Bruteforce: SSH"""
    cmd = f"for i in $(seq 1 {tries}); do timeout 0.5 bash -c \"</dev/tcp/{target}/2222\" >/dev/null 2>&1 || true; sleep 0.05; done"
    attacker.cmd(cmd + " &")

def bruteforce_http(attacker, target, tries=50):
    """Bruteforce: HTTP Basic Auth"""
    cmd = f"for i in $(seq 1 {tries}); do curl -s -u user$i:pass$i http://{target}/ >/dev/null 2>&1; sleep 0.1; done"
    attacker.cmd(cmd + " &")

def web_attack_sql_injection(attacker, target):
    """Web Attack: SQL Injection"""
    payloads = ["' OR '1'='1", "admin' --"]
    for payload in payloads:
        attacker.cmd(f"curl -s -G --data-urlencode \"q={payload}\" http://{target}/ >/dev/null 2>&1 &")
        time.sleep(0.5)

def web_attack_xss(attacker, target):
    """Web Attack: XSS"""
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    for payload in payloads:
        attacker.cmd(f"curl -s -G --data-urlencode \"search={payload}\" http://{target}/ >/dev/null 2>&1 &")
        time.sleep(0.5)

def botnet_ddos_http(attackers, target, dur=5):
    """Botnet: HTTP Flood"""
    for a in attackers:
        a.cmd(f"timeout {dur} python3 -c \"import requests; import time; start=time.time(); while time.time()-start<{dur}: requests.get('http://{target}/', timeout=1)\" &")
# ---- orchestrator sequence ----
def run_scenarios(net, with_attacks=True, dwell=10, benign_ratio=3):
    h1 = net.get('h1'); h2 = net.get('h2'); h3 = net.get('h3')
    h4 = net.get('h4'); h5 = net.get('h5'); h6 = net.get('h6')
    target = '10.0.2.3'  # h3 as main victim
    web_target = '10.0.2.3'  # HTTP server

    # Initial benign period
    info("*** Initial benign period (30 seconds)\n")
    write_label("benign")
    time.sleep(30)

    if not with_attacks:
        info("*** Attacks skipped (benign-only run)\n")
        clear_label()
        return

    info(f"*** Running mixed attack scenarios (dwell={dwell}s each)\n")

    # 1) DoS Attacks
    info("*** Starting DoS attacks\n")
    write_label("dos")
    dos_syn_flood(h1, target, dwell//2)
    dos_udp_flood(h2, target, dwell//2)
    dos_icmp_flood(h6, target, dwell//2)
    time.sleep(dwell)
    clear_label()
    time.sleep(5)  # Cool down

    # 2) DDoS Attack
    info("*** Starting DDoS attack\n")
    write_label("ddos")
    ddos_syn_flood([h1, h2, h5, h6], target, dwell)
    time.sleep(dwell)
    clear_label()
    time.sleep(5)

    # 3) Probe/Scanning Attacks
    info("*** Starting Probe attacks\n")
    write_label("probe")
    probe_nmap_stealth(h5, target)
    probe_nmap_version(h6, target)
    time.sleep(dwell)
    clear_label()
    time.sleep(5)

    # 4) Bruteforce Attacks
    info("*** Starting Bruteforce attacks\n")
    write_label("bruteforce")
    bruteforce_ssh(h6, target, tries=200)
    bruteforce_http(h2, web_target, tries=100)
    time.sleep(dwell)
    clear_label()
    time.sleep(5)

    # 5) Web Application Attacks
    info("*** Starting Web attacks\n")
    write_label("web_attack")
    web_attack_sql_injection(h1, web_target)
    web_attack_xss(h2, web_target)
    time.sleep(dwell)
    clear_label()
    time.sleep(5)

    # 6) Botnet DDoS
    info("*** Starting Botnet DDoS\n")
    write_label("botnet")
    botnet_ddos_http([h1, h2, h5, h6], web_target, dwell)
    time.sleep(dwell)
    clear_label()
    time.sleep(5)

    # 7) Mixed attack period (all attacks simultaneously)
    info("*** Starting mixed attack period\n")
    write_label("mixed_attacks")
    
    # Start all attacks simultaneously
    dos_syn_flood(h1, target, dwell)
    ddos_syn_flood([h2, h5], target, dwell)
    probe_nmap_stealth(h6, target)
    bruteforce_ssh(h6, target, tries=100)
    web_attack_sql_injection(h2, web_target)
    
    time.sleep(dwell)
    clear_label()
    time.sleep(5)

    # Final benign period
    info("*** Final benign period (30 seconds)\n")
    write_label("benign")
    time.sleep(30)
    clear_label()

    info("*** All attack scenarios finished\n")

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

    net = build_net(args.controller_ip, args.controller_port)
    try:
        if args.benign:
            start_benign_services(net)
            start_benign_traffic(net)
            time.sleep(5)  # Warm-up for services

        if args.attacks:
            run_scenarios(net, with_attacks=True, dwell=args.dwell)

        time.sleep(3)  # Allow final flows to be processed
        copy_csv_if_exists()

        if args.cli:
            info("*** Entering CLI (Ctrl-D to quit)\n")
            CLI(net)

    finally:
        info("*** Cleaning up\n")
        clear_label()
        stop_benign(net)
        net.stop()

if __name__ == "__main__":
    main()