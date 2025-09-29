#!/usr/bin/env python3
"""

watch -n 0.5 'echo -n "$(date): "; cat /tmp/current_label'

attack_orchestrator.py

3-tier Mininet topology with mixed benign and attack traffic for all attack types.
Fixed version with better attack timing and packet generation.
"""

import os
import time
import subprocess
import argparse
import random
import threading
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
DEFAULT_DWELL = 15
DEFAULT_CONTROLLER_IP = '127.0.0.1'
DEFAULT_CONTROLLER_PORT = 6653

# ---- helpers ----
def force_label(label):
    """Force the label to be set correctly"""
    try:
        subprocess.run(['rm', '-f', '/tmp/current_label'], check=True)
        time.sleep(0.1)
        
        with open('/tmp/current_label', 'w') as f:
            f.write(label)
        
        time.sleep(0.1)
        with open('/tmp/current_label', 'r') as f:
            actual = f.read().strip()
        
        print(f"🔧 LABEL SET: '{label}' -> Verified: '{actual}'")
        
        if actual != label:
            print(f"🚨 LABEL MISMATCH: Expected '{label}', got '{actual}'")
            force_label(label)
            
    except Exception as e:
        print(f"❌ Error setting label: {e}")

def clear_label():
    force_label("benign")

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
    sh(h1, "while true; do curl -m 2 -s http://10.0.2.3/ >/dev/null; sleep 0.5; done", background=True)
    sh(h2, "while true; do curl -m 2 -s http://10.0.2.3/ >/dev/null; sleep 0.7; done", background=True)
    sh(h6, "while true; do curl -m 2 -s http://10.0.2.4:8080/ >/dev/null; sleep 1.0; done", background=True)

    # iperf bursts
    sh(h1, "while true; do iperf3 -c 10.0.2.4 -t 3 -b 10M >/tmp/h1_iperf.log 2>&1; sleep 10; done", background=True)
    sh(h2, "while true; do iperf3 -c 10.0.2.4 -t 3 -b 5M >/tmp/h2_iperf.log 2>&1; sleep 15; done", background=True)
    sh(h5, "while true; do iperf3 -c 10.0.2.4 -t 2 -b 3M >/tmp/h5_iperf.log 2>&1; sleep 20; done", background=True)

    # UDP queries
    for h in (h1, h2, h6):
        sh(h, "while true; do echo -n 'q$(shuf -i1-100000 -n1)' | nc -u -w 1 10.0.3.5 5353 >/dev/null 2>&1; sleep 1; done", background=True)

    # pings
    sh(h1, "while true; do ping -c 3 -W 1 10.0.2.4; sleep 3; done", background=True)
    sh(h2, "while true; do ping -c 3 -W 1 10.0.2.3; sleep 4; done", background=True)

    info("*** Benign background traffic started\n")

# ---- attack functions ----
def run_attack(attacker, cmd, duration, background=False):
    """Run attack command with proper logging"""
    try:
        info(f"*** Starting attack on {attacker.name}: {cmd[:80]}...\n")
        if background:
            attacker.cmd(f"{cmd} &")
            time.sleep(2)
        else:
            attacker.cmd(f"timeout {duration} {cmd} &")
            time.sleep(duration)
    except Exception as e:
        info(f"*** Attack failed on {attacker.name}: {e}\n")

def dos_syn_flood(attacker, target, dur=10):
    """DoS: SYN Flood"""
    print(f"🎯 EXECUTING: DoS SYN Flood from {attacker.name}")
    run_attack(attacker, f"hping3 --fast -S -p 80 --flood {target}", dur)

def dos_udp_flood(attacker, target, dur=10):
    """DoS: UDP Flood"""
    print(f"🎯 EXECUTING: DoS UDP Flood from {attacker.name}")
    run_attack(attacker, f"hping3 --fast --udp -p 53 --flood {target}", dur)

def dos_icmp_flood(attacker, target, dur=10):
    """DoS: ICMP Flood"""
    print(f"🎯 EXECUTING: DoS ICMP Flood from {attacker.name}")
    run_attack(attacker, f"hping3 --fast --icmp --flood {target}", dur)

def ddos_syn_flood(attackers, target, dur=12):
    """DDoS: Multi-source SYN Flood"""
    print(f"🎯 EXECUTING: DDoS SYN Flood from {len(attackers)} attackers")
    for i, attacker in enumerate(attackers):
        base_port = 50000 + (i * 1000)
        run_attack(attacker, f"hping3 --fast -S -p 80 --flood --baseport {base_port} {target}", dur)

def probe_nmap_stealth(attacker, target):
    """Probe: Stealth Scan"""
    print(f"🎯 EXECUTING: Nmap Stealth Scan from {attacker.name}")
    attacker.cmd(f"nmap -sS -T4 -p 1-500 {target} >/tmp/nmap_scan.log 2>&1 &")

def probe_nmap_version(attacker, target):
    """Probe: Version Detection"""
    print(f"🎯 EXECUTING: Nmap Version Scan from {attacker.name}")
    attacker.cmd(f"nmap -sV -T4 -p 80,443,2222,8080,21,25,53 {target} >/tmp/nmap_version.log 2>&1 &")

def bruteforce_ssh(attacker, target, dur=10):
    """SSH brute force"""
    print(f"🎯 EXECUTING: SSH Brute Force from {attacker.name}")
    cmd = f"for i in {{1..100}}; do echo 'ssh_attempt_$i' | nc -w 1 {target} 22 & done"
    attacker.cmd(f"timeout {dur} bash -c '{cmd}'")
    time.sleep(dur)

def bruteforce_http(attacker, target, dur=10):
    """HTTP brute force"""
    print(f"🎯 EXECUTING: HTTP Brute Force from {attacker.name}")
    cmd = f"for i in {{1..50}}; do curl -m 2 -s 'http://{target}/?auth=attempt$i' >/dev/null 2>&1 & done"
    attacker.cmd(f"timeout {dur} bash -c '{cmd}'")
    time.sleep(dur)

def web_attack_sql_injection(attacker, target, dur=15):
    """SQL injection - WEB ATTACK"""
    print(f"🎯 EXECUTING: WEB SQL Injection from {attacker.name}")
    
    # TRIPLE CHECK the web label
    print("🔍 WEB ATTACK: Setting label to 'web'")
    force_label("web")
    time.sleep(1)
    
    # Verify label is still web
    with open('/tmp/current_label', 'r') as f:
        current_label = f.read().strip()
        print(f"🔍 WEB ATTACK: Current label before attack: '{current_label}'")
    
    if current_label != "web":
        print(f"🚨 WEB ATTACK CRITICAL: Label is '{current_label}', should be 'web'")
        force_label("web")
    
    # Simple continuous SQL injection
    cmd = f"""
    for i in $(seq 1 {dur}); do
        curl -m 2 -s "http://{target}/?id=1' OR '1'='1" >/dev/null &
        curl -m 2 -s "http://{target}/login.php?user=admin' --" >/dev/null &
        curl -m 2 -s "http://{target}/search.php?q=1' UNION SELECT 1,2,3--" >/dev/null &
        sleep 0.5
    done
    wait
    """
    
    attacker.cmd(f"timeout {dur+5} bash -c '{cmd}' &")
    
    # Monitor label during attack
    start_time = time.time()
    while time.time() - start_time < dur + 2:
        with open('/tmp/current_label', 'r') as f:
            label = f.read().strip()
            if label != "web":
                print(f"🚨 WEB ATTACK LABEL LOST: '{label}' at {time.time()}")
                force_label("web")
        time.sleep(1)
    
    print(f"✅ WEB ATTACK: SQL Injection completed from {attacker.name}")

def web_attack_xss(attacker, target, dur=15):
    """XSS attacks - WEB ATTACK"""
    print(f"🎯 EXECUTING: WEB XSS Attack from {attacker.name}")
    
    # Ensure web label
    force_label("web")
    time.sleep(1)
    
    # Simple continuous XSS
    cmd = f"""
    for i in $(seq 1 {dur}); do
        curl -m 2 -s "http://{target}/?search=<script>alert('XSS')</script>" >/dev/null &
        curl -m 2 -s "http://{target}/comment.php?text=<img src=x onerror=alert(1)>" >/dev/null &
        curl -m 2 -s "http://{target}/submit.php" -d "content=<body onload=alert(1)>" >/dev/null &
        sleep 0.5
    done
    wait
    """
    
    attacker.cmd(f"timeout {dur+5} bash -c '{cmd}' &")
    
    # Monitor label during attack
    start_time = time.time()
    while time.time() - start_time < dur + 2:
        with open('/tmp/current_label', 'r') as f:
            label = f.read().strip()
            if label != "web":
                print(f"🚨 WEB ATTACK LABEL LOST: '{label}' at {time.time()}")
                force_label("web")
        time.sleep(1)
    
    print(f"✅ WEB ATTACK: XSS completed from {attacker.name}")

def botnet_ddos_http(attackers, target, dur=12):
    """Botnet HTTP flood"""
    print(f"🎯 EXECUTING: Botnet DDoS from {len(attackers)} attackers")
    for a in attackers:
        cmd = f"for i in $(seq 1 1000); do curl -s http://{target}/ >/dev/null 2>&1; sleep 0.01; done"
        run_attack(a, cmd, dur)

def u2r_attack(attacker, target, dur=12):
    """U2R attacks"""
    print(f"🎯 EXECUTING: U2R Attack from {attacker.name}")
    script = f"""#!/bin/bash
for i in {{1..50}}; do
    python3 -c "print('A'*1000)" | nc -w 1 {target} 80 &
    python3 -c "print('B'*500)" | nc -w 1 {target} 22 &
    sleep 0.1
done
sleep {dur}
"""
    attacker.cmd(f"echo '{script}' > /tmp/u2r_attack.sh")
    attacker.cmd("chmod +x /tmp/u2r_attack.sh")
    attacker.cmd(f"timeout {dur+3} /tmp/u2r_attack.sh &")
    time.sleep(dur)

# ---- orchestrator sequence ----
def run_selective_scenarios(net, args):
    h1, h2, h3, h4, h5, h6 = [net.get(f'h{i}') for i in range(1, 7)]
    target = '10.0.2.3'
    
    # Define all possible scenarios
    all_scenarios = {
        'dos': lambda: [
            info("*** Starting DoS attacks\n"),
            dos_syn_flood(h1, target, args.dwell),
            dos_udp_flood(h2, target, args.dwell),
            dos_icmp_flood(h6, target, args.dwell)
        ],
        
        'ddos': lambda: [
            info("*** Starting DDoS attacks\n"),
            ddos_syn_flood([h1, h2, h5, h6], target, args.dwell)
        ],
        
        'probe': lambda: [
            info("*** Starting probing attacks\n"),
            probe_nmap_stealth(h5, target),
            probe_nmap_version(h6, target),
            time.sleep(args.dwell)
        ],
        
        'bfa': lambda: [
            info("*** Starting brute force attacks\n"),
            bruteforce_ssh(h5, target, args.dwell),
            bruteforce_http(h6, target, args.dwell)
        ],
        
        'web': lambda: [
            info("*** Starting WEB attacks\n"),
            print("🎯 WEB SCENARIO: Starting web attacks with label 'web'"),
            web_attack_sql_injection(h1, target, args.dwell),
            web_attack_xss(h2, target, args.dwell)
        ],
        
        'botnet': lambda: [
            info("*** Starting botnet attacks\n"),
            botnet_ddos_http([h1, h2, h5, h6], target, args.dwell)
        ],
        
        'u2r': lambda: [
            info("*** Starting U2R attacks\n"),
            u2r_attack(h6, target, args.dwell)
        ]
    }
    
    # Determine which scenarios to run
    scenarios_to_run = []
    
    if args.all:
        scenarios_to_run = list(all_scenarios.keys())
        info("*** Running ALL attack scenarios\n")
    elif args.benign_only:
        info("*** Running benign traffic only\n")
        scenarios_to_run = []
    else:
        if args.dos: scenarios_to_run.append('dos')
        if args.ddos: scenarios_to_run.append('ddos') 
        if args.probe: scenarios_to_run.append('probe')
        if args.bfa: scenarios_to_run.append('bfa')
        if args.web: scenarios_to_run.append('web')
        if args.botnet: scenarios_to_run.append('botnet')
        if args.u2r: scenarios_to_run.append('u2r')
    
    if not scenarios_to_run and not args.benign_only:
        info("*** No attacks selected.\n")
        return
    
    # DEBUG: Print scenario analysis
    print("\n🔍 SCENARIO ANALYSIS:")
    print(f"Scenarios to run: {scenarios_to_run}")
    print(f"Web scenario in list: {'web' in scenarios_to_run}")
    print(f"DDoS scenario in list: {'ddos' in scenarios_to_run}")
    
    # Initial benign period
    info("*** Initial benign period (15 seconds)\n")
    force_label("benign")
    time.sleep(15)
    
    # Run selected scenarios
    for scenario_name in scenarios_to_run:
        print(f"\n🎬 STARTING SCENARIO: {scenario_name}")
        
        # Set label for this scenario
        print(f"🏷️  Setting label to: {scenario_name}")
        force_label(scenario_name)
        time.sleep(3)
        
        # Verify label is set correctly
        with open('/tmp/current_label', 'r') as f:
            current_label = f.read().strip()
            print(f"🏷️  Current label: '{current_label}'")
            
            if current_label != scenario_name:
                print(f"🚨 LABEL ERROR: Expected '{scenario_name}', got '{current_label}'")
                force_label(scenario_name)
        
        info(f"*** STARTING {scenario_name} attack\n")
        
        # Execute the scenario
        print(f"⚡ Executing {scenario_name} attack functions")
        all_scenarios[scenario_name]()
        
        # Keep label for capture
        print(f"⏳ Keeping {scenario_name} label for capture")
        time.sleep(3)
        
        info(f"*** COMPLETED {scenario_name} attack\n")
        
        # Clear label
        print("🔄 Clearing label to 'benign'")
        force_label("benign")
        time.sleep(5)
    
    # Final benign period
    info("*** Final benign period (15 seconds)\n")
    force_label("benign")
    time.sleep(15)
    clear_label()

def main():
    parser = argparse.ArgumentParser(description="Selective attack orchestrator")
    parser.add_argument("--controller-ip", default='127.0.0.1')
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--dwell", type=int, default=10, help="Seconds per attack")
    parser.add_argument("--cli", action="store_true", help="Enter CLI after")
    
    # Individual attack flags
    parser.add_argument("--dos", action="store_true", help="Run DoS attacks")
    parser.add_argument("--ddos", action="store_true", help="Run DDoS attacks") 
    parser.add_argument("--probe", action="store_true", help="Run probing attacks")
    parser.add_argument("--bfa", action="store_true", help="Run brute force attacks")
    parser.add_argument("--web", action="store_true", help="Run web attacks")
    parser.add_argument("--botnet", action="store_true", help="Run botnet attacks")
    parser.add_argument("--u2r", action="store_true", help="Run U2R attacks")
    
    # Group flags
    parser.add_argument("--all", action="store_true", help="Run ALL attacks")
    parser.add_argument("--benign-only", action="store_true", help="Only benign traffic")
    
    args = parser.parse_args()

    # DEBUG: Print all arguments
    print("🔍 COMMAND LINE ARGUMENTS:")
    print(f"  --web: {args.web}")
    print(f"  --ddos: {args.ddos}")
    print(f"  --all: {args.all}")
    print(f"  --benign-only: {args.benign_only}")

    setLogLevel('info')
    clear_label()

    net = build_net(args.controller_ip, args.controller_port)
    try:
        net.start()
        start_benign_services(net)
        start_benign_traffic(net)
        time.sleep(5)

        run_selective_scenarios(net, args)

        time.sleep(5)
        copy_csv_if_exists()

        if args.cli:
            CLI(net)
    finally:
        net.stop()

if __name__ == "__main__":
    main()