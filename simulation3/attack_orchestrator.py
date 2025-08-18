#!/usr/bin/env python3
"""
attack_orchestrator.py

Enhanced Mininet topology + traffic generator + attack runner.
"""
import os, time, subprocess, random, argparse
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI

LABEL_FILE = '/tmp/current_label'
CSV_IN = '/tmp/insdn_features.csv'

def sh(host, cmd):
    return host.cmd(f"bash -c \"{cmd}\"")

def write_label(v): open(LABEL_FILE,'w').write(str(v))
def clear_label(): write_label(0)

def _dpid_for(i):
    return format(i, '016x')

def build_net(controller_ip='127.0.0.1', controller_port=6653):
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True, autoStaticArp=True)
    c0 = RemoteController('c0', ip=controller_ip, port=controller_port)
    net.addController(c0)

    # Core/spine/leaf topology with canonical switch names
    s1 = net.addSwitch('s1', protocols='OpenFlow13', dpid=_dpid_for(1))  # core
    s2 = net.addSwitch('s2', protocols='OpenFlow13', dpid=_dpid_for(2))  # spine
    s3 = net.addSwitch('s3', protocols='OpenFlow13', dpid=_dpid_for(3))  # leaf1
    s4 = net.addSwitch('s4', protocols='OpenFlow13', dpid=_dpid_for(4))  # leaf2
    s5 = net.addSwitch('s5', protocols='OpenFlow13', dpid=_dpid_for(5))  # leaf3

    # Hosts
    h1 = net.addHost('h1', ip='10.0.1.1/24')   # client
    h2 = net.addHost('h2', ip='10.0.1.2/24')   # client
    h3 = net.addHost('h3', ip='10.0.2.3/24')   # server
    h4 = net.addHost('h4', ip='10.0.2.4/24')   # server (iperf)
    h5 = net.addHost('h5', ip='10.0.3.5/24')   # mixed
    h6 = net.addHost('h6', ip='10.0.3.6/24')   # attacker/mixed

    # Links
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

    # Ensure simple routing on hosts
    for h in (h1,h2,h3,h4,h5,h6):
        h.setDefaultRoute('dev ' + h.defaultIntf().name)

    # Start benign servers
    sh(h3, 'nohup python3 -m http.server 80 >/tmp/h3_http.log 2>&1 &')
    sh(h4, 'nohup python3 -m http.server 8080 >/tmp/h4_http.log 2>&1 &')
    sh(h3, 'nohup socat TCP-LISTEN:2222,reuseaddr,fork EXEC:/bin/cat >/tmp/h3_echo.log 2>&1 &')
    sh(h4, 'nohup iperf3 -s >/tmp/h4_iperf3.log 2>&1 &')
    sh(h5, 'nohup bash -c \'while true; do nc -u -l -p 5353 -k -e /bin/cat; done\' >/tmp/h5_dns.log 2>&1 &')

    info("*** Fabric and services ready\n")
    return net

# ---------------- benign ----------------
def start_benign(net):
    h1,h2,h3,h4,h5,h6 = (net.get(n) for n in ('h1','h2','h3','h4','h5','h6'))

    # Web client loops
    sh(h1, 'nohup bash -c \'while true; do curl -m 2 -s http://10.0.2.3/ >/dev/null; sleep 0.2; done\' >/tmp/h1_curl.log 2>&1 &')
    sh(h2, 'nohup bash -c \'while true; do curl -m 2 -s http://10.0.2.3/ >/dev/null; sleep 0.4; done\' >/tmp/h2_curl.log 2>&1 &')
    sh(h6, 'nohup bash -c \'while true; do curl -m 2 -s http://10.0.2.4:8080/ >/dev/null; sleep 0.6; done\' >/tmp/h6_curl.log 2>&1 &')

    # iperf bursts
    sh(h1, 'nohup bash -c \'while true; do iperf3 -c 10.0.2.4 -t 5 -b 20M >/tmp/h1_iperf.log 2>&1; sleep 15; done\' &')
    sh(h2, 'nohup bash -c \'while true; do iperf3 -c 10.0.2.4 -t 5 -b 10M >/tmp/h2_iperf.log 2>&1; sleep 20; done\' &')

    # UDP small queries
    sh(h1, 'nohup bash -c \'while true; do echo -n "q$(shuf -i1-100000 -n1)" | nc -u -w 1 10.0.3.5 5353 >/dev/null 2>&1; sleep 0.5; done\' >/tmp/h1_dns.log 2>&1 &')

    # ICMP pings
    sh(h1, 'nohup ping -i 1 10.0.2.4 >/tmp/h1_ping.log 2>&1 &')
    sh(h2, 'nohup ping -i 1.3 10.0.2.3 >/tmp/h2_ping.log 2>&1 &')

    info("*** Benign background traffic started\n")

def stop_benign(net):
    for h in net.hosts:
        sh(h, "pkill -f 'http.server' || true")
        sh(h, "pkill -f 'iperf3 -s' || true")
        sh(h, "pkill -f 'iperf3 -c' || true")
        sh(h, "pkill -f 'nc -u -l -p 5353' || true")
        sh(h, "pkill -f 'curl -m 2' || true")
        sh(h, "pkill -f 'ping -i' || true")
        sh(h, "pkill -f 'socat TCP-LISTEN:2222' || true")

# ---------------- attacks ----------------
def syn_flood(attacker, target, dur=10):
    sh(attacker, f'timeout {dur} hping3 --flood -S -p 80 --rand-source {target} >/tmp/{attacker.name}_synf.log 2>&1 &')

def udp_flood(attacker, target, dur=10):
    script = f"from scapy.all import *\nfor i in range(1500): send(IP(dst='{target}')/UDP(dport=53)/Raw(b'X'*1200), verbose=False)\n"
    sh(attacker, f'python3 - <<PY\n{script}\nPY\n &')

def icmp_flood(attacker, target, dur=10):
    sh(attacker, f'timeout {dur} hping3 --flood --icmp {target} >/tmp/{attacker.name}_icmp.log 2>&1 &')

def nmap_scan(attacker, target):
    sh(attacker, f'nmap -sS -p 1-1024 {target} -oN /tmp/{attacker.name}_scan.txt &')

def ssh_bruteforce_sim(attacker, target, tries=300):
    sh(attacker, f'bash -c "for i in $(seq 1 {tries}); do timeout 1 bash -c \\"</dev/tcp/{target}/2222\\" 2>/dev/null || true; sleep 0.05; done" &')

def botnet_sim(attackers, target, dur=15):
    for a in attackers:
        sh(a, f'python3 - <<PY\nfrom scapy.all import *\nfor i in range(1200): send(IP(dst=\"{target}\")/UDP(dport=80)/Raw(b\"B\"*200), verbose=False)\nPY\n &')

def run_scenarios(net, with_attacks=True, dwell=14):
    h1=net.get('h1'); h3=net.get('h3'); h4=net.get('h4'); h5=net.get('h5'); h6=net.get('h6')
    target='10.0.2.3' # h3

    if not with_attacks:
        info("*** Skipping attacks (benign only)\n")
        return

    write_label(1); syn_flood(h1, target, dur=dwell-2); time.sleep(dwell); clear_label()
    write_label(2); udp_flood(h3, target, dur=dwell-2); time.sleep(dwell); clear_label()
    write_label(3); icmp_flood(h4, target, dur=dwell-2); time.sleep(dwell); clear_label()
    write_label(4); nmap_scan(h5, target); time.sleep(dwell); clear_label()
    write_label(5); ssh_bruteforce_sim(h6, '10.0.2.3', tries=500); time.sleep(dwell); clear_label()
    write_label(6); botnet_sim([h1,h3,h4], target, dur=dwell-2); time.sleep(dwell); clear_label()

def collect_csv():
    time.sleep(3)
    if os.path.exists(CSV_IN):
        dst=f"./collected_{int(time.time())}.csv"
        subprocess.run(['cp', CSV_IN, dst])
        info(f"*** CSV copied -> {dst}\n")
    else:
        info(f"*** No CSV found at {CSV_IN}\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--controller-ip", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--benign", action="store_true")
    parser.add_argument("--attacks", action="store_true")
    parser.add_argument("--dwell", type=int, default=14)
    parser.add_argument("--cli", action="store_true")
    args = parser.parse_args()

    setLogLevel('info')
    clear_label()
    net = build_net(args.controller_ip, args.controller_port)
    try:
        if args.benign:
            start_benign(net)
            time.sleep(6)
        if args.attacks:
            run_scenarios(net, with_attacks=True, dwell=args.dwell)
        time.sleep(4)
        collect_csv()
        if args.cli:
            CLI(net)
    finally:
        clear_label()
        stop_benign(net)
        net.stop()

if __name__ == '__main__':
    main()
