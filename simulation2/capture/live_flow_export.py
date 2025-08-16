#!/usr/bin/env python3
"""Captures packets on the Mininet root-namespace (ovs-system) interface,
converts each flow to an 83-column CSV row identical to InSDN fields."""
import subprocess, datetime, pathlib, sys, signal

CSV_DIR = pathlib.Path('flows_out')
CSV_DIR.mkdir(exist_ok=True)

def main():
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    pcap = CSV_DIR / f'capture_{ts}.pcap'
    csv  = CSV_DIR / f'flows_{ts}.csv'
    # 1. dump packets
    tcpdump = subprocess.Popen(['tcpdump','-U','-i','any','-w',str(pcap)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def stop(signum, frame):
        tcpdump.terminate(); tcpdump.wait()
        # 2. convert to CSV with cicflowmeter
        subprocess.run(['cicflowmeter','-f',str(pcap),'-c',str(csv)], check=True)
        print(f'\n[+] CSV ready at {csv}')
        sys.exit(0)
    signal.signal(signal.SIGINT, stop)   # Ctrl-C to finish
    print('[*] Capturing…  press Ctrl-C when finished.')
    signal.pause()

if __name__=='__main__':
    main()
