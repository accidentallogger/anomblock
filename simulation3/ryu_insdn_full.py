#!/usr/bin/env python3
"""
ryu_insdn_full.py (updated)

- Simple learning switch
- PacketIn-based per-packet capture
- Bidirectional 5-tuple flow buckets
- Computes an InSDN/CICFlowMeter-style 84+ feature set (exactly your HEADERS order)
- Label injection via /tmp/current_label
- Writes rows to /tmp/insdn_features.csv with immediate flush

Notes:
- PacketIn heavy workloads can overwhelm the controller: consider sampling/mirroring for scale.
- "First packet defines forward direction" convention is used.
"""

import os
import time
import csv
import threading
import statistics
from collections import defaultdict, namedtuple, Counter

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4

# ----------------- CONFIG -----------------
CSV_OUT = '/tmp/insdn_features.csv'
PACKET_CACHE_TTL = 4.0            # seconds of inactivity before a flow is flushed
POLL_INTERVAL = 1.0               # OFPFlowStatsRequest interval (kept for future port-level stats)
INITIAL_WINDOW_PKTS = 10
SUBFLOW_GAP = 1.0                 # seconds to split active/idle windows
BULK_PKT_SIZE = 1000              # bytes threshold for bulk metrics
BULK_IAT = 1.0                    # seconds between packets in a bulk
SAMPLE_EVERY_N = 1                # Packet sampling (1 = no sampling)
# ------------------------------------------

PacketRec = namedtuple('PacketRec', [
    'ts', 'length', 'dir', 'tcp_flags', 'eth_hdr_len', 'ip_hdr_len', 'l4_hdr_len'
])

def safe_mean(xs): return statistics.mean(xs) if xs else 0.0
def safe_std(xs): return statistics.pstdev(xs) if len(xs) > 1 else 0.0
def safe_var(xs): return statistics.pvariance(xs) if len(xs) > 1 else 0.0

def read_label_file():
    try:
        with open('/tmp/current_label', 'r') as fh:
            v = fh.read().strip()
            return int(v) if v else 0
    except Exception:
        return 0

# ----------------- HEADERS (84+ InSDN-like) -----------------
HEADERS = [
    # IDs/meta
    "FlowID","SrcIP","SrcPort","DstIP","DstPort","Protocol","StartTime",
    # header lengths
    "Fwd_Header_Len","Bwd_Header_Len",
    # packet-level counts & byte sums
    "Tot_Fwd_Pkts","Tot_Bwd_Pkts","Tot_Fwd_Bytes","Tot_Bwd_Bytes",
    # pkt-len stats forward (min,mean,max,std)
    "Fwd_PktLen_Min","Fwd_PktLen_Mean","Fwd_PktLen_Max","Fwd_PktLen_Std",
    # pkt-len stats backward
    "Bwd_PktLen_Min","Bwd_PktLen_Mean","Bwd_PktLen_Max","Bwd_PktLen_Std",
    # aggregated pkt-len
    "PktLen_Min","PktLen_Mean","PktLen_Max","PktLen_Var","PktLen_Std",
    # duration, IATs
    "Flow_Duration_s",
    "Flow_IAT_Min","Flow_IAT_Mean","Flow_IAT_Max","Flow_IAT_Std",
    "Fwd_IAT_Tot","Fwd_IAT_Min","Fwd_IAT_Mean","Fwd_IAT_Max","Fwd_IAT_Std",
    "Bwd_IAT_Tot","Bwd_IAT_Min","Bwd_IAT_Mean","Bwd_IAT_Max","Bwd_IAT_Std",
    # active/idle
    "Active_Min","Active_Mean","Active_Max","Active_Std",
    "Idle_Min","Idle_Mean","Idle_Max","Idle_Std",
    # TCP flags (directional and totals)
    "Fwd_PSH","Bwd_PSH","Fwd_URG","Bwd_URG",
    "FIN_Count","SYN_Count","RST_Count","PSH_Count","ACK_Count","URG_Count","CWR_Count","ECE_Count",
    # flow-level behaviour
    "DownUp_Ratio","Fwd_Seg_Avg","Bwd_Seg_Avg",
    # bulk metrics
    "Fwd_Bulk_Byts_Avg","Fwd_Bulk_Pkts_Avg","Fwd_Bulk_Rate_Avg",
    "Bwd_Bulk_Byts_Avg","Bwd_Bulk_Pkts_Avg","Bwd_Bulk_Rate_Avg",
    # init windows
    "Init_Fwd_Win_Bytes","Init_Bwd_Win_Bytes",
    # forward act data pkts, seg size min
    "Fwd_Act_Data_Pkts","Fwd_Seg_Size_Min",
    # rates
    "Flow_Bytes_per_s","Flow_Pkts_per_s","Fwd_Pkts_per_s","Bwd_Pkts_per_s",
    # subflow averages
    "Subflow_Fwd_Pkts_Avg","Subflow_Fwd_Bytes_Avg","Subflow_Bwd_Pkts_Avg","Subflow_Bwd_Bytes_Avg",
    # additional features
    "TTL_Avg","TTL_Min","TTL_Max","Unique_Src_Ports","Unique_Dst_Ports",
    "Packet_Size_Mode","Packet_Size_Median","First_Payload_Bytes",
    # label
    "Label"
]

# ----------------- FlowBucket -----------------
class FlowBucket:
    def __init__(self):
        self.packets = []             # [PacketRec]
        self.first_ts = None
        self.last_ts = None
        self.total_bytes = 0
        self.total_pkts = 0
        self.forward_ip = None
        # header accumulators
        self.fwd_header_bytes = 0; self.fwd_hdr_cnt = 0
        self.bwd_header_bytes = 0; self.bwd_hdr_cnt = 0
        # TTL values
        self.ttl_vals = []
        # unique port tracking
        self.src_ports = set(); self.dst_ports = set()
        # packet sizes for median/mode
        self.size_counter = Counter()

# ----------------- RYU APP -----------------
class InSDNFullApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(InSDNFullApp, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.flows = defaultdict(FlowBucket)
        self.lock = threading.Lock()
        self.mac_to_port = defaultdict(dict)

        # Prepare CSV
        os.makedirs(os.path.dirname(CSV_OUT) or '/tmp', exist_ok=True)
        write_header = not os.path.exists(CSV_OUT)
        self.csv_fh = open(CSV_OUT, 'a', newline='')
        self.csv_writer = csv.writer(self.csv_fh)
        if write_header:
            self.csv_writer.writerow(HEADERS)
            self.csv_fh.flush()

        # Background tasks
        self.poller = hub.spawn(self._poller)
        self.gc = hub.spawn(self._gc_loop)
        self.logger.info("InSDNFullApp started, writing %s", CSV_OUT)

    # -------- datapath lifecycle --------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.logger.info("Registered datapath dpid=%s", dp.id)
        else:
            if dp.id in self.datapaths:
                del self.datapaths[dp.id]
                self.logger.info("Unregistered datapath dpid=%s", dp.id)

    # -------- install table-miss --------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)
        dp.send_msg(mod)
        self.logger.info("Installed table-miss on dpid=%s", dp.id)

    # -------- PacketIn: learning switch + capture --------
    _pkt_counter = 0

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match.get('in_port')

        # Learning switch
        data = msg.data
        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return
        dst = eth.dst; src = eth.src
        dpid = dp.id

        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofp.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath=dp, priority=1, match=match,
                instructions=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)],
                buffer_id=msg.buffer_id
            )
            dp.send_msg(mod)

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data if msg.buffer_id == ofp.OFPCML_NO_BUFFER or msg.buffer_id == ofp.OFP_NO_BUFFER else None
        )
        dp.send_msg(out)

        # Sampling if requested
        self._pkt_counter += 1
        if SAMPLE_EVERY_N > 1 and (self._pkt_counter % SAMPLE_EVERY_N):
            return

        # ---- Feature capture (IPv4 only) ----
        ts = time.time()
        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4 is None:
            return

        proto = ip4.proto
        src_ip = ip4.src; dst_ip = ip4.dst

        # Header lengths (safe parsing)
        eth_hdr_len = 14
        ip_hdr_len = 20
        try:
            if len(data) > eth_hdr_len:
                ip_hdr_len = (data[eth_hdr_len] & 0x0F) * 4 or 20
        except Exception:
            ip_hdr_len = 20

        l4_offset = eth_hdr_len + ip_hdr_len
        l4_hdr_len = 0
        src_port = 0; dst_port = 0; tcp_flags = 0

        try:
            if proto == 6 and len(data) >= l4_offset + 20:  # TCP
                src_port = (data[l4_offset] << 8) | data[l4_offset+1]
                dst_port = (data[l4_offset+2] << 8) | data[l4_offset+3]
                tcp_flags = data[l4_offset+13]
                l4_hdr_len = ((data[l4_offset+12] >> 4) & 0x0F) * 4 or 20
            elif proto == 17 and len(data) >= l4_offset + 8:  # UDP
                src_port = (data[l4_offset] << 8) | data[l4_offset+1]
                dst_port = (data[l4_offset+2] << 8) | data[l4_offset+3]
                l4_hdr_len = 8
            else:
                l4_hdr_len = 0
        except Exception:
            # leave defaults
            pass

        key = (src_ip, dst_ip, src_port, dst_port, proto)
        plen = len(data)

        with self.lock:
            bucket = self.flows[key]
            if bucket.first_ts is None:
                bucket.first_ts = ts
                bucket.forward_ip = src_ip
            bucket.last_ts = ts

            direction = 'fwd' if src_ip == bucket.forward_ip else 'bwd'
            rec = PacketRec(
                ts=ts, length=plen, dir=direction, tcp_flags=tcp_flags,
                eth_hdr_len=eth_hdr_len, ip_hdr_len=ip_hdr_len, l4_hdr_len=l4_hdr_len
            )
            bucket.packets.append(rec)
            bucket.total_pkts += 1
            bucket.total_bytes += plen

            if direction == 'fwd':
                bucket.fwd_header_bytes += (eth_hdr_len + ip_hdr_len + l4_hdr_len)
                bucket.fwd_hdr_cnt += 1
            else:
                bucket.bwd_header_bytes += (eth_hdr_len + ip_hdr_len + l4_hdr_len)
                bucket.bwd_hdr_cnt += 1

            # TTL
            try:
                bucket.ttl_vals.append(ip4.ttl)
            except Exception:
                pass

            # ports (for uniqueness stats)
            bucket.src_ports.add(src_port)
            bucket.dst_ports.add(dst_port)

            # size histogram
            bucket.size_counter.update([plen])

    # -------- poller kept for future extensions --------
    def _poller(self):
        while True:
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                req = parser.OFPFlowStatsRequest(dp)
                dp.send_msg(req)
            hub.sleep(POLL_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply(self, ev):
        # Not used for dataset generation (PacketIn is our source).
        pass

    # -------- GC: finalize idle flows to CSV --------
    def _gc_loop(self):
        while True:
            now = time.time()
            to_flush = []
            with self.lock:
                for key, bucket in list(self.flows.items()):
                    if bucket.last_ts and (now - bucket.last_ts) > PACKET_CACHE_TTL:
                        to_flush.append((key, bucket))
                        del self.flows[key]
            for key, bucket in to_flush:
                try:
                    row = self._compute_features_row(key, bucket)
                    self._write_row(row)
                    self.logger.info(
                        "WROTE flow %s label=%s pkts=%d bytes=%d",
                        key, row[-1], bucket.total_pkts, bucket.total_bytes
                    )
                except Exception as e:
                    self.logger.exception("Error finalizing flow %s: %s", key, e)
            hub.sleep(0.5)

    def _write_row(self, row):
        # Ensure exact alignment with HEADERS (pad/trim defensively)
        if len(row) < len(HEADERS):
            row = row + [0] * (len(HEADERS) - len(row))
        elif len(row) > len(HEADERS):
            row = row[:len(HEADERS)]
        self.csv_writer.writerow(row)
        self.csv_fh.flush()

    # -------- feature computations --------
    def _compute_features_row(self, key, bucket: FlowBucket):
        (src_ip, dst_ip, src_port, dst_port, proto) = key
        start_ts = bucket.first_ts or 0.0
        duration = (bucket.last_ts - bucket.first_ts) if (bucket.first_ts and bucket.last_ts) else 0.0

        # Split directions
        fwd = [p for p in bucket.packets if p.dir == 'fwd']
        bwd = [p for p in bucket.packets if p.dir == 'bwd']

        # Header length averages
        fwd_hdr_len = int(bucket.fwd_header_bytes / bucket.fwd_hdr_cnt) if bucket.fwd_hdr_cnt else 0
        bwd_hdr_len = int(bucket.bwd_header_bytes / bucket.bwd_hdr_cnt) if bucket.bwd_hdr_cnt else 0

        # Counts & bytes
        tot_fwd_pkts = len(fwd); tot_bwd_pkts = len(bwd)
        tot_fwd_bytes = sum(p.length for p in fwd); tot_bwd_bytes = sum(p.length for p in bwd)

        # Packet length stats
        fwd_lens = [p.length for p in fwd]
        bwd_lens = [p.length for p in bwd]
        all_lens = [p.length for p in bucket.packets]

        F_fwd_min = min(fwd_lens) if fwd_lens else 0
        F_fwd_mean = safe_mean(fwd_lens)
        F_fwd_max = max(fwd_lens) if fwd_lens else 0
        F_fwd_std = safe_std(fwd_lens)

        B_bwd_min = min(bwd_lens) if bwd_lens else 0
        B_bwd_mean = safe_mean(bwd_lens)
        B_bwd_max = max(bwd_lens) if bwd_lens else 0
        B_bwd_std = safe_std(bwd_lens)

        P_min = min(all_lens) if all_lens else 0
        P_mean = safe_mean(all_lens)
        P_max = max(all_lens) if all_lens else 0
        P_var = safe_var(all_lens)
        P_std = safe_std(all_lens)
        P_median = statistics.median(all_lens) if all_lens else 0
        P_mode = bucket.size_counter.most_common(1)[0][0] if bucket.size_counter else 0

        # IATs
        def iat_series(pkts):
            if len(pkts) < 2: return []
            times = [p.ts for p in sorted(pkts, key=lambda x: x.ts)]
            return [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]

        flow_iats = iat_series(bucket.packets)
        Flow_IAT_Min = min(flow_iats) if flow_iats else 0.0
        Flow_IAT_Mean = safe_mean(flow_iats) if flow_iats else 0.0
        Flow_IAT_Max = max(flow_iats) if flow_iats else 0.0
        Flow_IAT_Std  = safe_std(flow_iats)  if len(flow_iats) > 1 else 0.0

        fwd_iats = iat_series(fwd)
        bwd_iats = iat_series(bwd)
        Fwd_IAT_Tot = sum(fwd_iats) if fwd_iats else 0.0
        Fwd_IAT_Min = min(fwd_iats) if fwd_iats else 0.0
        Fwd_IAT_Mean = safe_mean(fwd_iats) if fwd_iats else 0.0
        Fwd_IAT_Max = max(fwd_iats) if fwd_iats else 0.0
        Fwd_IAT_Std = safe_std(fwd_iats) if len(fwd_iats) > 1 else 0.0

        Bwd_IAT_Tot = sum(bwd_iats) if bwd_iats else 0.0
        Bwd_IAT_Min = min(bwd_iats) if bwd_iats else 0.0
        Bwd_IAT_Mean = safe_mean(bwd_iats) if bwd_iats else 0.0
        Bwd_IAT_Max = max(bwd_iats) if bwd_iats else 0.0
        Bwd_IAT_Std = safe_std(bwd_iats) if len(bwd_iats) > 1 else 0.0

        # Active/Idle stats
        def active_idle(pkts):
            if not pkts:
                return (0,0,0,0, 0,0,0,0)
            times = sorted([p.ts for p in pkts])
            intervals = []
            s = times[0]; last = times[0]
            for t in times[1:]:
                if t - last <= SUBFLOW_GAP:
                    last = t
                else:
                    intervals.append((s, last)); s = t; last = t
            intervals.append((s, last))
            act_durs = [e - s for s, e in intervals]
            idles = [intervals[i+1][0] - intervals[i][1] for i in range(len(intervals)-1)] if len(intervals) > 1 else []
            return (
                min(act_durs) if act_durs else 0.0,
                safe_mean(act_durs) if act_durs else 0.0,
                max(act_durs) if act_durs else 0.0,
                safe_std(act_durs) if len(act_durs) > 1 else 0.0,
                min(idles) if idles else 0.0,
                safe_mean(idles) if idles else 0.0,
                max(idles) if idles else 0.0,
                safe_std(idles) if len(idles) > 1 else 0.0
            )

        A_min, A_mean, A_max, A_std, I_min, I_mean, I_max, I_std = active_idle(bucket.packets)

        # Flags
        def count_flags(pkts):
            SYN=ACK=FIN=RST=PSH=URG=CWR=ECE=0
            for p in pkts:
                f = p.tcp_flags
                if f & 0x02: SYN += 1
                if f & 0x10: ACK += 1
                if f & 0x01: FIN += 1
                if f & 0x04: RST += 1
                if f & 0x08: PSH += 1
                if f & 0x20: URG += 1
                if f & 0x80: CWR += 1
                if f & 0x40: ECE += 1
            return dict(SYN=SYN, ACK=ACK, FIN=FIN, RST=RST, PSH=PSH, URG=URG, CWR=CWR, ECE=ECE)

        fwd_flags = count_flags(fwd)
        bwd_flags = count_flags(bwd)
        tot_flags = count_flags(bucket.packets)

        # Flow behaviour
        down_up_ratio = (tot_bwd_bytes / tot_fwd_bytes) if tot_fwd_bytes > 0 else (float(tot_bwd_bytes) if tot_bwd_bytes > 0 else 0.0)
        fwd_seg_avg = safe_mean(fwd_lens) if fwd_lens else 0.0
        bwd_seg_avg = safe_mean(bwd_lens) if bwd_lens else 0.0

        # Bulk metrics
        def compute_bulk(pkts):
            if not pkts: return (0.0, 0.0, 0.0)
            bulks = []; cur = []
            for p in sorted(pkts, key=lambda x: x.ts):
                if p.length >= BULK_PKT_SIZE:
                    if not cur:
                        cur = [p]
                    else:
                        if p.ts - cur[-1].ts <= BULK_IAT:
                            cur.append(p)
                        else:
                            bulks.append(cur); cur = [p]
                else:
                    if cur:
                        bulks.append(cur); cur = []
            if cur: bulks.append(cur)
            if not bulks: return (0.0, 0.0, 0.0)
            bytes_per_bulk = [sum(pp.length for pp in b) for b in bulks]
            pkts_per_bulk = [len(b) for b in bulks]
            rates = []
            for b in bulks:
                d = b[-1].ts - b[0].ts
                d = d if d > 0 else 1e-6
                rates.append(sum(pp.length for pp in b) / d)
            return (safe_mean(bytes_per_bulk), safe_mean(pkts_per_bulk), safe_mean(rates))

        Fwd_Bulk_Byts_Avg, Fwd_Bulk_Pkts_Avg, Fwd_Bulk_Rate_Avg = compute_bulk(fwd)
        Bwd_Bulk_Byts_Avg, Bwd_Bulk_Pkts_Avg, Bwd_Bulk_Rate_Avg = compute_bulk(bwd)

        # Init windows (sum of first N packet sizes)
        init_fwd = sum(p.length for p in sorted(fwd, key=lambda x: x.ts)[:INITIAL_WINDOW_PKTS])
        init_bwd = sum(p.length for p in sorted(bwd, key=lambda x: x.ts)[:INITIAL_WINDOW_PKTS])

        # Forward active data packets (payload present)
        fwd_act_data_pkts = sum(
            1 for p in fwd if p.length > (p.eth_hdr_len + p.ip_hdr_len + p.l4_hdr_len)
        )
        fwd_seg_min = min(fwd_lens) if fwd_lens else 0

        # Rates (guard divide by zero)
        flow_bps = (bucket.total_bytes / duration) if duration > 0 else 0.0
        flow_pps = (bucket.total_pkts / duration) if duration > 0 else 0.0
        fwd_pps = (tot_fwd_pkts / duration) if duration > 0 else 0.0
        bwd_pps = (tot_bwd_pkts / duration) if duration > 0 else 0.0

        # Subflow averages
        def subflow_avg(pkts):
            if not pkts: return (0.0, 0.0)
            t_sorted = sorted(pkts, key=lambda x: x.ts)
            subflows = []; cur = [t_sorted[0]]
            for p in t_sorted[1:]:
                if p.ts - cur[-1].ts <= SUBFLOW_GAP:
                    cur.append(p)
                else:
                    subflows.append(cur); cur = [p]
            subflows.append(cur)
            return (
                safe_mean([len(s) for s in subflows]),
                safe_mean([sum(x.length for x in s) for s in subflows])
            )

        sf_fwd_pkts_avg, sf_fwd_bytes_avg = subflow_avg(fwd)
        sf_bwd_pkts_avg, sf_bwd_bytes_avg = subflow_avg(bwd)

        # TTL & unique ports
        ttl_vals = bucket.ttl_vals
        ttl_avg = safe_mean(ttl_vals) if ttl_vals else 0
        ttl_min = min(ttl_vals) if ttl_vals else 0
        ttl_max = max(ttl_vals) if ttl_vals else 0
        uniq_src_ports = len(bucket.src_ports)
        uniq_dst_ports = len(bucket.dst_ports)

        # First payload bytes
        first_payload = 0
        if bucket.packets:
            p0 = bucket.packets[0]
            first_payload = max(0, p0.length - (p0.eth_hdr_len + p0.ip_hdr_len + p0.l4_hdr_len))

        # Label
        label = read_label_file()

        # Assemble row
        row = [
            f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}-{int(start_ts)}",
            src_ip, src_port, dst_ip, dst_port, proto, start_ts,
            fwd_hdr_len, bwd_hdr_len,
            tot_fwd_pkts, tot_bwd_pkts, tot_fwd_bytes, tot_bwd_bytes,
            F_fwd_min, F_fwd_mean, F_fwd_max, F_fwd_std,
            B_bwd_min, B_bwd_mean, B_bwd_max, B_bwd_std,
            P_min, P_mean, P_max, P_var, P_std,
            duration,
            Flow_IAT_Min, Flow_IAT_Mean, Flow_IAT_Max, Flow_IAT_Std,
            Fwd_IAT_Tot, Fwd_IAT_Min, Fwd_IAT_Mean, Fwd_IAT_Max, Fwd_IAT_Std,
            Bwd_IAT_Tot, Bwd_IAT_Min, Bwd_IAT_Mean, Bwd_IAT_Max, Bwd_IAT_Std,
            A_min, A_mean, A_max, A_std,
            I_min, I_mean, I_max, I_std,
            # directional PSH/URG
            fwd_flags.get('PSH', 0), bwd_flags.get('PSH', 0),
            fwd_flags.get('URG', 0), bwd_flags.get('URG', 0),
            # total flags
            tot_flags.get('FIN', 0), tot_flags.get('SYN', 0), tot_flags.get('RST', 0),
            tot_flags.get('PSH', 0), tot_flags.get('ACK', 0), tot_flags.get('URG', 0),
            tot_flags.get('CWR', 0), tot_flags.get('ECE', 0),
            # behaviours
            down_up_ratio, fwd_seg_avg, bwd_seg_avg,
            # bulk
            Fwd_Bulk_Byts_Avg, Fwd_Bulk_Pkts_Avg, Fwd_Bulk_Rate_Avg,
            Bwd_Bulk_Byts_Avg, Bwd_Bulk_Pkts_Avg, Bwd_Bulk_Rate_Avg,
            # init windows
            init_fwd, init_bwd,
            # fwd active data & min seg
            fwd_act_data_pkts, fwd_seg_min,
            # rates
            flow_bps, flow_pps, fwd_pps, bwd_pps,
            # subflows
            sf_fwd_pkts_avg, sf_fwd_bytes_avg, sf_bwd_pkts_avg, sf_bwd_bytes_avg,
            # extras
            ttl_avg, ttl_min, ttl_max, uniq_src_ports, uniq_dst_ports,
            P_mode, P_median, first_payload,
            # label
            label
        ]

        # Final safety check
        if len(row) != len(HEADERS):
            self.logger.warning("Header length mismatch: headers=%d row=%d", len(HEADERS), len(row))
        return row

    # -------- cleanup --------
    def close(self):
        try:
            self.csv_fh.close()
        except Exception:
            pass
