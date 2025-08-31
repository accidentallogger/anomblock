#!/usr/bin/env python3
"""
ryu_insdn_full.py

Complete Ryu controller for InSDN feature extraction without API.
"""

import os
import time
import csv
import json
import threading
import statistics
from collections import defaultdict, namedtuple, Counter
import socket
import struct

# Ryu imports
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp

# ----------------- CONFIG -----------------
CSV_OUT = '/tmp/insdn_features.csv'
PACKET_CACHE_TTL = 4.0
POLL_INTERVAL = 1.0
INITIAL_WINDOW_PKTS = 10
SUBFLOW_GAP = 1.0
BULK_PKT_SIZE = 1000
BULK_IAT = 1.0
SAMPLE_EVERY_N = 1

HEADERS = [
    "FlowID","SrcIP","SrcPort","DstIP","DstPort","Protocol","StartTime",
    "Fwd_Header_Len","Bwd_Header_Len",
    "Tot_Fwd_Pkts","Tot_Bwd_Pkts","Tot_Fwd_Bytes","Tot_Bwd_Bytes",
    "Fwd_PktLen_Min","Fwd_PktLen_Mean","Fwd_PktLen_Max","Fwd_PktLen_Std",
    "Bwd_PktLen_Min","Bwd_PktLen_Mean","Bwd_PktLen_Max","Bwd_PktLen_Std",
    "PktLen_Min","PktLen_Mean","PktLen_Max","PktLen_Var","PktLen_Std",
    "Flow_Duration_s",
    "Flow_IAT_Min","Flow_IAT_Mean","Flow_IAT_Max","Flow_IAT_Std",
    "Fwd_IAT_Tot","Fwd_IAT_Min","Fwd_IAT_Mean","Fwd_IAT_Max","Fwd_IAT_Std",
    "Bwd_IAT_Tot","Bwd_IAT_Min","Bwd_IAT_Mean","Bwd_IAT_Max","Bwd_IAT_Std",
    "Active_Min","Active_Mean","Active_Max","Active_Std",
    "Idle_Min","Idle_Mean","Idle_Max","Idle_Std",
    "Fwd_PSH","Bwd_PSH","Fwd_URG","Bwd_URG",
    "FIN_Count","SYN_Count","RST_Count","PSH_Count","ACK_Count","URG_Count","CWR_Count","ECE_Count",
    "DownUp_Ratio","Fwd_Seg_Avg","Bwd_Seg_Avg",
    "Fwd_Bulk_Byts_Avg","Fwd_Bulk_Pkts_Avg","Fwd_Bulk_Rate_Avg",
    "Bwd_Bulk_Byts_Avg","Bwd_Bulk_Pkts_Avg","Bwd_Bulk_Rate_Avg",
    "Init_Fwd_Win_Bytes","Init_Bwd_Win_Bytes",
    "Fwd_Act_Data_Pkts","Fwd_Seg_Size_Min",
    "Flow_Bytes_per_s","Flow_Pkts_per_s","Fwd_Pkts_per_s","Bwd_Pkts_per_s",
    "Subflow_Fwd_Pkts_Avg","Subflow_Fwd_Bytes_Avg","Subflow_Bwd_Pkts_Avg","Subflow_Bwd_Bytes_Avg",
    "TTL_Avg","TTL_Min","TTL_Max","Unique_Src_Ports","Unique_Dst_Ports",
    "Packet_Size_Mode","Packet_Size_Median","First_Payload_Bytes",
    "Label"
]

PacketRec = namedtuple('PacketRec', [
    'ts', 'length', 'dir', 'tcp_flags', 'eth_hdr_len', 'ip_hdr_len', 'l4_hdr_len'
])

def safe_mean(xs): return statistics.mean(xs) if xs else 0.0
def safe_std(xs): return statistics.pstdev(xs) if len(xs) > 1 else 0.0
def safe_var(xs): return statistics.pvariance(xs) if len(xs) > 1 else 0.0
def safe_min(xs): return min(xs) if xs else 0.0
def safe_max(xs): return max(xs) if xs else 0.0

def read_label_file():
    try:
        with open('/tmp/current_label', 'r') as fh:
            v = fh.read().strip()
            return v if v else "benign"
    except Exception:
        return "benign"

class FlowBucket:
    def __init__(self):
        self.packets = []
        self.first_ts = None
        self.last_ts = None
        self.total_bytes = 0
        self.total_pkts = 0
        self.forward_ip = None
        self.fwd_header_bytes = 0; self.fwd_hdr_cnt = 0
        self.bwd_header_bytes = 0; self.bwd_hdr_cnt = 0
        self.ttl_vals = []
        self.src_ports = set(); self.dst_ports = set()
        self.size_counter = Counter()

class InSDNFullApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(InSDNFullApp, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.flows = defaultdict(FlowBucket)
        self.lock = threading.Lock()
        self.mac_to_port = defaultdict(dict)

        os.makedirs(os.path.dirname(CSV_OUT) or '/tmp', exist_ok=True)
        write_header = not os.path.exists(CSV_OUT)
        self.csv_fh = open(CSV_OUT, 'a', newline='')
        self.csv_writer = csv.writer(self.csv_fh)
        if write_header:
            self.csv_writer.writerow(HEADERS)
            self.csv_fh.flush()

        self.gc = hub.spawn(self._gc_loop)
        self.logger.info("InSDNFullApp started, writing %s", CSV_OUT)

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

    _pkt_counter = 0

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        in_port = msg.match.get('in_port')

        data = msg.data
        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return
        dst = eth.dst; src = eth.src
        dpid = dp.id

        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, dp.ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != dp.ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath=dp, priority=1, match=match,
                instructions=[parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)],
                buffer_id=msg.buffer_id
            )
            dp.send_msg(mod)

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data if msg.buffer_id == dp.ofproto.OFPCML_NO_BUFFER or msg.buffer_id == dp.ofproto.OFP_NO_BUFFER else None
        )
        dp.send_msg(out)

        self._pkt_counter += 1
        if SAMPLE_EVERY_N > 1 and (self._pkt_counter % SAMPLE_EVERY_N):
            return

        ts = time.time()
        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4 is None:
            return

        proto = ip4.proto
        src_ip = ip4.src; dst_ip = ip4.dst

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
            if proto == 6 and len(data) >= l4_offset + 20:
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                if tcp_pkt:
                    src_port = tcp_pkt.src_port
                    dst_port = tcp_pkt.dst_port
                    tcp_flags = tcp_pkt.bits
                    l4_hdr_len = tcp_pkt.offset * 4
            elif proto == 17 and len(data) >= l4_offset + 8:
                udp_pkt = pkt.get_protocol(udp.udp)
                if udp_pkt:
                    src_port = udp_pkt.src_port
                    dst_port = udp_pkt.ddst_port
                    l4_hdr_len = 8
        except Exception:
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

            try:
                bucket.ttl_vals.append(ip4.ttl)
            except Exception:
                pass

            bucket.src_ports.add(src_port)
            bucket.dst_ports.add(dst_port)
            bucket.size_counter.update([plen])

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
        if len(row) < len(HEADERS):
            row = row + [0] * (len(HEADERS) - len(row))
        elif len(row) > len(HEADERS):
            row = row[:len(HEADERS)]
        try:
            self.csv_writer.writerow(row)
            self.csv_fh.flush()
        except Exception as e:
            self.logger.exception("CSV write failed: %s", e)

    def _compute_features_row(self, key, bucket):
        (src_ip, dst_ip, src_port, dst_port, proto) = key
        pkts = list(bucket.packets)
        if not pkts:
            return [0] * len(HEADERS)

        start_ts = bucket.first_ts or pkts[0].ts
        end_ts = bucket.last_ts or pkts[-1].ts
        duration = max(1e-6, end_ts - start_ts)

        # per-dir lists
        fwd = [p for p in pkts if p.dir == 'fwd']
        bwd = [p for p in pkts if p.dir == 'bwd']
        fwd_lens = [p.length for p in fwd]
        bwd_lens = [p.length for p in bwd]
        all_lens = [p.length for p in pkts]

        # IATs
        def iats(seq):
            if len(seq) < 2:
                return []
            seq_sorted = sorted(seq, key=lambda x: x.ts)
            return [seq_sorted[i].ts - seq_sorted[i-1].ts for i in range(1, len(seq_sorted))]

        all_iats = iats(pkts)
        fwd_iats = iats(fwd)
        bwd_iats = iats(bwd)

        # Active/Idle using SUBFLOW_GAP on overall IATs
        active_periods = []
        idle_gaps = []
        if pkts:
            last_ts = pkts[0].ts
            cur_active_start = last_ts
            for p in sorted(pkts, key=lambda x: x.ts)[1:]:
                gap = p.ts - last_ts
                if gap > SUBFLOW_GAP:
                    active_periods.append(max(0.0, last_ts - cur_active_start))
                    idle_gaps.append(gap)
                    cur_active_start = p.ts
                last_ts = p.ts
            active_periods.append(max(0.0, last_ts - cur_active_start))

        # Flags counts
        FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)
        def flag_count(mask, seq=None):
            seq = seq if seq is not None else pkts
            return sum(1 for p in seq if (p.tcp_flags & mask) != 0)

        fwd_psh = flag_count(PSH, fwd)
        bwd_psh = flag_count(PSH, bwd)
        fwd_urg = flag_count(URG, fwd)
        bwd_urg = flag_count(URG, bwd)

        fin_cnt = flag_count(FIN)
        syn_cnt = flag_count(SYN)
        rst_cnt = flag_count(RST)
        psh_cnt = flag_count(PSH)
        ack_cnt = flag_count(ACK)
        urg_cnt = flag_count(URG)
        cwr_cnt = flag_count(CWR)
        ece_cnt = flag_count(ECE)

        # Simplified bulk stats
        def bulk_stats(seq):
            if not seq:
                return (0.0, 0.0, 0.0)
            return (0.0, 0.0, 0.0)  # Simplified for now

        fwd_bytes = sum(fwd_lens)
        bwd_bytes = sum(bwd_lens)
        tot_bytes = fwd_bytes + bwd_bytes
        tot_pkts = len(pkts)
        tot_fwd = len(fwd)
        tot_bwd = len(bwd)

        fwd_bulk_b, fwd_bulk_p, fwd_bulk_r = bulk_stats(fwd)
        bwd_bulk_b, bwd_bulk_p, bwd_bulk_r = bulk_stats(bwd)

        fwd_seg_avg = safe_mean(fwd_lens)
        bwd_seg_avg = safe_mean(bwd_lens)

        # Subflows
        subflows = []
        if pkts:
            ssorted = sorted(pkts, key=lambda x: x.ts)
            cur = [ssorted[0]]
            for p in ssorted[1:]:
                if (p.ts - cur[-1].ts) > SUBFLOW_GAP:
                    subflows.append(cur)
                    cur = [p]
                else:
                    cur.append(p)
            subflows.append(cur)

        def subflow_dir_avgs(direction):
            if not subflows:
                return (0.0, 0.0)
            pkts_avgs = []
            bytes_avgs = []
            for sf in subflows:
                dseq = [p for p in sf if p.dir == direction]
                pkts_avgs.append(len(dseq))
                bytes_avgs.append(sum(p.length for p in dseq))
            return (safe_mean(pkts_avgs), safe_mean(bytes_avgs))

        sub_fwd_pkts_avg, sub_fwd_bytes_avg = subflow_dir_avgs('fwd')
        sub_bwd_pkts_avg, sub_bwd_bytes_avg = subflow_dir_avgs('bwd')

        # Flow/s rates
        flow_bytes_per_s = tot_bytes / duration
        flow_pkts_per_s = tot_pkts / duration
        fwd_pkts_per_s = tot_fwd / duration
        bwd_pkts_per_s = tot_bwd / duration

        # IAT aggregates
        def iat_stats(iat_list):
            return (
                safe_min(iat_list),
                safe_mean(iat_list),
                safe_max(iat_list),
                safe_std(iat_list),
                sum(iat_list) if iat_list else 0.0
            )
        all_min, all_mean, all_max, all_std, _ = iat_stats(all_iats)
        f_min, f_mean, f_max, f_std, f_tot = iat_stats(fwd_iats)
        b_min, b_mean, b_max, b_std, b_tot = iat_stats(bwd_iats)

        # Packet length stats
        fwd_min = safe_min(fwd_lens); fwd_max = safe_max(fwd_lens)
        fwd_mean = safe_mean(fwd_lens); fwd_std = safe_std(fwd_lens)
        bwd_min = safe_min(bwd_lens); bwd_max = safe_max(bwd_lens)
        bwd_mean = safe_mean(bwd_lens); bwd_std = safe_std(bwd_lens)
        all_min_len = safe_min(all_lens)
        all_max_len = safe_max(all_lens)
        all_mean_len = safe_mean(all_lens)
        all_var_len = safe_var(all_lens)
        all_std_len = (all_var_len ** 0.5) if all_var_len > 0 else 0.0

        # Header lengths
        fwd_header_len_total = bucket.fwd_header_bytes
        bwd_header_len_total = bucket.bwd_header_bytes

        # Down/Up ratio
        down_up_ratio = (tot_bwd / max(1, tot_fwd))

        # Init window bytes (simplified)
        init_fwd_win = 0
        init_bwd_win = 0

        # Fwd active data pkts
        def payload_len(p):
            return max(0, p.length - (p.eth_hdr_len + p.ip_hdr_len + p.l4_hdr_len))
        fwd_act_data_pkts = sum(1 for p in fwd if payload_len(p) > 0)
        fwd_seg_size_min = fwd_min

        # TTL stats
        ttl_avg = safe_mean(bucket.ttl_vals)
        ttl_min = safe_min(bucket.ttl_vals)
        ttl_max = safe_max(bucket.ttl_vals)

        # Unique ports
        uniq_src_ports = len(bucket.src_ports)
        uniq_dst_ports = len(bucket.dst_ports)

        # Mode & Median of packet sizes
        ps_mode = 0
        if bucket.size_counter:
            ps_mode = bucket.size_counter.most_common(1)[0][0]
        ps_median = 0.0
        if all_lens:
            sl = sorted(all_lens)
            n = len(sl)
            mid = n // 2
            if n % 2 == 1:
                ps_median = float(sl[mid])
            else:
                ps_median = (sl[mid-1] + sl[mid]) / 2.0

        # First_Payload_Bytes
        first_payload_bytes = 0
        for p in pkts:
            pl = payload_len(p)
            if pl > 0:
                first_payload_bytes = pl
                break

        # Build FlowID
        fid = f"{src_ip}-{src_port}-{dst_ip}-{dst_port}-{proto}-{int(start_ts*1000)}"

        # Label (string)
        label = read_label_file()

        # Assemble row
        row = [
            fid, src_ip, src_port, dst_ip, dst_port, proto, start_ts,
            fwd_header_len_total, bwd_header_len_total,
            tot_fwd, tot_bwd, fwd_bytes, bwd_bytes,
            fwd_min, fwd_mean, fwd_max, fwd_std,
            bwd_min, bwd_mean, bwd_max, bwd_std,
            all_min_len, all_mean_len, all_max_len, all_var_len, all_std_len,
            duration,
            all_min, all_mean, all_max, all_std,
            f_tot, f_min, f_mean, f_max, f_std,
            b_tot, b_min, b_mean, b_max, b_std,
            safe_min(active_periods), safe_mean(active_periods), safe_max(active_periods), safe_std(active_periods),
            safe_min(idle_gaps), safe_mean(idle_gaps), safe_max(idle_gaps), safe_std(idle_gaps),
            fwd_psh, bwd_psh, fwd_urg, bwd_urg,
            fin_cnt, syn_cnt, rst_cnt, psh_cnt, ack_cnt, urg_cnt, cwr_cnt, ece_cnt,
            down_up_ratio, fwd_seg_avg, bwd_seg_avg,
            fwd_bulk_b, fwd_bulk_p, fwd_bulk_r,
            bwd_bulk_b, bwd_bulk_p, bwd_bulk_r,
            init_fwd_win, init_bwd_win,
            fwd_act_data_pkts, fwd_seg_size_min,
            flow_bytes_per_s, flow_pkts_per_s, fwd_pkts_per_s, bwd_pkts_per_s,
            sub_fwd_pkts_avg, sub_fwd_bytes_avg, sub_bwd_pkts_avg, sub_bwd_bytes_avg,
            ttl_avg, ttl_min, ttl_max, uniq_src_ports, uniq_dst_ports,
            ps_mode, ps_median, first_payload_bytes,
            label
        ]
        return row