#!/usr/bin/env python3
"""

ryu-manager ryu_insdn_full.py --verbose

ryu_insdn_full.py

Fixed Ryu controller for InSDN feature extraction with better attack capture.
"""

import os
import time
import csv
import threading
import statistics
from collections import defaultdict, namedtuple
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp

# ----------------- CONFIG -----------------
CSV_OUT = '/tmp/insdn_features.csv'
PACKET_CACHE_TTL = 1.5  # MUCH shorter TTL for short attacks
FLUSH_TIMEOUT = 1.0     # Flush after 1 second of inactivity
MIN_PACKETS_FOR_FLOW = 2  # Require fewer packets

INSDN_FIELDS = [
    'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol',
    'Timestamp', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
    'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
    'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
    'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot',
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
    'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
    'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s',
    'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean',
    'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt',
    'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
    'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg',
    'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg',
    'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
    'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts',
    'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
    'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts',
    'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max',
    'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label'
]

HEADERS = INSDN_FIELDS

PacketRec = namedtuple('PacketRec', [
    'ts', 'length', 'dir', 'tcp_flags', 'eth_hdr_len', 'ip_hdr_len', 'l4_hdr_len'
])

def safe_mean(xs): return statistics.mean(xs) if xs else 0.0
def safe_std(xs): return statistics.pstdev(xs) if len(xs) > 1 else 0.0
def safe_var(xs): return statistics.pvariance(xs) if len(xs) > 1 else 0.0
def safe_min(xs): return min(xs) if xs else 0.0
def safe_max(xs): return max(xs) if xs else 0.0

def read_label_file():
    """Read label with extensive debugging for web attacks"""
    try:
        # Try multiple times to read the label
        for attempt in range(5):
            try:
                with open('/tmp/current_label', 'r') as fh:
                    v = fh.read().strip()
                    current_time = time.time()
                    
                    if "web" in v.lower():
                        print(f"🎯 WEB ATTACK DETECTED: Label '{v}' at time {current_time}")
                        # Force flush any buffered output
                        import sys
                        sys.stdout.flush()
                    
                    if v:  # Only return if we got a non-empty value
                        return v
                    else:
                        print(f"⚠️  Empty label file, attempt {attempt + 1}")
            except Exception as e:
                print(f"❌ Label read error attempt {attempt + 1}: {e}")
                if attempt == 4:  # Last attempt failed
                    print("💥 All label read attempts failed")
            
            time.sleep(0.2)  # Short delay before retry
        
        # If all attempts failed, return benign but log it
        print("🔴 Falling back to 'benign' label")
        return "benign"
        
    except Exception as e:
        print(f"💥 Critical error reading label: {e}")
        return "benign"

class FlowBucket:
    def __init__(self):
        self.packets = []
        self.first_ts = None
        self.last_ts = None
        self.total_bytes = 0
        self.total_pkts = 0
        self.forward_ip = None
        self.fwd_header_bytes = 0
        self.fwd_hdr_cnt = 0
        self.bwd_header_bytes = 0
        self.bwd_hdr_cnt = 0

class InSDNFullApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(InSDNFullApp, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.flows = defaultdict(FlowBucket)
        self.lock = threading.Lock()
        self.mac_to_port = defaultdict(dict)
        
        os.makedirs(os.path.dirname(CSV_OUT) or '/tmp', exist_ok=True)
        
        # Initialize CSV file
        self._init_csv_file()
        
        self.gc = hub.spawn(self._gc_loop)
        self.flow_flusher = hub.spawn(self._flow_flusher_loop)
        self.logger.info("InSDNFullApp started with aggressive flow capture")

    def _init_csv_file(self):
        """Initialize CSV file with proper error handling"""
        try:
            # Close existing file if open
            if hasattr(self, 'csv_fh'):
                try:
                    self.csv_fh.close()
                except:
                    pass
            
            # Open new file
            self.csv_fh = open(CSV_OUT, 'a', newline='', buffering=1)
            self.csv_writer = csv.writer(self.csv_fh)
            
            # Write header if file is empty or doesn't exist
            if not os.path.exists(CSV_OUT) or os.path.getsize(CSV_OUT) == 0:
                self.csv_writer.writerow(HEADERS)
                self.csv_fh.flush()
                os.fsync(self.csv_fh.fileno())
                self.logger.info("📝 Created CSV file with headers")
            else:
                self.logger.info("📝 Using existing CSV file")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize CSV file: {e}")

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
        dst = eth.dst
        src = eth.src
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

        ts = time.time()
        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4 is None:
            return

        proto = ip4.proto
        src_ip = ip4.src
        dst_ip = ip4.dst

        eth_hdr_len = 14
        ip_hdr_len = 20
        try:
            if len(data) > eth_hdr_len:
                ip_hdr_len = (data[eth_hdr_len] & 0x0F) * 4 or 20
        except Exception:
            ip_hdr_len = 20

        l4_offset = eth_hdr_len + ip_hdr_len
        l4_hdr_len = 0
        src_port = 0
        dst_port = 0
        tcp_flags = 0

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
                    dst_port = udp_pkt.dst_port
                    l4_hdr_len = 8
        except Exception:
            pass

        # Use millisecond granularity for flow keys
        millisecond_granularity = int(ts * 1000)
        key = (src_ip, dst_ip, src_port, dst_port, proto, millisecond_granularity // 100)  # Group by 100ms
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

    def _flow_flusher_loop(self):
        """Very aggressive flow flushing to capture short attacks"""
        while True:
            now = time.time()
            to_flush = []
            with self.lock:
                for key, bucket in list(self.flows.items()):
                    # FLUSH ANY flow that's been idle for 0.5 seconds OR has packets
                    if (bucket.last_ts and 
                        ((now - bucket.last_ts > 0.5) or  # Reduced from 1.0 to 0.5
                        (len(bucket.packets) >= 1 and now - bucket.last_ts > 0.2))):
                        to_flush.append((key, bucket))
                        del self.flows[key]
        
            for key, bucket in to_flush:
                try:
                    if bucket.packets:
                        row = self._compute_features_row(key, bucket)
                        if row:  # Only write if we got a valid row
                            self._write_row(row)
                            self.logger.info(
                                "CAPTURED %s:%d->%s:%d proto=%d label=%s pkts=%d",
                                key[0], key[2], key[1], key[3], key[4], row[-1], len(bucket.packets)
                            )
                except Exception as e:
                    self.logger.exception("Error finalizing flow %s: %s", key, e)
            hub.sleep(0.2)  # Reduced from 0.3 to 0.2 seconds

    def _gc_loop(self):
        """Clean up very old flows"""
        while True:
            now = time.time()
            with self.lock:
                for key, bucket in list(self.flows.items()):
                    if bucket.last_ts and (now - bucket.last_ts) > 30.0:
                        del self.flows[key]
            hub.sleep(5.0)

    def _write_row(self, row):
        try:
            current_size = os.path.getsize(CSV_OUT) if os.path.exists(CSV_OUT) else 0
            self.logger.info("📝 Writing flow to CSV (current size: %d bytes)", current_size)
            
            self.csv_writer.writerow(row)
            self.csv_fh.flush()
            os.fsync(self.csv_fh.fileno())
            
            new_size = os.path.getsize(CSV_OUT)
            self.logger.info("✅ Wrote flow to CSV (new size: %d bytes, added: %d bytes)", 
                            new_size, new_size - current_size)
            
        except Exception as e:
            self.logger.exception("CSV write failed: %s", e)
            # Try to reinitialize the file
            try:
                self._init_csv_file()
            except:
                pass

    def _compute_features_row(self, key, bucket):  # FIXED: Proper indentation starts here
        (src_ip, dst_ip, src_port, dst_port, proto, _) = key
        pkts = list(bucket.packets)
        if not pkts:
            return None

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

        # Active/Idle periods
        active_periods = []
        idle_gaps = []
        if pkts:
            sorted_pkts = sorted(pkts, key=lambda x: x.ts)
            last_ts = sorted_pkts[0].ts
            cur_active_start = last_ts
            for p in sorted_pkts[1:]:
                gap = p.ts - last_ts
                if gap > 1.0:  # SUBFLOW_GAP
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

        # Packet statistics
        fwd_bytes = sum(fwd_lens)
        bwd_bytes = sum(bwd_lens)
        tot_bytes = fwd_bytes + bwd_bytes
        tot_pkts = len(pkts)
        tot_fwd = len(fwd)
        tot_bwd = len(bwd)

        # Flow rates
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

        # Average packet sizes
        pkt_size_avg = safe_mean(all_lens)
        fwd_seg_size_avg = safe_mean(fwd_lens)
        bwd_seg_size_avg = safe_mean(bwd_lens)

        # Subflows
        subflows = []
        if pkts:
            ssorted = sorted(pkts, key=lambda x: x.ts)
            cur = [ssorted[0]]
            for p in ssorted[1:]:
                if (p.ts - cur[-1].ts) > 1.0:  # SUBFLOW_GAP
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

        # Simplified bulk stats
        fwd_byts_b_avg = 0.0
        fwd_pkts_b_avg = 0.0
        fwd_blk_rate_avg = 0.0
        bwd_byts_b_avg = 0.0
        bwd_pkts_b_avg = 0.0
        bwd_blk_rate_avg = 0.0

        # Window sizes and active data packets
        init_fwd_win_byts = 0
        init_bwd_win_byts = 0
        
        def payload_len(p):
            return max(0, p.length - (p.eth_hdr_len + p.ip_hdr_len + p.l4_hdr_len))
        fwd_act_data_pkts = sum(1 for p in fwd if payload_len(p) > 0)
        fwd_seg_size_min = fwd_min

        # Build FlowID
        fid = f"{src_ip}-{src_port}-{dst_ip}-{dst_port}-{proto}-{int(start_ts*1000)}"

        # Label
        label = read_label_file()

        # Assemble row
        row = [
            fid, src_ip, src_port, dst_ip, dst_port, proto,
            start_ts, duration, tot_fwd, tot_bwd,
            fwd_bytes, bwd_bytes, fwd_max, fwd_min, fwd_mean, fwd_std,
            bwd_max, bwd_min, bwd_mean, bwd_std,
            flow_bytes_per_s, flow_pkts_per_s, all_mean, all_std, all_max, all_min,
            f_tot, f_mean, f_std, f_max, f_min,
            b_tot, b_mean, b_std, b_max, b_min,
            fwd_psh, bwd_psh, fwd_urg, bwd_urg,
            fwd_header_len_total, bwd_header_len_total,
            fwd_pkts_per_s, bwd_pkts_per_s,
            all_min_len, all_max_len, all_mean_len, all_std_len, all_var_len,
            fin_cnt, syn_cnt, rst_cnt, psh_cnt, ack_cnt, urg_cnt, cwr_cnt, ece_cnt,
            down_up_ratio, pkt_size_avg, fwd_seg_size_avg, bwd_seg_size_avg,
            fwd_byts_b_avg, fwd_pkts_b_avg, fwd_blk_rate_avg,
            bwd_byts_b_avg, bwd_pkts_b_avg, bwd_blk_rate_avg,
            sub_fwd_pkts_avg, sub_fwd_bytes_avg, sub_bwd_pkts_avg, sub_bwd_bytes_avg,
            init_fwd_win_byts, init_bwd_win_byts,
            fwd_act_data_pkts, fwd_seg_size_min,
            safe_mean(active_periods), safe_std(active_periods), safe_max(active_periods), safe_min(active_periods),
            safe_mean(idle_gaps), safe_std(idle_gaps), safe_max(idle_gaps), safe_min(idle_gaps),
            label
        ]
        
        if len(row) != len(HEADERS):
            if len(row) < len(HEADERS):
                row = row + [0] * (len(HEADERS) - len(row))
            else:
                row = row[:len(HEADERS)]
        
        return row