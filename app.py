import os
import csv
import time
import socket
import struct
from pathlib import Path
from typing import List, Dict

import numpy as np
import pandas as pd
import streamlit as st
import joblib
from tensorflow.keras.models import load_model

# ============================
# CONFIG
# ============================
DEFAULT_SOURCE_CSV = "/tmp/insdn_features.csv"  # written by ryu_insdn_full.py
DEFAULT_OUT_CSV    = "./insdn_with_predictions.csv"
MODEL_PATH         = "model/lstm_model.h5"
SCALER_PATH        = "model/scaler.pkl"
LABEL_ENCODER_PATH = "model/label_encoder.pkl"

# The 12 input columns expected by your LSTM/scaler
MODEL_COLUMNS = [
    "Src IP", "Dst IP", "Dst Port", "Flow Duration", "Flow Pkts/s",
    "Flow IAT Mean", "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Max",
    "Bwd Header Len", "Bwd Pkts/s", "Init Bwd Win Byts"
]

# Mapping from Ryu CSV headers -> the 12-model columns
# (the Ryu app writes these exact names)
RYU_TO_MODEL = {
    "SrcIP":             "Src IP",
    "DstIP":             "Dst IP",
    "DstPort":           "Dst Port",
    "Flow_Duration_s":   "Flow Duration",
    "Flow_Pkts_per_s":   "Flow Pkts/s",
    "Flow_IAT_Mean":     "Flow IAT Mean",
    "Bwd_IAT_Tot":       "Bwd IAT Tot",
    "Bwd_IAT_Mean":      "Bwd IAT Mean",
    "Bwd_IAT_Max":       "Bwd IAT Max",
    "Bwd_Header_Len":    "Bwd Header Len",
    "Bwd_Pkts_per_s":    "Bwd Pkts/s",
    "Init_Bwd_Win_Bytes":"Init Bwd Win Byts",
}

# ============================
# HELPERS
# ============================
def ip_to_int(ip: str) -> int:
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception:
        return 0

def to_number(x):
    # robust cast for numbers coming from CSV
    try:
        if x is None or x == "":
            return 0
        if isinstance(x, (int, float)):
            return x
        # handle scientific, ints, floats
        return float(x)
    except Exception:
        return 0

def ryu_row_to_model_row(ryu_row: Dict[str, str]) -> Dict[str, float]:
    """
    Convert a single row (dict) from ryu_insdn_full HEADERS into the 12-feature dict expected by the model.
    """
    out = {}
    # IPs
    out["Src IP"] = ip_to_int(ryu_row.get("SrcIP", "0.0.0.0"))
    out["Dst IP"] = ip_to_int(ryu_row.get("DstIP", "0.0.0.0"))
    # Direct mapped numerics
    for ryu_name, model_name in RYU_TO_MODEL.items():
        if model_name in ("Src IP", "Dst IP"):
            continue  # already handled
        out[model_name] = to_number(ryu_row.get(ryu_name, 0))
    return out

def load_models():
    model = load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    label_enc = joblib.load(LABEL_ENCODER_PATH)
    return model, scaler, label_enc

def predict_rows(df_feat: pd.DataFrame, model, scaler, label_enc) -> List[str]:
    """
    df_feat must have exactly MODEL_COLUMNS.
    Returns a list of string labels (decoded from label encoder).
    """
    # Scale
    X_scaled = scaler.transform(df_feat)          # shape: [N, 12]
    X_lstm   = X_scaled.reshape(len(df_feat), 1, -1)  # [N, 1, 12]
    # Predict
    probs = model.predict(X_lstm, verbose=0)      # [N, num_classes]
    preds = np.argmax(probs, axis=1)
    labels = label_enc.inverse_transform(preds)
    return labels

def open_csv_and_seek(csv_path: str, start_end: bool = True):
    """
    Open a CSV in text mode and return (fileobj, csv.DictReader, header_list).
    If start_end is True, seek to file end (tail mode).
    """
    f = open(csv_path, "r", newline="")
    # Read header first
    pos0 = f.tell()
    header_line = f.readline()
    if not header_line:
        # empty file, keep position at 0
        f.seek(pos0)
        header = []
        reader = None
        return f, reader, header
    header = [h.strip() for h in header_line.strip().split(",")]
    # Tail behavior
    if start_end:
        f.seek(0, os.SEEK_END)
    reader = csv.DictReader(f, fieldnames=header)
    return f, reader, header

# ============================
# STREAMLIT APP
# ============================
st.set_page_config(layout="wide")
st.title("🧠 InSDN LSTM IDS — Live from Ryu CSV")

# --- Sidebar controls
with st.sidebar:
    st.subheader("Data Sources")
    source_csv = st.text_input("Ryu CSV path", value=DEFAULT_SOURCE_CSV)
    out_csv = st.text_input("Save detections to", value=DEFAULT_OUT_CSV)
    autoscroll = st.checkbox("Auto-scroll logs", value=True)
    start_button = st.button("Start")
    stop_button  = st.button("Stop")

# --- Session state
if "running" not in st.session_state:
    st.session_state.running = False
if "file_pos" not in st.session_state:
    st.session_state.file_pos = 0
if "det_count" not in st.session_state:
    st.session_state.det_count = 0
if "last_rate_t" not in st.session_state:
    st.session_state.last_rate_t = time.time()
if "last_rate_n" not in st.session_state:
    st.session_state.last_rate_n = 0
if "df_buffer" not in st.session_state:
    st.session_state.df_buffer = pd.DataFrame(columns=MODEL_COLUMNS + ["Predicted_Label", "StartTime", "FlowID"])

# Start/Stop
if start_button:
    st.session_state.running = True
if stop_button:
    st.session_state.running = False

# --- Model loading
try:
    model, scaler, label_encoder = load_models()
    st.success("Model, scaler and label encoder loaded.")
except Exception as e:
    st.error(f"Failed to load model/scaler/label_encoder: {e}")
    st.stop()

# --- UI placeholders
rate_placeholder = st.metric("Flows/sec", "0.0")
table_placeholder = st.empty()
log_placeholder = st.empty()

# Ensure output CSV has header
out_path = Path(out_csv)
if not out_path.exists():
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", newline="") as fo:
            w = csv.writer(fo)
            w.writerow(MODEL_COLUMNS + ["Predicted_Label", "FlowID", "StartTime"])
    except Exception as e:
        st.warning(f"Could not pre-create output CSV: {e}")

# --- Main loop
if st.session_state.running:
    if not os.path.exists(source_csv):
        st.error(f"Source CSV not found: {source_csv}")
        st.stop()

    # Open & tail
    try:
        f, reader, header = open_csv_and_seek(source_csv, start_end=True)
    except Exception as e:
        st.error(f"Could not open source CSV: {e}")
        st.stop()

    # Keep reading new rows until user stops
    log_lines: List[str] = []
    try:
        while st.session_state.running:
            line = f.readline()
            if not line:
                # no new data yet
                time.sleep(0.2)
                # update rate metric
                now = time.time()
                dt = now - st.session_state.last_rate_t
                if dt >= 1.0:
                    rate = st.session_state.last_rate_n / dt if dt > 0 else 0.0
                    rate_placeholder.metric("Flows/sec", f"{rate:.1f}")
                    st.session_state.last_rate_t = now
                    st.session_state.last_rate_n = 0
                continue

            # Parse row -> dict with header
            row_vals = [x.strip() for x in line.strip().split(",")]
            if len(row_vals) != len(header):
                # malformed/partial line
                continue

            row = {header[i]: row_vals[i] for i in range(len(header))}

            # Convert to model feature row
            feat_dict = ryu_row_to_model_row(row)
            # Guard: ensure all expected columns exist
            if set(feat_dict.keys()) != set(MODEL_COLUMNS):
                # Align fields if any missing
                for c in MODEL_COLUMNS:
                    feat_dict.setdefault(c, 0)

            df_feat = pd.DataFrame([feat_dict], columns=MODEL_COLUMNS)

            # Predict
            try:
                labels = predict_rows(df_feat, model, scaler, label_encoder)
                label = labels[0]
            except Exception as e:
                label = "Error"
            
            # Collect display info
            flow_id = row.get("FlowID", "n/a")
            start_time = row.get("StartTime", "0")
            st.session_state.last_rate_n += 1
            st.session_state.det_count += 1

            # Add to UI buffer
            show_row = df_feat.copy()
            show_row["Predicted_Label"] = label
            show_row["FlowID"] = flow_id
            show_row["StartTime"] = start_time
            st.session_state.df_buffer = pd.concat(
                [st.session_state.df_buffer, show_row],
                axis=0, ignore_index=True
            )
            # Keep last N rows to avoid growing forever
            if len(st.session_state.df_buffer) > 5000:
                st.session_state.df_buffer = st.session_state.df_buffer.iloc[-3000:].reset_index(drop=True)

            # Append to output CSV
            try:
                with open(out_path, "a", newline="") as fo:
                    w = csv.writer(fo)
                    w.writerow([show_row.iloc[0][c] for c in MODEL_COLUMNS] +
                               [label, flow_id, start_time])
            except Exception as e:
                # non-fatal
                pass

            # Logs
            ts_hhmmss = time.strftime("%H:%M:%S", time.localtime(float(start_time))) if str(start_time).replace(".","",1).isdigit() else time.strftime("%H:%M:%S")
            status = "✅ SAFE" if label.lower() == "normal" else f"❌ ATTACK: {label}"
            log_lines.append(f"{ts_hhmmss} | {status} | FlowID={flow_id}")
            if len(log_lines) > 200:
                log_lines.pop(0)

            # Refresh UI
            # Table (last 200 detections)
            table_placeholder.dataframe(
                st.session_state.df_buffer.tail(200),
                use_container_width=True
            )
            log_text = "\n".join(log_lines[-50:])
            if autoscroll:
                log_placeholder.text(log_text)
            else:
                # keep static until user scrolls
                pass

    finally:
        try:
            f.close()
        except Exception:
            pass

else:
    st.info("Click **Start** to begin tailing Ryu CSV and running the IDS.\n\n"
            "Make sure your Ryu controller is running `ryu_insdn_full.py` and Mininet scenario is generating flows.")

# ============================
# HOW TO USE
# ============================
# 1) Start your Ryu controller with ryu_insdn_full.py so it writes /tmp/insdn_features.csv
# 2) Launch your Mininet + attacks (attack_orchestrator.py)
# 3) In another terminal: streamlit run insdn_ids_dashboard.py
# 4) Click Start. New flows appended to /tmp/insdn_features.csv will be ingested, scored, and displayed.
