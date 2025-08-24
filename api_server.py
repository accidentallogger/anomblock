#!/usr/bin/env python3
"""
api_server.py

FastAPI server that accepts flow payloads posted by ryu_insdn_full.py (or raw Ryu rows),
scores them using model/scaler/label_encoder, and exposes a /recent endpoint for dashboards.

Endpoints:
- GET  /healthz
- GET  /labels
- GET  /recent?n=50
- GET  /packets?n=20
- POST /predict-row     (accepts ryu payload or model_row; returns label + probs)
- POST /predict-batch   (list)
- POST /predict-csv     (csv upload with Ryu headers)
"""

import io
import os
import socket
import struct
import threading
import time
import json
import asyncio
from typing import Any, Dict, List, Optional
from collections import deque
import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, File, UploadFile, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.responses import JSONResponse
from tensorflow.keras.models import load_model
from sse_starlette.sse import EventSourceResponse

# Config (can override with env)
MODEL_PATH = os.getenv("MODEL_PATH", "model2/lstm_model.h5")
SCALER_PATH = os.getenv("SCALER_PATH", "model2/scaler.pkl")
LABEL_ENCODER_PATH = os.getenv("LABEL_ENCODER_PATH", "model2/label_encoder.pkl")

API_RECENT_MAX = int(os.getenv("API_RECENT_MAX", "500"))

MODEL_COLUMNS = [
    "Src IP", "Dst IP", "Dst Port", "Flow Duration", "Flow Pkts/s",
    "Flow IAT Mean", "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Max",
    "Bwd Header Len", "Bwd Pkts/s", "Init Bwd Win Byts"
]

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

def ip_to_int(ip: str) -> int:
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception:
        return 0

def to_number(x: Any) -> float:
    try:
        if x is None or x == "":
            return 0.0
        if isinstance(x, (int, float, np.floating, np.integer)):
            return float(x)
        return float(str(x).strip())
    except Exception:
        return 0.0

def ryu_row_to_model_row(ryu_row: Dict[str, Any]) -> Dict[str, float]:
    out: Dict[str, float] = {}
    out["Src IP"] = ip_to_int(str(ryu_row.get("SrcIP", "0.0.0.0")))
    out["Dst IP"] = ip_to_int(str(ryu_row.get("DstIP", "0.0.0.0")))
    for ryu_name, model_name in RYU_TO_MODEL.items():
        if model_name in ("Src IP", "Dst IP"):
            continue
        out[model_name] = to_number(ryu_row.get(ryu_name, 0))
    for c in MODEL_COLUMNS:
        out.setdefault(c, 0.0)
    return out

def detect_and_extract_model_row(obj: Dict[str, Any]) -> Dict[str, float]:
    # explicit model_row
    if "model_row" in obj and isinstance(obj["model_row"], dict):
        row = obj["model_row"]
        if "model_columns" in obj and isinstance(obj["model_columns"], list):
            cols = obj["model_columns"]
            mapped = {}
            for i, target in enumerate(MODEL_COLUMNS):
                if i < len(cols):
                    mapped[target] = to_number(row.get(cols[i], 0))
                else:
                    mapped[target] = to_number(row.get(target, 0))
            return mapped
        return {k: to_number(row.get(k, 0)) for k in MODEL_COLUMNS}
    # ryu_row nested
    if "ryu_row" in obj and isinstance(obj["ryu_row"], dict):
        return ryu_row_to_model_row(obj["ryu_row"])
    # direct model-like
    if set(MODEL_COLUMNS).issubset(set(obj.keys())):
        return {k: to_number(obj.get(k, 0)) for k in MODEL_COLUMNS}
    # assume it's a raw ryu dict
    return ryu_row_to_model_row(obj)

# Pydantic models
class PredictResponse(BaseModel):
    label: str
    probs: Optional[List[float]] = None
    flow_id: Optional[str] = None
    start_time: Optional[float] = None

class BatchPredictResponse(BaseModel):
    labels: List[str]
    probs: Optional[List[List[float]]] = None

class AnyDict(BaseModel):
    root: Dict[str, Any]

# App
app = FastAPI(title="InSDN IDS API", version="1.3")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

# Prediction lock + recent store
_pred_lock = threading.Lock()
_recent_lock = threading.Lock()
_sse_subscribers = []

# SSE event management
class SSEManager:
    def __init__(self):
        self.subscribers = []
    
    async def add_event(self, event_type: str, data: Dict[str, Any]):
        for subscriber in self.subscribers:
            await subscriber.put({"type": event_type, "data": data})
    
    def add_subscriber(self, queue):
        self.subscribers.append(queue)
    
    def remove_subscriber(self, queue):
        if queue in self.subscribers:
            self.subscribers.remove(queue)

sse_manager = SSEManager()

@app.on_event("startup")
async def startup_event():
    # load artifacts
    try:
        app.state.model = load_model(MODEL_PATH)
        print(f"Loaded model from {MODEL_PATH}")
    except Exception as e:
        app.state.model = None
        print(f"Warning: failed to load model: {e}")
    try:
        app.state.scaler = joblib.load(SCALER_PATH)
        print(f"Loaded scaler from {SCALER_PATH}")
    except Exception as e:
        app.state.scaler = None
        print(f"Warning: failed to load scaler: {e}")
    try:
        app.state.label_enc = joblib.load(LABEL_ENCODER_PATH)
        print(f"Loaded label encoder from {LABEL_ENCODER_PATH}")
    except Exception as e:
        app.state.label_enc = None
        print(f"Warning: failed to load label_encoder: {e}")
    # recent predictions buffer: list of dicts
    app.state.recent = []
    # packet buffer
    app.state.packet_buffer = deque(maxlen=1000)  # Store recent packets

@app.get("/healthz")
def healthz():
    ok = (app.state.model is not None) and (app.state.scaler is not None) and (app.state.label_enc is not None)
    return {"status": "ok" if ok else "degraded", "ready": ok}

@app.get("/labels")
def labels():
    le = getattr(app.state, "label_enc", None)
    if le is None:
        return {"classes": []}
    return {"classes": list(le.classes_)}

def _append_recent(item: Dict[str, Any]):
    with _recent_lock:
        app.state.recent.append(item)
        if len(app.state.recent) > API_RECENT_MAX:
            app.state.recent = app.state.recent[-API_RECENT_MAX:]

@app.get("/packets")
def get_packets(n: int = Query(20, gt=0, le=1000)):
    """Endpoint to get recent packets"""
    with _recent_lock:
        packets = list(app.state.packet_buffer)[-n:]
        return {"packets": packets}

@app.get("/sse")
async def sse_endpoint():
    async def event_generator():
        queue = asyncio.Queue()
        sse_manager.add_subscriber(queue)
        try:
            while True:
                event = await queue.get()
                yield {
                    "event": "message",
                    "data": json.dumps(event)
                }
        except asyncio.CancelledError:
            sse_manager.remove_subscriber(queue)
    
    return EventSourceResponse(event_generator())

@app.post("/predict-row", response_model=PredictResponse)
async def predict_row(row: AnyDict, return_probs: bool = Query(False)):
    try:
        r = row.root
        feat = detect_and_extract_model_row(r)
        df = pd.DataFrame([feat], columns=MODEL_COLUMNS)
        # prediction
        with _pred_lock:
            if app.state.scaler is None or app.state.model is None or app.state.label_enc is None:
                raise RuntimeError("Model/scaler/label_encoder not available on server.")
            Xs = app.state.scaler.transform(df)
            Xl = Xs.reshape(len(df), 1, Xs.shape[1])
            probs = app.state.model.predict(Xl, verbose=0)
        preds = np.argmax(probs, axis=1)
        labels = app.state.label_enc.inverse_transform(preds)
        label = str(labels[0])
        probs_list = probs.tolist()[0]
        resp = {
            "label": label,
            "flow_id": r.get("flow_id") or r.get("FlowID"),
            "start_time": float(r.get("start_time") or r.get("StartTime")) if str(r.get("start_time") or r.get("StartTime") or "").replace(".","",1).isdigit() else None
        }
        if return_probs:
            resp["probs"] = probs_list

        # store a compact recent entry for the dashboard
        recent_item = {
            "ts": time.time(),
            "flow_id": resp["flow_id"],
            "start_time": resp["start_time"],
            "label": label,
            "probs": probs_list,
            "model_row": feat,
            "meta": r.get("meta") if isinstance(r.get("meta"), dict) else {}
        }
        _append_recent(recent_item)

        # Store packet info if available in the row
        if "packets" in r and isinstance(r["packets"], list):
            with _recent_lock:
                for pkt in r["packets"]:
                    if isinstance(pkt, dict):
                        app.state.packet_buffer.append({
                            "timestamp": time.time(),
                            "src_ip": pkt.get("src_ip"),
                            "dst_ip": pkt.get("dst_ip"),
                            "protocol": pkt.get("protocol"),
                            "length": pkt.get("length"),
                            "direction": pkt.get("direction")
                        })
                        # Send packet event to SSE
                        await sse_manager.add_event("packet", {
                            "timestamp": time.time(),
                            "src_ip": pkt.get("src_ip"),
                            "dst_ip": pkt.get("dst_ip"),
                            "protocol": pkt.get("protocol"),
                            "length": pkt.get("length"),
                            "direction": pkt.get("direction")
                        })
        
        # Send flow event to SSE
        await sse_manager.add_event("flow", recent_item)
        
        return JSONResponse(resp)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"prediction error: {e}")

@app.post("/predict-batch", response_model=BatchPredictResponse)
async def predict_batch(rows: List[AnyDict], return_probs: bool = Query(False)):
    try:
        feats = [detect_and_extract_model_row(r.root) for r in rows]
        df = pd.DataFrame(feats, columns=MODEL_COLUMNS)
        with _pred_lock:
            if app.state.scaler is None or app.state.model is None or app.state.label_enc is None:
                raise RuntimeError("Model/scaler/label_encoder not available on server.")
            Xs = app.state.scaler.transform(df)
            Xl = Xs.reshape(len(df), 1, Xs.shape[1])
            probs = app.state.model.predict(Xl, verbose=0)
        preds = np.argmax(probs, axis=1)
        labels = app.state.label_enc.inverse_transform(preds)
        labels_list = [str(x) for x in labels]
        # append to recent
        for i, r in enumerate(rows):
            recent_item = {
                "ts": time.time(),
                "flow_id": r.root.get("flow_id") or r.root.get("FlowID"),
                "start_time": r.root.get("start_time") or r.root.get("StartTime"),
                "label": labels_list[i],
                "probs": probs.tolist()[i],
                "model_row": feats[i],
                "meta": r.root.get("meta") if isinstance(r.root.get("meta"), dict) else {}
            }
            _append_recent(recent_item)
            
            # Send flow event to SSE
            await sse_manager.add_event("flow", recent_item)
            
            # Store packets if available
            if "packets" in r.root and isinstance(r.root["packets"], list):
                with _recent_lock:
                    for pkt in r.root["packets"]:
                        if isinstance(pkt, dict):
                            app.state.packet_buffer.append({
                                "timestamp": time.time(),
                                "src_ip": pkt.get("src_ip"),
                                "dst_ip": pkt.get("dst_ip"),
                                "protocol": pkt.get("protocol"),
                                "length": pkt.get("length"),
                                "direction": pkt.get("direction")
                            })
                            # Send packet event to SSE
                            await sse_manager.add_event("packet", {
                                "timestamp": time.time(),
                                "src_ip": pkt.get("src_ip"),
                                "dst_ip": pkt.get("dst_ip"),
                                "protocol": pkt.get("protocol"),
                                "length": pkt.get("length"),
                                "direction": pkt.get("direction")
                            })
        resp = {"labels": labels_list}
        if return_probs:
            resp["probs"] = probs.tolist()
        return JSONResponse(resp)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"batch prediction error: {e}")

@app.post("/predict-csv", response_model=BatchPredictResponse)
async def predict_csv(file: UploadFile = File(...), return_probs: bool = Query(False)):
    try:
        content = await file.read()
        df_in = pd.read_csv(io.BytesIO(content))
        feats = [ryu_row_to_model_row(rec) for rec in df_in.to_dict(orient="records")]
        df = pd.DataFrame(feats, columns=MODEL_COLUMNS)
        with _pred_lock:
            if app.state.scaler is None or app.state.model is None or app.state.label_enc is None:
                raise RuntimeError("Model/scaler/label_encoder not available on server.")
            Xs = app.state.scaler.transform(df)
            Xl = Xs.reshape(len(df), 1, Xs.shape[1])
            probs = app.state.model.predict(Xl, verbose=0)
        preds = np.argmax(probs, axis=1)
        labels = app.state.label_enc.inverse_transform(preds)
        for i, feat in enumerate(feats):
            recent_item = {
                "ts": time.time(),
                "flow_id": None,
                "start_time": None,
                "label": str(labels[i]),
                "probs": probs.tolist()[i],
                "model_row": feat,
                "meta": {}
            }
            _append_recent(recent_item)
            # Send flow event to SSE
            await sse_manager.add_event("flow", recent_item)
        resp = {"labels": [str(x) for x in labels]}
        if return_probs:
            resp["probs"] = probs.tolist()
        return JSONResponse(resp)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"csv prediction error: {e}")

@app.get("/recent")
def recent(n: int = Query(50, gt=0, le=API_RECENT_MAX)):
    with _recent_lock:
        slice_ = app.state.recent[-n:]
        # return a shallow copy
        return {"recent": list(reversed(slice_))}  # most recent first

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_server:app", host="0.0.0.0", port=8000, reload=False)