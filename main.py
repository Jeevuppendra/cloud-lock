# cloud_lock_api.py
# Run locally:  uvicorn cloud_lock_api:app --host 0.0.0.0 --port 8000
# Deploy to cloud (Render/Railway) easily.

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import time
import secrets

app = FastAPI(title="Cloud Lock Demo API", version="1.0")

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # for demo
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------------
# DEMO SECURITY KEYS (change these!)
# ----------------------------
ADMIN_API_KEY = "CHANGE_ME_ADMIN_KEY_12345"   # used by web/phone to trigger unlock
DEVICE_KEYS = {                               # used by ESP32
    "lock1": "CHANGE_ME_DEVICE_KEY_LOCK1"
}

# ----------------------------
# In-memory command store
# ----------------------------
# commands[device_id] = {
#   "action": "unlock" or "none",
#   "request_id": "abc",
#   "expires_at": unix_time,
#   "created_at": unix_time
# }
commands: Dict[str, Dict[str, Any]] = {}

# simple event log
events = []  # keep last N events


def now() -> int:
    return int(time.time())


def ensure_device(device_id: str):
    if device_id not in DEVICE_KEYS:
        raise HTTPException(status_code=404, detail="Unknown device_id")
    if device_id not in commands:
        commands[device_id] = {"action": "none", "request_id": "", "expires_at": 0, "created_at": 0}


class UnlockRequest(BaseModel):
    device_id: str
    ttl_seconds: Optional[int] = 10  # command expiry


class AckRequest(BaseModel):
    device_id: str
    request_id: str
    status: str = "done"  # done/failed/other


@app.get("/")
def root():
    return {"ok": True, "service": "cloud-lock-demo", "time": now()}


@app.post("/api/unlock")
def api_unlock(payload: UnlockRequest, x_api_key: Optional[str] = Header(default=None)):
    # Admin authentication
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin API key")

    ensure_device(payload.device_id)

    # Create a one-time unlock command
    req_id = secrets.token_hex(8)
    ttl = max(3, min(int(payload.ttl_seconds or 10), 60))  # 3..60 seconds
    exp = now() + ttl

    commands[payload.device_id] = {
        "action": "unlock",
        "request_id": req_id,
        "expires_at": exp,
        "created_at": now(),
    }

    events.append({"ts": now(), "type": "unlock_issued", "device_id": payload.device_id, "request_id": req_id})
    if len(events) > 200:
        del events[:50]

    return {"ok": True, "device_id": payload.device_id, "action": "unlock", "request_id": req_id, "expires_at": exp}


@app.get("/api/command")
def api_command(device_id: str):
    ensure_device(device_id)
    cmd = commands.get(device_id, {"action": "none", "request_id": "", "expires_at": 0, "created_at": 0})

    # Expire command if too old
    if cmd["action"] != "none" and now() > int(cmd.get("expires_at", 0)):
        commands[device_id] = {"action": "none", "request_id": "", "expires_at": 0, "created_at": 0}
        events.append({"ts": now(), "type": "command_expired", "device_id": device_id})
        return {"action": "none"}

    return cmd


@app.post("/api/ack")
def api_ack(payload: AckRequest, x_device_key: Optional[str] = Header(default=None)):
    ensure_device(payload.device_id)

    # Device authentication
    expected = DEVICE_KEYS[payload.device_id]
    if x_device_key != expected:
        raise HTTPException(status_code=401, detail="Invalid device key")

    current = commands.get(payload.device_id, {})
    if current.get("request_id") != payload.request_id:
        # Request mismatch (maybe already cleared) — still log it
        events.append({
            "ts": now(),
            "type": "ack_mismatch",
            "device_id": payload.device_id,
            "request_id": payload.request_id,
            "current_request_id": current.get("request_id", ""),
            "status": payload.status,
        })
        return {"ok": False, "detail": "request_id mismatch"}

    # Clear command after successful ack
    commands[payload.device_id] = {"action": "none", "request_id": "", "expires_at": 0, "created_at": 0}
    events.append({
        "ts": now(),
        "type": "ack",
        "device_id": payload.device_id,
        "request_id": payload.request_id,
        "status": payload.status
    })

    return {"ok": True}


@app.get("/api/events")
def api_events(x_api_key: Optional[str] = Header(default=None)):
    # Optional: protect logs behind admin key
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin API key")
    return {"events": events[-100:]}
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
