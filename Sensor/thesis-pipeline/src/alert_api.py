from fastapi import FastAPI
from pydantic import BaseModel
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

DB_PATH = Path("data/alerts.db")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
app = FastAPI(title="C2 Threat Hunting & SOC API")

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS alerts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, orig_h TEXT, resp_h TEXT, "
        "scenario TEXT, risk_score INTEGER, severity TEXT, reason TEXT)"
    )
    return conn

class Alert(BaseModel):
    orig_h: str
    resp_h: str
    scenario: Optional[str] = None
    risk_score: int
    severity: str
    reason: str

@app.post("/alerts")
def create_alert(a: Alert):
    conn = get_conn()
    conn.execute(
        "INSERT INTO alerts (ts, orig_h, resp_h, scenario, risk_score, severity, reason) "
        "VALUES (?,?,?,?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(), a.orig_h, a.resp_h, a.scenario, a.risk_score, a.severity, a.reason)
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}

@app.get("/alerts")
def list_alerts(min_score: int = 0, limit: int = 100000):
    conn = get_conn()
    if limit <= 0:
        rows = conn.execute(
            "SELECT id, ts, orig_h, resp_h, scenario, risk_score, severity, reason "
            "FROM alerts WHERE risk_score >= ? ORDER BY risk_score DESC, id DESC",
            (min_score,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, ts, orig_h, resp_h, scenario, risk_score, severity, reason "
            "FROM alerts WHERE risk_score >= ? ORDER BY risk_score DESC, id DESC LIMIT ?",
            (min_score, limit)
        ).fetchall()
    conn.close()
    cols = ["id", "ts", "orig_h", "resp_h", "scenario", "risk_score", "severity", "reason"]
    return [dict(zip(cols, r)) for r in rows]