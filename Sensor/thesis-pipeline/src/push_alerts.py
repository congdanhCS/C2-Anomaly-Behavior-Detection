"""
Doc mo hinh RF da luu + feature cua cua so moi nhat, tinh risk score 0-100
(muc 5.2) va gui sang Alert API (de do duoc do tre end-to-end tu telemetry
den khi alert duoc luu, theo yeu cau muc 5.6).

Can: pip install requests
"""
import pandas as pd
import pickle
import requests
import time
from pathlib import Path

API_URL = "http://localhost:8000/alerts"
MODEL_PATH = Path("models/rf_model.pkl")
DATA_PATH = Path("data/features/test.csv")  # thay bang nguon telemetry truc tiep khi trien khai thuc

bundle = pickle.load(open(MODEL_PATH, "rb"))
model, cols = bundle["model"], bundle["features"]

df = pd.read_csv(DATA_PATH)
df["risk_prob"] = model.predict_proba(df[cols])[:, 1]
df["risk_score"] = (df["risk_prob"] * 100).astype(int)


def severity(score):
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Suspicious"
    return "Normal"


alerts = df[df["risk_score"] >= 30].sort_values("risk_score", ascending=False)
print(f"Gui {len(alerts)} canh bao den API...")

latencies_ms = []
for _, row in alerts.iterrows():
    reason = (
        f"n_conn={row.get('n_conn', 0):.0f}, "
        f"periodicity_score={row.get('periodicity_score', 0):.2f}, "
        f"dns_nx_ratio={row.get('dns_nx_ratio', 0):.0%}"
    )
    payload = {
        "orig_h": row["orig_h"],
        "resp_h": row["resp_h"],
        "scenario": row.get("scenario", ""),
        "risk_score": int(row["risk_score"]),
        "severity": severity(row["risk_score"]),
        "reason": reason,
    }
    t0 = time.time()
    try:
        requests.post(API_URL, json=payload, timeout=5)
        latencies_ms.append((time.time() - t0) * 1000)
    except requests.exceptions.RequestException as e:
        print(f"  Loi gui alert: {e}")

if latencies_ms:
    print(f"Do tre trung binh tu khi co ket qua detection den khi alert duoc API luu: "
          f"{sum(latencies_ms) / len(latencies_ms):.2f} ms "
          f"(min={min(latencies_ms):.2f} ms, max={max(latencies_ms):.2f} ms)")
