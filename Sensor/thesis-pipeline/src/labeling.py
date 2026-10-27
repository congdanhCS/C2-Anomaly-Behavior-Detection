"""labeling.py - Gan nhan Benign / C2-Suspicious cho flow (conn) va lan sang dns/http/ssl theo uid."""
import pandas as pd
from common import CTU13_BOT_IPS

LABEL_NAMES = {0: "Benign", 1: "C2/Suspicious"}


def get_ctu13_bot_ips(scenario_name):
    """Lay tap hop IP botnet theo ten scenario (vd: 'ctu13_s9' hoac 'scenario9')."""
    name = str(scenario_name).lower().strip()
    if name.startswith("scenario"):
        num = name.replace("scenario", "")
        name = f"ctu13_s{num}"
    return CTU13_BOT_IPS.get(name, {"147.32.84.165"})


def rule_from_meta(name, meta):
    """Tu meta.json cua lan capture -> (rule, c2_type) hoac (None, None) neu thieu thong tin."""
    label = meta.get("label")
    if label is None and name.lower().startswith("benign"):
        label = "benign"
    if label == "benign":
        return {"type": "benign"}, "benign"
    if label == "c2":
        bot, c2 = meta.get("bot_ip"), meta.get("c2_ip")
        if not bot or not c2:
            return None, None
        return {"type": "pair", "bot_ip": str(bot), "c2_ip": str(c2)}, str(meta.get("mode", "c2"))
    return None, None


def filter_window(conn, start_epoch, end_epoch, margin=2.0):
    """Giu flow co ts trong [start - margin, end + margin] (neu co moc thoi gian)."""
    if start_epoch is not None:
        conn = conn[conn["ts"] >= start_epoch - margin]
    if end_epoch is not None:
        conn = conn[conn["ts"] <= end_epoch + margin]
    return conn.reset_index(drop=True)


def label_conn(conn, rule):
    out = conn.copy()
    t = rule["type"]
    if t == "benign":
        lab = pd.Series(0, index=out.index)
        desc = "scenario benign: moi flow = Benign"
    elif t == "ip":
        # Ho tro truyen 1 IP (str), nhieu IP (set/list), hoac tra theo scenario_name
        if "scenario" in rule:
            bot_ips = get_ctu13_bot_ips(rule["scenario"])
        else:
            raw_ip = rule["ip"]
            bot_ips = {raw_ip} if isinstance(raw_ip, str) else set(raw_ip)
            
        lab = ((out["orig_h"].isin(bot_ips)) | (out["resp_h"].isin(bot_ips))).astype(int)
        desc = f"flow co IP trong {sorted(bot_ips)} = C2/Suspicious"
    elif t == "pair":
        a, b = rule["bot_ip"], rule["c2_ip"]
        lab = (((out["orig_h"] == a) & (out["resp_h"] == b)) |
               ((out["orig_h"] == b) & (out["resp_h"] == a))).astype(int)
        desc = f"flow giua {a} va {b} = C2/Suspicious"
    else:
        raise ValueError(f"rule khong hop le: {rule}")
    out["label"] = lab.astype("int8")
    out["label_name"] = out["label"].map(LABEL_NAMES)
    out["label_rule"] = desc
    return out


def propagate_label(df, conn_labeled):
    """Gan nhan cho dns/http/ssl theo uid cua conn; bo dong khong con conn tuong ung."""
    if df.empty:
        out = df.copy()
        out["label"] = pd.Series(dtype="int8")
        out["label_name"] = pd.Series(dtype="object")
        return out
    m = conn_labeled.set_index("uid")["label"]
    out = df[df["uid"].isin(m.index)].copy()
    out["label"] = out["uid"].map(m).astype("int8")
    out["label_name"] = out["label"].map(LABEL_NAMES)
    return out