"""
Trich xuat dac trung 4 nhom A (flow), B (temporal), C (DNS), D (TLS/HTTP)
theo thiet ke muc 3.6 cua khoa luan. Cua so truot W=300s, buoc delta=60s,
nguong toi thieu n_min=4 ket noi cho thong ke chu ky.

Can: pip install pandas numpy tldextract pyarrow
"""
import pandas as pd
import numpy as np
from pathlib import Path
import tldextract

PROCESSED_DIR = Path("data/processed/dataset_v1")
OUT_DIR = Path("data/features")
OUT_DIR.mkdir(parents=True, exist_ok=True)

W = 300      # do dai cua so (s)
DELTA = 60   # buoc truot (s)
N_MIN = 4    # so ket noi toi thieu de tinh dac trung chu ky (3 khoang cach)

FAIL_STATES = {"S0", "REJ", "RSTOS0", "RSTRH", "SH"}


def shannon_entropy(s):
    if not s:
        return 0.0
    probs = pd.Series(list(s)).value_counts(normalize=True)
    return float(-(probs * np.log2(probs)).sum())


def subdomain_part(domain):
    """Tach phan nhan con truoc ten mien dang ky, dung tldextract de xu ly
    dung cac hau to nhieu tang (vd .com.vn) thay vi cat co dinh hai nhan cuoi."""
    try:
        ext = tldextract.extract(domain)
        return ext.subdomain if ext.subdomain else domain
    except Exception:
        return domain


print("[1/5] Dang tai du lieu Flows...")
flows = pd.read_parquet(PROCESSED_DIR / "flows.parquet")
# Cac cot ky vong co san tu buoc parsing truoc do:
# uid, ts, orig_h, resp_h, resp_p, orig_bytes, resp_bytes, orig_pkts,
# duration, conn_state, label, scenario, split

# --- Gan moi ket noi vao TAT CA cac cua so truot ma no thuoc ve (co the > 1 do chong lan) ---
flows["t0_scenario"] = flows.groupby("scenario")["ts"].transform("min")
k_min = np.ceil((flows["ts"] - flows["t0_scenario"] - W) / DELTA).clip(lower=0).astype(int)
k_max = np.floor((flows["ts"] - flows["t0_scenario"]) / DELTA).astype(int)

idx_rows, win_rows = [], []
for k0, k1, idx in zip(k_min.values, k_max.values, flows.index.values):
    for k in range(int(k0), int(k1) + 1):
        idx_rows.append(idx)
        win_rows.append(k)
win_map = pd.DataFrame({"_idx": idx_rows, "window": win_rows})
flows_w = flows.loc[win_map["_idx"]].reset_index(drop=True)
flows_w["window"] = win_map["window"].values

print(f"  {len(flows)} flow goc -> {len(flows_w)} ban ghi (host,dich,cua so) sau khi truot")

# ============================================================
# NHOM A - Dac trung flow
# ============================================================
print("[2/5] Dang tinh Nhom A (Flow)...")
flows_w["total_bytes"] = flows_w["orig_bytes"].fillna(0) + flows_w["resp_bytes"].fillna(0)
flows_w["is_fail"] = flows_w["conn_state"].isin(FAIL_STATES)
flows_w["is_small"] = flows_w["total_bytes"] <= 512

group_a = flows_w.groupby(["orig_h", "resp_h", "window", "split", "scenario"]).agg(
    n_conn=("uid", "count"),
    n_dst_port=("resp_p", "nunique"),
    orig_bytes_mean=("orig_bytes", "mean"),
    orig_bytes_std=("orig_bytes", "std"),
    resp_bytes_mean=("resp_bytes", "mean"),
    resp_bytes_std=("resp_bytes", "std"),
    pkts_mean=("orig_pkts", "mean"),
    duration_mean=("duration", "mean"),
    duration_std=("duration", "std"),
    fail_ratio=("is_fail", "mean"),
    small_ratio=("is_small", "mean"),
    size_cv=("total_bytes", lambda x: (x.std() / x.mean()) if x.mean() else 0.0),
    sum_orig_bytes=("orig_bytes", "sum"),
    sum_resp_bytes=("resp_bytes", "sum"),
    label=("label", "max"),
).reset_index()

# bytes_ratio = (sum orig +1) / (sum orig + sum resp + 2) -- cong thuc muc 3.6.2
group_a["bytes_ratio"] = (group_a["sum_orig_bytes"] + 1) / (
    group_a["sum_orig_bytes"] + group_a["sum_resp_bytes"] + 2
)
group_a.drop(columns=["sum_orig_bytes", "sum_resp_bytes"], inplace=True)

# n_dst_host: so dich duy nhat cua HOST NGUON trong cua so (muc host, khong phai muc cap)
n_dst_host = (
    flows_w.groupby(["orig_h", "window"])["resp_h"].nunique().rename("n_dst_host").reset_index()
)
group_a = group_a.merge(n_dst_host, on=["orig_h", "window"], how="left")

# ============================================================
# NHOM B - Dac trung thoi gian (beaconing)
# ============================================================
print("[3/5] Dang tinh Nhom B (Temporal/Beaconing)...")


def calc_temporal(g):
    ts_sorted = np.sort(g["ts"].values)
    n = len(ts_sorted)
    conn_rate = n / (W / 60.0)
    if n < N_MIN:
        return pd.Series(
            {
                "iat_mean": 0.0, "iat_std": 0.0, "iat_median": 0.0, "iat_cv": 0.0,
                "madm_rel": 0.0, "skew_bowley": 0.0, "frac_near_median": 0.0,
                "coverage": 0.0, "periodicity_score": 0.0, "low_n": 1,
                "conn_rate": conn_rate,
            }
        )
    iat = np.diff(ts_sorted)
    iat_mean, iat_std, iat_median = iat.mean(), iat.std(), float(np.median(iat))
    iat_cv = iat_std / iat_mean if iat_mean > 0 else 0.0
    madm_rel = (np.median(np.abs(iat - iat_median)) / iat_median) if iat_median > 0 else 0.0
    q1, q2, q3 = np.percentile(iat, [25, 50, 75])
    skew_bowley = (q1 + q3 - 2 * q2) / (q3 - q1) if (q3 - q1) > 0 else 0.0
    frac_near_median = float(np.mean(np.abs(iat - iat_median) <= 0.2 * iat_median)) if iat_median > 0 else 0.0
    coverage = (ts_sorted[-1] - ts_sorted[0]) / W
    periodicity_score = 0.5 * ((1 - min(1, abs(skew_bowley))) + (1 - min(1, madm_rel)))
    return pd.Series(
        {
            "iat_mean": iat_mean, "iat_std": iat_std, "iat_median": iat_median, "iat_cv": iat_cv,
            "madm_rel": madm_rel, "skew_bowley": skew_bowley, "frac_near_median": frac_near_median,
            "coverage": coverage, "periodicity_score": periodicity_score, "low_n": 0,
            "conn_rate": conn_rate,
        }
    )


temp_feats = flows_w.groupby(["orig_h", "resp_h", "window"]).apply(calc_temporal).reset_index()
features = group_a.merge(temp_feats, on=["orig_h", "resp_h", "window"], how="left")

# ============================================================
# NHOM C - Dac trung DNS
# ============================================================
print("[4/5] Dang ghep Nhom C (DNS) va Nhom D (TLS/HTTP)...")
dns_path = PROCESSED_DIR / "dns.parquet"
if dns_path.exists():
    dns = pd.read_parquet(dns_path)
    dns = dns.drop(columns=[c for c in ["orig_h", "resp_h", "window"] if c in dns.columns], errors="ignore")
    dns = dns.merge(flows_w[["uid", "orig_h", "resp_h", "window"]], on="uid", how="inner")
    dns["query"] = dns["query"].fillna("").str.lower().str.rstrip(".")
    dns["subdomain"] = dns["query"].apply(subdomain_part)
    dns["qlen"] = dns["query"].str.len()
    dns["entropy"] = dns["subdomain"].apply(shannon_entropy)
    dns["is_nx"] = dns.get("rcode_name", "") == "NXDOMAIN"
    dns["is_txt_null"] = dns.get("qtype_name", "").isin(["TXT", "NULL"])

    dns_grp = dns.groupby(["orig_h", "resp_h", "window"]).agg(
        dns_n_query=("uid", "count"),
        dns_qlen_mean=("qlen", "mean"),
        dns_qlen_max=("qlen", "max"),
        dns_entropy_mean=("entropy", "mean"),
        dns_entropy_max=("entropy", "max"),
        dns_nx_ratio=("is_nx", "mean"),
        dns_n_unique_sub=("query", "nunique"),
        dns_txt_null_ratio=("is_txt_null", "mean"),
    ).reset_index()

    if "TTLs" in dns.columns:
        dns["ttl_first"] = pd.to_numeric(dns["TTLs"].astype(str).str.split(";").str[0], errors="coerce")
        ttl_grp = dns.groupby(["orig_h", "resp_h", "window"])["ttl_first"].mean().rename(
            "dns_ttl_mean"
        ).reset_index()
        dns_grp = dns_grp.merge(ttl_grp, on=["orig_h", "resp_h", "window"], how="left")
    else:
        dns_grp["dns_ttl_mean"] = 0.0

    def dns_iat_cv(g):
        ts_sorted = np.sort(g["ts"].values)
        if len(ts_sorted) < 2:
            return 0.0
        iat = np.diff(ts_sorted)
        return float(iat.std() / iat.mean()) if iat.mean() > 0 else 0.0

    dns_cv = dns.groupby(["orig_h", "resp_h", "window"]).apply(dns_iat_cv).rename("dns_iat_cv").reset_index()
    dns_grp = dns_grp.merge(dns_cv, on=["orig_h", "resp_h", "window"], how="left")
    dns_grp["has_dns"] = 1
    features = features.merge(dns_grp, on=["orig_h", "resp_h", "window"], how="left")
features["has_dns"] = features["has_dns"].fillna(0) if "has_dns" in features.columns else 0

# ============================================================
# NHOM D - Dac trung TLS / HTTP
# ============================================================
ssl_path = PROCESSED_DIR / "ssl.parquet"
if ssl_path.exists():
    ssl = pd.read_parquet(ssl_path)
    ssl = ssl.drop(columns=[c for c in ["orig_h", "resp_h", "window"] if c in ssl.columns], errors="ignore")
    ssl = ssl.merge(flows_w[["uid", "orig_h", "resp_h", "window"]], on="uid", how="inner")
    ssl["sni_missing"] = ssl.get("server_name", pd.Series(dtype=str)).isna() | (
        ssl.get("server_name", "") == ""
    )
    ssl_grp = ssl.groupby(["orig_h", "resp_h", "window"]).agg(
        tls_n_session=("uid", "count"),
        tls_n_sni=("server_name", "nunique"),
        tls_sni_missing_ratio=("sni_missing", "mean"),
        tls_established_ratio=("established", "mean") if "established" in ssl.columns else ("uid", "count"),
        tls_resumed_ratio=("resumed", "mean") if "resumed" in ssl.columns else ("uid", "count"),
        tls_v13_ratio=("version", lambda x: (x == "TLSv13").mean()) if "version" in ssl.columns else ("uid", "count"),
    ).reset_index()
    ssl_grp["has_tls"] = 1
    features = features.merge(ssl_grp, on=["orig_h", "resp_h", "window"], how="left")
features["has_tls"] = features["has_tls"].fillna(0) if "has_tls" in features.columns else 0

http_path = PROCESSED_DIR / "http.parquet"
if http_path.exists():
    http = pd.read_parquet(http_path)
    http = http.drop(columns=[c for c in ["orig_h", "resp_h", "window"] if c in http.columns], errors="ignore")
    http = http.merge(flows_w[["uid", "orig_h", "resp_h", "window"]], on="uid", how="inner")
    http["is_post"] = http.get("method", "") == "POST"
    if "status_code" in http.columns:
        http["is_ok"] = http["status_code"].between(200, 299)
    else:
        http["is_ok"] = False
    http_grp = http.groupby(["orig_h", "resp_h", "window"]).agg(
        http_n_req=("uid", "count"),
        http_post_ratio=("is_post", "mean"),
        http_n_uri=("uri", "nunique") if "uri" in http.columns else ("uid", "count"),
        http_n_ua=("user_agent", "nunique") if "user_agent" in http.columns else ("uid", "count"),
        http_resp_len_mean=("response_body_len", "mean") if "response_body_len" in http.columns else ("uid", "count"),
        http_resp_len_cv=(
            "response_body_len",
            lambda x: (x.std() / x.mean()) if x.mean() else 0.0,
        ) if "response_body_len" in http.columns else ("uid", "count"),
        http_ok_ratio=("is_ok", "mean"),
    ).reset_index()
    http_grp["has_http"] = 1
    features = features.merge(http_grp, on=["orig_h", "resp_h", "window"], how="left")
features["has_http"] = features["has_http"].fillna(0) if "has_http" in features.columns else 0

# ============================================================
print("[5/5] Dang xu ly missing values va luu tep...")
num_cols = features.select_dtypes(include=[np.number]).columns
features[num_cols] = features[num_cols].fillna(0)

for split in ["train", "val", "test"]:
    out = features[features["split"] == split]
    out.to_csv(OUT_DIR / f"{split}.csv", index=False)
    print(f"  {split}: {len(out)} cua so, {int(out['label'].sum())} C2/Suspicious")

print(f"Hoan tat! Dataset dac trung (4 nhom A/B/C/D, cua so truot W={W}s/delta={DELTA}s) luu tai {OUT_DIR}")
