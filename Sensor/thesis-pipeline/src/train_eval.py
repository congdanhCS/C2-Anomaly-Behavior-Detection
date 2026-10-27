"""
Huan luyen + danh gia 3 phuong phap theo dung thiet ke Chuong 4:
  0. Rule-based baseline (nguong chon tren validation)
  1. Random Forest + ablation A / A+B / A+B+C / A+B+C+D (nguong chon tren validation)
  2. Isolation Forest (chi hoc tren benign, contamination chon tren validation)
Bao cao du Precision/Recall/F1/FPR/PR-AUC/ROC-AUC/latency/CPU-RAM.

Can: pip install scikit-learn psutil
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    precision_score, recall_score, f1_score, confusion_matrix,
    average_precision_score, roc_auc_score,
)
import pickle, time, json
from pathlib import Path

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

FEAT_DIR = Path("data/features")
MODEL_DIR = Path("models")
RESULTS_DIR = Path("results")
MODEL_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

train = pd.read_csv(FEAT_DIR / "train.csv")
val = pd.read_csv(FEAT_DIR / "val.csv")
test = pd.read_csv(FEAT_DIR / "test.csv")

group_A = ["n_conn", "n_dst_port", "n_dst_host", "orig_bytes_mean", "orig_bytes_std",
           "resp_bytes_mean", "resp_bytes_std", "pkts_mean", "duration_mean", "duration_std",
           "bytes_ratio", "fail_ratio", "small_ratio", "size_cv"]
group_B = ["conn_rate", "iat_mean", "iat_std", "iat_median", "iat_cv", "madm_rel",
           "skew_bowley", "frac_near_median", "coverage", "periodicity_score", "low_n"]
group_C = ["dns_n_query", "dns_qlen_mean", "dns_qlen_max", "dns_entropy_mean", "dns_entropy_max",
           "dns_nx_ratio", "dns_n_unique_sub", "dns_txt_null_ratio", "dns_ttl_mean", "dns_iat_cv", "has_dns"]
group_D = ["tls_n_session", "tls_n_sni", "tls_sni_missing_ratio", "tls_established_ratio",
           "tls_resumed_ratio", "tls_v13_ratio", "http_n_req", "http_post_ratio", "http_n_uri",
           "http_n_ua", "http_resp_len_mean", "http_resp_len_cv", "http_ok_ratio", "has_tls", "has_http"]


def existing(cols):
    return [c for c in cols if c in train.columns]


feature_sets, acc = {}, []
for name, grp in [("A", group_A), ("A+B", group_B), ("A+B+C", group_C), ("A+B+C+D", group_D)]:
    acc = acc + grp
    feature_sets[name] = existing(acc)


def resource_snapshot():
    if not HAS_PSUTIL:
        return {"cpu_pct": None, "ram_mb": None}
    return {
        "cpu_pct": psutil.cpu_percent(interval=0.1),
        "ram_mb": round(psutil.Process().memory_info().rss / 1e6, 1),
    }


def evaluate(y_true, y_pred, y_prob=None, name=""):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    multi_class = pd.Series(y_true).nunique() > 1
    pr_auc = average_precision_score(y_true, y_prob) if (y_prob is not None and multi_class) else None
    roc_auc = roc_auc_score(y_true, y_prob) if (y_prob is not None and multi_class) else None
    res = {
        "name": name, "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
        "pr_auc": pr_auc, "roc_auc": roc_auc,
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
    }
    pr_s = "n/a" if pr_auc is None else f"{pr_auc:.3f}"
    roc_s = "n/a" if roc_auc is None else f"{roc_auc:.3f}"
    print(f"[{name}] P:{precision:.3f} R:{recall:.3f} F1:{f1:.3f} FPR:{fpr:.4f} "
          f"PR-AUC:{pr_s} ROC-AUC:{roc_s} | TP{tp} FP{fp} FN{fn} TN{tn}")
    return res


def best_threshold(y_val, prob_val):
    """Chon nguong toi da hoa F1 TREN VALIDATION -- khong bao gio dung tap test o buoc nay."""
    best_t, best_f1 = 0.5, -1.0
    for t in np.linspace(0.05, 0.95, 19):
        f1 = f1_score(y_val, (prob_val >= t).astype(int), zero_division=0)
        if f1 > best_f1:
            best_f1, best_t = f1, t
    return best_t, best_f1


all_results = []

# ----------------------------------------------------------------
print("=== 0. RULE-BASED BASELINE ===")
# C2 neu (periodicity_score cao VA du so ket noi) HOAC (ty le NXDOMAIN cao)
def rule_predict(df, ps_thr, nx_thr):
    has_ps = "periodicity_score" in df.columns
    has_nx = "dns_nx_ratio" in df.columns
    cond_beacon = (df["periodicity_score"] >= ps_thr) & (df["n_conn"] >= 4) & (df["low_n"] == 0) if has_ps else False
    cond_dns = (df["dns_nx_ratio"] >= nx_thr) if has_nx else False
    return (cond_beacon | cond_dns).astype(int)


best_combo, best_f1_rule = (0.7, 0.3), -1.0
for ps_thr in [0.5, 0.6, 0.7, 0.8]:
    for nx_thr in [0.2, 0.3, 0.4, 0.5]:
        f1 = f1_score(val["label"], rule_predict(val, ps_thr, nx_thr), zero_division=0)
        if f1 > best_f1_rule:
            best_f1_rule, best_combo = f1, (ps_thr, nx_thr)
print(f"  Nguong chon tren validation: periodicity_score>={best_combo[0]}, "
      f"dns_nx_ratio>={best_combo[1]} (F1_val={best_f1_rule:.3f})")
pred_test_rule = rule_predict(test, *best_combo)
all_results.append(evaluate(test["label"], pred_test_rule, None, "Rule-based"))

# ----------------------------------------------------------------
print("\n=== 1. RANDOM FOREST - ABLATION STUDY (A -> A+B+C+D) ===")
best_rf, best_rf_threshold, best_rf_f1 = None, 0.5, -1.0
for name, cols in feature_sets.items():
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42)
    rf.fit(train[cols], train["label"])
    fit_resource = resource_snapshot()

    prob_val = rf.predict_proba(val[cols])[:, 1]
    thr, f1_val = best_threshold(val["label"], prob_val)

    t0 = time.time()
    prob_test = rf.predict_proba(test[cols])[:, 1]
    latency_ms = (time.time() - t0) / max(len(test), 1) * 1000
    pred_test = (prob_test >= thr).astype(int)

    print(f"\nCau hinh {name} | nguong={thr:.2f} (F1_val={f1_val:.3f}) | "
          f"do tre suy luan: {latency_ms:.4f} ms/mau | tai nguyen huan luyen: {fit_resource}")
    res = evaluate(test["label"], pred_test, prob_test, f"RF-{name}")
    res.update({"threshold": thr, "latency_ms": latency_ms, "train_resource": fit_resource})
    all_results.append(res)

    if name == "A+B+C+D":
        best_rf, best_rf_threshold, best_rf_f1 = rf, thr, f1_val

# ----------------------------------------------------------------
print("\n=== 2. ISOLATION FOREST (chi hoc tren luu luong benign) ===")
full_cols = feature_sets["A+B+C+D"]
X_train_benign = train[train["label"] == 0][full_cols]

best_if, best_contam, best_if_f1 = None, 0.01, -1.0
for contam in [0.005, 0.01, 0.02, 0.05]:
    iF = IsolationForest(contamination=contam, random_state=42)
    iF.fit(X_train_benign)
    pred_val = np.where(iF.predict(val[full_cols]) == -1, 1, 0)
    f1_val = f1_score(val["label"], pred_val, zero_division=0)
    if f1_val > best_if_f1:
        best_if, best_contam, best_if_f1 = iF, contam, f1_val
print(f"  contamination chon tren validation: {best_contam} (F1_val={best_if_f1:.3f})")

t0 = time.time()
pred_test_if = np.where(best_if.predict(test[full_cols]) == -1, 1, 0)
latency_ms = (time.time() - t0) / max(len(test), 1) * 1000
anomaly_score = -best_if.score_samples(test[full_cols])  # cang cao cang bat thuong
res_if = evaluate(test["label"], pred_test_if, anomaly_score, "Isolation Forest (A+B+C+D)")
res_if["latency_ms"] = latency_ms
all_results.append(res_if)

# ----------------------------------------------------------------
print("\nDang luu mo hinh va ket qua...")
pickle.dump(
    {"model": best_rf, "features": full_cols, "threshold": best_rf_threshold},
    open(MODEL_DIR / "rf_model.pkl", "wb"),
)
pickle.dump({"model": best_if, "features": full_cols}, open(MODEL_DIR / "if_model.pkl", "wb"))
json.dump(all_results, open(RESULTS_DIR / "metrics.json", "w"), indent=2, default=str)
print(f"Hoan tat! Ket qua day du (Precision/Recall/F1/FPR/PR-AUC/ROC-AUC/latency/CPU-RAM) "
      f"luu tai {RESULTS_DIR / 'metrics.json'}")
print("Luu y: dung ket qua tren TEST de bao cao trong khoa luan; "
      "nguong/tham so da duoc chon rieng tren VALIDATION dung theo muc 1.6.")
