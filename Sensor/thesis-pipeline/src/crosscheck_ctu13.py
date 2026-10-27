#!/usr/bin/env python3
"""
crosscheck_ctu13.py - Doi chieu nhan quy tac IP (147.32.84.165) voi nhan goc trong file .binetflow.

  python3 src/crosscheck_ctu13.py
  python3 src/crosscheck_ctu13.py --binetflow /home/orca/Desktop/scenario3/capture20110812.binetflow

Khop flow theo 5-tuple (proto + 2 dau IP:port, khong phan biet chieu), bo qua ICMP.
Luu y: pcap cong khai chi co traffic botnet, file .binetflow co ca Normal/Background,
nen chi mot phan flow cua binetflow xuat hien trong log Zeek.
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CTU3_BOT_IP, CTU3_DIR, REPORT_DIR  # noqa: E402
from labeling import label_conn  # noqa: E402
from parse_clean import load_zeek_dir  # noqa: E402

WANTED = {"proto", "srcaddr", "sport", "dstaddr", "dport", "label"}


def make_key(proto, a_ip, a_port, b_ip, b_port):
    a = a_ip + ":" + a_port.astype(str)
    b = b_ip + ":" + b_port.astype(str)
    lo = a.where(a <= b, b)
    hi = b.where(a <= b, a)
    return proto + "|" + lo + "|" + hi


def simplify(label):
    s = label.fillna("").str.lower()
    return pd.Series(
        ["Botnet" if "botnet" in x else "Normal" if "normal" in x else "Background" for x in s],
        index=label.index)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binetflow", default=str(CTU3_DIR / "capture20110812.binetflow"))
    ap.add_argument("--zeek-dir", default=str(CTU3_DIR / "zeek_logs"))
    args = ap.parse_args()

    tables, _ = load_zeek_dir(args.zeek_dir)
    conn = label_conn(tables["conn"], {"type": "ip", "ip": CTU3_BOT_IP})
    conn = conn[conn["proto"].isin(["tcp", "udp"])].copy()
    conn["key"] = make_key(conn["proto"], conn["orig_h"], conn["orig_p"], conn["resp_h"], conn["resp_p"])
    ips = set(conn["orig_h"]) | set(conn["resp_h"])
    print(f"Zeek: {len(conn)} flow tcp/udp, {len(ips)} IP khac nhau")

    total_labels = pd.Series(dtype="int64")
    kept = []
    for chunk in pd.read_csv(args.binetflow, dtype=str, chunksize=500_000,
                             usecols=lambda c: c.strip().lower() in WANTED, low_memory=False):
        chunk.columns = [c.strip().lower() for c in chunk.columns]
        chunk["simple"] = simplify(chunk["label"])
        total_labels = total_labels.add(chunk["simple"].value_counts(), fill_value=0)
        chunk["proto"] = chunk["proto"].str.lower()
        chunk = chunk[chunk["proto"].isin(["tcp", "udp"]) &
                      chunk["srcaddr"].isin(ips) & chunk["dstaddr"].isin(ips) &
                      chunk["sport"].str.fullmatch(r"\d+", na=False) &
                      chunk["dport"].str.fullmatch(r"\d+", na=False)].copy()
        if len(chunk):
            chunk["key"] = make_key(chunk["proto"], chunk["srcaddr"], chunk["sport"].astype(int),
                                    chunk["dstaddr"], chunk["dport"].astype(int))
            chunk["is_bot"] = (chunk["simple"] == "Botnet").astype(int)
            kept.append(chunk[["key", "is_bot"]])

    print("\nPhan bo nhan trong file .binetflow (toan bo):")
    print(total_labels.astype(int).to_string())
    if not kept:
        sys.exit("\nKhong khop duoc flow nao (kiem tra ten cot / dinh dang file .binetflow).")

    bn = pd.concat(kept).groupby("key")["is_bot"].max().rename("bn_botnet")
    m = conn.merge(bn, left_on="key", right_index=True, how="left")
    matched = m[m["bn_botnet"].notna()].copy()
    print(f"\nKhop duoc {len(matched)}/{len(m)} flow Zeek ({len(matched) / len(m):.1%}) voi .binetflow")
    if len(matched):
        matched["bn_botnet"] = matched["bn_botnet"].astype(int)
        print("\nBang doi chieu (hang: nhan quy tac IP; cot: .binetflow co phai Botnet khong):")
        print(pd.crosstab(matched["label"], matched["bn_botnet"],
                          rownames=["zeek_ip_rule"], colnames=["binetflow_botnet"]).to_string())
        agree = (matched["label"] == matched["bn_botnet"]).mean()
        print(f"\nTy le nhat quan tren flow khop: {agree:.2%}")
        bad = matched[matched["label"] != matched["bn_botnet"]]
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        out = REPORT_DIR / "crosscheck_ctu13_mismatch.csv"
        bad[["ts", "orig_h", "orig_p", "resp_h", "resp_p", "proto", "label", "bn_botnet"]].head(1000).to_csv(out, index=False)
        print(f"{len(bad)} flow khong nhat quan (luu toi da 1000 dong vao {out})")


if __name__ == "__main__":
    main()
