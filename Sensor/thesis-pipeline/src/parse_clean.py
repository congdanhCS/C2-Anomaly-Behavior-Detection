#!/usr/bin/env python3
"""
parse_clean.py - Parse + lam sach log Zeek (conn, dns, http, ssl) thanh DataFrame chuan.

Dung nhanh de kiem tra 1 thu muc log:
  python3 src/parse_clean.py /home/orca/Desktop/scenario3/zeek_logs
  python3 src/parse_clean.py /home/orca/Desktop/scenario3/zeek_logs --save ctu13_s3_raw

Quy tac lam sach (ghi vao khoa luan):
  1. Doi gia tri thieu cua Zeek ('-', '(empty)', '') thanh missing; JSON bo qua truong thieu -> them cot rong.
  2. Ep kieu: so (ts, port, bytes, pkts, duration), boolean (T/F), chuoi.
  3. Bo ban ghi thieu khoa (ts, uid, IP, port, proto), bo uid trung, chi giu proto tcp/udp/icmp (conn).
  4. Dien missing: bytes/pkts -> 0, duration -> 0.0, service -> 'none', history -> '', conn_state -> 'UNK'.
  5. Cot dang list (answers, TTLs, ...) doi thanh chuoi noi bang ';'.
  6. Them ts_dt (UTC), sap xep theo ts.
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import INTERIM_DIR, read_zeek_log  # noqa: E402

ID_MAP = {"id.orig_h": "orig_h", "id.orig_p": "orig_p", "id.resp_h": "resp_h", "id.resp_p": "resp_p"}

CONN_COLS = ["ts", "uid", "orig_h", "orig_p", "resp_h", "resp_p", "proto", "service", "duration",
             "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes",
             "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]
DNS_COLS = ["ts", "uid", "orig_h", "orig_p", "resp_h", "resp_p", "proto", "trans_id", "rtt", "query",
            "qclass_name", "qtype_name", "rcode", "rcode_name", "AA", "TC", "RD", "RA", "Z",
            "answers", "TTLs", "rejected"]
HTTP_COLS = ["ts", "uid", "orig_h", "orig_p", "resp_h", "resp_p", "trans_depth", "method", "host", "uri",
             "referrer", "version", "user_agent", "request_body_len", "response_body_len",
             "status_code", "status_msg", "resp_mime_types"]
SSL_COLS = ["ts", "uid", "orig_h", "orig_p", "resp_h", "resp_p", "version", "cipher", "curve",
            "server_name", "resumed", "established", "ssl_history", "next_protocol", "ja3", "ja3s"]


def to_bool(s):
    m = {True: True, False: False, "T": True, "F": False, "true": True, "false": False}
    return s.map(lambda v: m.get(v, pd.NA)).astype("boolean")


def join_lists(df):
    for c in df.columns:
        if df[c].map(lambda x: isinstance(x, (list, tuple))).any():
            df[c] = df[c].map(lambda x: ";".join(map(str, x)) if isinstance(x, (list, tuple)) else x)
    return df


def _prep(raw, cols):
    df = raw.rename(columns=ID_MAP).copy()
    df = join_lists(df)
    df = df.mask(df.isin(["-", "(empty)", ""]))
    return df.reindex(columns=cols)


def clean_conn(raw):
    rep = {"rows_in": len(raw)}
    df = _prep(raw, CONN_COLS)
    num = ["ts", "orig_p", "resp_p", "duration", "orig_bytes", "resp_bytes", "missed_bytes",
           "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]
    for c in num:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    rep["missing_before_fill"] = {c: int(df[c].isna().sum())
                                  for c in ["duration", "orig_bytes", "resp_bytes", "service", "history"]}
    n = len(df)
    df = df.dropna(subset=["ts", "uid", "orig_h", "orig_p", "resp_h", "resp_p", "proto"])
    rep["dropped_null_key"] = n - len(df)
    n = len(df)
    df = df.drop_duplicates(subset="uid")
    rep["dropped_duplicate_uid"] = n - len(df)
    df["proto"] = df["proto"].astype(str).str.lower()
    n = len(df)
    df = df[df["proto"].isin(["tcp", "udp", "icmp"])].copy()
    rep["dropped_other_proto"] = n - len(df)
    for c in ["orig_bytes", "resp_bytes", "missed_bytes", "orig_pkts", "orig_ip_bytes",
              "resp_pkts", "resp_ip_bytes"]:
        df[c] = df[c].fillna(0).astype("int64")
    df["duration"] = df["duration"].fillna(0.0).astype("float64")
    df["orig_p"] = df["orig_p"].astype("int64")
    df["resp_p"] = df["resp_p"].astype("int64")
    df["service"] = df["service"].fillna("none").astype(str)
    df["history"] = df["history"].fillna("").astype(str)
    df["conn_state"] = df["conn_state"].fillna("UNK").astype(str)
    for c in ["local_orig", "local_resp"]:
        df[c] = to_bool(df[c])
    df["ts_dt"] = pd.to_datetime(df["ts"], unit="s", utc=True)
    df = df.sort_values("ts").reset_index(drop=True)
    rep["rows_out"] = len(df)
    return df, rep


def _clean_generic(raw, cols, num=(), boolean=(), text=(), dedupe=None):
    rep = {"rows_in": len(raw)}
    df = _prep(raw, cols)
    for c in num:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    n = len(df)
    df = df.dropna(subset=["ts", "uid", "orig_h", "resp_h"])
    rep["dropped_null_key"] = n - len(df)
    if dedupe:
        n = len(df)
        df = df.drop_duplicates(subset=dedupe)
        rep["dropped_duplicates"] = n - len(df)
    df = df.copy()
    for c in text:
        df[c] = df[c].fillna("").astype(str)
    for c in boolean:
        df[c] = to_bool(df[c])
    for c in ("orig_p", "resp_p"):
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype("int64")
    df["ts_dt"] = pd.to_datetime(df["ts"], unit="s", utc=True)
    df = df.sort_values("ts").reset_index(drop=True)
    rep["rows_out"] = len(df)
    return df, rep


def clean_dns(raw):
    df, rep = _clean_generic(
        raw, DNS_COLS,
        num=["ts", "trans_id", "rtt", "rcode", "Z"],
        boolean=["AA", "TC", "RD", "RA", "rejected"],
        text=["query", "qclass_name", "qtype_name", "rcode_name", "answers", "TTLs"],
        dedupe=["uid", "trans_id", "query", "qtype_name"])
    df["query"] = df["query"].str.lower().str.rstrip(".")
    return df, rep


def clean_http(raw):
    return _clean_generic(
        raw, HTTP_COLS,
        num=["ts", "trans_depth", "request_body_len", "response_body_len", "status_code"],
        text=["method", "host", "uri", "referrer", "version", "user_agent", "status_msg", "resp_mime_types"],
        dedupe=["uid", "trans_depth", "ts"])


def clean_ssl(raw):
    return _clean_generic(
        raw, SSL_COLS,
        num=["ts"],
        boolean=["resumed", "established"],
        text=["version", "cipher", "curve", "server_name", "ssl_history", "next_protocol", "ja3", "ja3s"],
        dedupe=["uid", "ts"])


def load_zeek_dir(zeek_dir):
    """Doc + lam sach 4 loai log trong 1 thu muc. Tra ve (dict DataFrame, dict bao cao)."""
    zeek_dir = Path(zeek_dir)
    if not zeek_dir.is_dir():
        raise FileNotFoundError(f"Khong thay thu muc log: {zeek_dir}")
    tables, reports = {}, {}
    for name, fn in [("conn", clean_conn), ("dns", clean_dns), ("http", clean_http), ("ssl", clean_ssl)]:
        tables[name], reports[name] = fn(read_zeek_log(zeek_dir / f"{name}.log"))
    if tables["conn"].empty:
        raise ValueError(f"conn.log trong hoac thieu o {zeek_dir}. Kiem tra lai buoc chay Zeek.")
    return tables, reports


def main():
    ap = argparse.ArgumentParser(description="Parse + lam sach log Zeek")
    ap.add_argument("zeek_dir")
    ap.add_argument("--save", help="ten thu muc luu parquet trong data/interim/")
    args = ap.parse_args()
    tables, reports = load_zeek_dir(args.zeek_dir)
    for name in ["conn", "dns", "http", "ssl"]:
        df, rep = tables[name], reports[name]
        print(f"\n=== {name}.log ===")
        print({k: v for k, v in rep.items()})
        if len(df):
            print(f"khoang thoi gian: {df['ts_dt'].min()}  ->  {df['ts_dt'].max()}")
            print(df.head(3).to_string(max_colwidth=30))
    if args.save:
        out = INTERIM_DIR / args.save
        out.mkdir(parents=True, exist_ok=True)
        for name, df in tables.items():
            df.to_parquet(out / f"{name}.parquet", index=False)
        print(f"\nDa luu parquet vao {out}")


if __name__ == "__main__":
    main()
