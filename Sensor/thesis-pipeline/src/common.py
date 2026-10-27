"""common.py - duong dan, hang so va ham doc log Zeek (JSON hoac TSV)."""
import json
import os
from pathlib import Path

import pandas as pd

HOME = Path.home()
DESKTOP = HOME / "Desktop"
PIPE_ROOT = Path(__file__).resolve().parent.parent

# Co the ghi de bang bien moi truong (dung khi test)
RAW_DIR = Path(os.environ.get("LAB_RAW_DIR", DESKTOP / "lab-data" / "raw"))
CTU3_DIR = Path(os.environ.get("CTU3_DIR", DESKTOP / "scenario3"))
CTU3_BOT_IP = "147.32.84.165"  # may nhiem Rbot theo README cua scenario 3
CTU13_BOT_IPS = {
    "ctu13_s1":  {"147.32.84.165"},
    "ctu13_s2":  {"147.32.84.165"},
    "ctu13_s3":  {"147.32.84.165"},
    "ctu13_s4":  {"147.32.84.165"},
    "ctu13_s5":  {"147.32.84.165"},
    "ctu13_s6":  {"147.32.84.165"},
    "ctu13_s7":  {"147.32.84.165"},
    "ctu13_s8":  {"147.32.84.165"},
    "ctu13_s9":  {"147.32.84.165", "147.32.84.191", "147.32.84.192", "147.32.84.193",
                  "147.32.84.204", "147.32.84.205", "147.32.84.206", "147.32.84.207",
                  "147.32.84.208", "147.32.84.209"},
    "ctu13_s11": {"147.32.84.165", "147.32.84.191", "147.32.84.192"},
    "ctu13_s12": {"147.32.84.165", "147.32.84.191", "147.32.84.192"},
    "ctu13_s13": {"147.32.84.165"},
}

CTU13_C2_TYPES = {
    "ctu13_s1":  "irc_http_neris",
    "ctu13_s2":  "irc_http_neris",
    "ctu13_s3":  "irc_scan_rbot",
    "ctu13_s4":  "irc_ddos_rbot",
    "ctu13_s5":  "smtp_http_virut",
    "ctu13_s6":  "p2p_menti",
    "ctu13_s7":  "http_sogou",
    "ctu13_s8":  "p2p_murlo",
    "ctu13_s9":  "irc_http_neris",
    "ctu13_s11": "irc_ddos_rbot",
    "ctu13_s12": "p2p_nsis",
    "ctu13_s13": "http_virut",
}

INTERIM_DIR = PIPE_ROOT / "data" / "interim"
PROCESSED_DIR = PIPE_ROOT / "data" / "processed" / "dataset_v1"
REPORT_DIR = PIPE_ROOT / "reports"
CONFIG_DIR = PIPE_ROOT / "configs"


def _read_tsv(lines):
    fields, rows = None, []
    for line in lines:
        line = line.rstrip("\n")
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif line.startswith("#") or not line:
            continue
        else:
            rows.append(line.split("\t"))
    if fields is None:
        return pd.DataFrame()
    return pd.DataFrame(rows, columns=fields)


def read_zeek_log(path):
    """Doc 1 file log Zeek, tu nhan dang JSON-lines hoac TSV. File khong ton tai/rong -> DataFrame rong."""
    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    first = next((l for l in lines if l.strip()), "")
    if first.startswith("{"):
        records = []
        for l in lines:
            l = l.strip()
            if l.startswith("{"):
                try:
                    records.append(json.loads(l))
                except json.JSONDecodeError:
                    pass  # dong hong cuoi file: bo qua
        return pd.DataFrame(records)
    return _read_tsv(lines)
