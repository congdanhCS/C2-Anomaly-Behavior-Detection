#!/usr/bin/env python3
"""
build_dataset.py - Tu log Zeek cua tat ca scenario -> Dataset v1 (da lam sach, gan nhan, chia train/val/test).

Cach dung (trong /home/orca/Desktop/thesis-pipeline, da kich hoat venv):
  python3 src/build_dataset.py --list                 # liet ke scenario tim thay + trang thai
  python3 src/build_dataset.py                        # build theo configs/splits.json

Scenario duoc tu dong tim tu:
  - /home/orca/Desktop/scenario3/zeek_logs             -> 'ctu13_s3' (nhan: moi flow co IP 147.32.84.165)
  - /home/orca/Desktop/lab-data/raw/*/meta.json         -> ten lay tu meta['scenario']

Dau ra: data/processed/dataset_v1/{flows,dns,http,ssl}.parquet, flows.csv, manifest.json
        reports/class_distribution.csv
"""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (CONFIG_DIR, CTU13_BOT_IPS, CTU13_C2_TYPES, DESKTOP, INTERIM_DIR,  # noqa: E402
                    PROCESSED_DIR, RAW_DIR, REPORT_DIR)
from labeling import filter_window, label_conn, propagate_label, rule_from_meta  # noqa: E402
from parse_clean import load_zeek_dir  # noqa: E402

SPLITS = ["train", "val", "test"]


def to_epoch(iso):
    return datetime.fromisoformat(iso).timestamp() if iso else None


def discover():
    found = {}
    
    # 1. Quet 12 scenario cua CTU-13 (tru scenario 10)
    ctu_scenarios = [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13]
    for i in ctu_scenarios:
        scen_key = f"ctu13_s{i}"
        scen_dir = DESKTOP / f"scenario{i}"
        zeek_dir = scen_dir / "zeek_logs"
        
        if not scen_dir.is_dir():
            continue
            
        problem = None
        if not (zeek_dir / "conn.log").exists():
            problem = "thieu zeek_logs/conn.log"
            
        bot_ips = CTU13_BOT_IPS.get(scen_key, {"147.32.84.165"})
        # Neu co CTU13_C2_TYPES thi lay loai tuong ung, khong thi mac dinh la ctu13_botnet
        c2_type = globals().get("CTU13_C2_TYPES", {}).get(scen_key, "ctu13_botnet")
        
        found[scen_key] = dict(
            name=scen_key,
            source="ctu13",
            dir=scen_dir,
            zeek_dir=zeek_dir,
            rule={"type": "ip", "ip": bot_ips},
            c2_type=c2_type,
            start=None,
            end=None,
            meta={},
            problem=problem
        )

    # 2. Quet cac scenario tu Lab
    if RAW_DIR.is_dir():
        for d in sorted(RAW_DIR.iterdir()):
            mp = d / "meta.json"
            if not (d.is_dir() and mp.exists()):
                continue
            try:
                meta = json.loads(mp.read_text())
            except json.JSONDecodeError:
                print(f"[CANH BAO] meta.json hong: {mp}")
                continue
            name = meta.get("scenario", d.name)
            if name in found:
                print(f"[CANH BAO] scenario '{name}' bi trung ten, dung ban moi nhat: {d.name}")
            rule, c2_type = rule_from_meta(name, meta)
            problem = None
            if rule is None:
                problem = "thieu label/bot_ip/c2_ip trong meta.json (chay add_meta.py)"
            elif not (d / "zeek_logs" / "conn.log").exists():
                problem = "thieu zeek_logs/conn.log"
            elif not meta.get("end"):
                problem = "meta.json chua co 'end' (stop_capture.sh chua chay xong?)"
            found[name] = dict(name=name, source="lab", dir=d, zeek_dir=d / "zeek_logs", rule=rule,
                               c2_type=c2_type, start=to_epoch(meta.get("start")),
                               end=to_epoch(meta.get("end")), meta=meta, problem=problem)
    return found


def process(sc):
    tables, _ = load_zeek_dir(sc["zeek_dir"])
    conn = filter_window(tables["conn"], sc["start"], sc["end"])
    conn_l = label_conn(conn, sc["rule"])
    out = {"conn": conn_l}
    for n in ["dns", "http", "ssl"]:
        out[n] = propagate_label(tables[n], conn_l)
    for df in out.values():
        df["scenario"] = sc["name"]
        df["source"] = sc["source"]
        df["c2_type"] = sc["c2_type"]
    d = INTERIM_DIR / sc["name"]
    d.mkdir(parents=True, exist_ok=True)
    for n, df in out.items():
        df.to_parquet(d / f"{n}.parquet", index=False)
    return out


def concat(frames):
    frames = [f for f in frames if len(f)]
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def main():
    ap = argparse.ArgumentParser(description="Build Dataset v1")
    ap.add_argument("--list", action="store_true", help="chi liet ke scenario")
    ap.add_argument("--splits", default=str(CONFIG_DIR / "splits.json"))
    args = ap.parse_args()

    found = discover()
    split_path = Path(args.splits)
    splits = json.loads(split_path.read_text()) if split_path.exists() else {}
    assigned = {n: s for s in SPLITS for n in splits.get(s, [])}

    print(f"{'scenario':<18}{'nguon':<7}{'loai':<11}{'split':<7}trang thai")
    for n, sc in found.items():
        print(f"{n:<18}{sc['source']:<7}{str(sc['c2_type']):<11}{assigned.get(n, '-'):<7}"
              f"{sc['problem'] or 'OK'}")
    if args.list:
        return

    if not split_path.exists():
        sys.exit(f"\nChua co {split_path}. Tao file tu configs/splits.example.json va sua ten scenario.")
    dup = [n for n in assigned if sum(n in splits.get(s, []) for s in SPLITS) > 1]
    if dup:
        sys.exit(f"\nLOI: scenario nam o nhieu hon 1 split (data leakage): {dup}")
    missing = [n for n in assigned if n not in found]
    if missing:
        sys.exit(f"\nLOI: splits.json nhac toi scenario khong tim thay: {missing}")
    bad = [n for n in assigned if found[n]["problem"]]
    if bad:
        sys.exit("\nLOI: scenario chua san sang: " + ", ".join(f"{n} ({found[n]['problem']})" for n in bad))
    skipped = [n for n in found if n not in assigned]
    if skipped:
        print(f"\n[CANH BAO] bo qua scenario khong nam trong splits.json: {skipped}")

    parts = {k: [] for k in ["conn", "dns", "http", "ssl"]}
    manifest = []
    for n in assigned:
        sc = found[n]
        out = process(sc)
        c2 = int(out["conn"]["label"].sum())
        print(f"[OK] {n}: {len(out['conn'])} flow, C2/Suspicious={c2}, "
              f"dns={len(out['dns'])} http={len(out['http'])} ssl={len(out['ssl'])}")
        if sc["rule"]["type"] in ("pair", "ip") and c2 == 0:
            print(f"     [CANH BAO] {n} khong co flow C2 nao. Kiem tra bot_ip/c2_ip trong meta.json "
                  f"va xem sensor co thay traffic khong.")
        for k in parts:
            out[k]["split"] = assigned[n]
            parts[k].append(out[k])
        manifest.append({"scenario": n, "split": assigned[n], "source": sc["source"],
                         "c2_type": sc["c2_type"], "flows": len(out["conn"]), "c2_flows": c2,
                         "start": sc["meta"].get("start"), "end": sc["meta"].get("end"),
                         "params": {k: v for k, v in sc["meta"].items()
                                    if k not in ("start", "end", "scenario")}})

    tables = {k: concat(v) for k, v in parts.items()}
    flows = tables["conn"]

    dist = (flows.groupby(["split", "scenario", "source", "c2_type"])["label"]
            .agg(flows="size", c2="sum").reset_index())
    dist["benign"] = dist["flows"] - dist["c2"]
    dist["c2_ratio"] = (dist["c2"] / dist["flows"]).round(4)
    dist["split"] = pd.Categorical(dist["split"], SPLITS, ordered=True)
    dist = dist.sort_values(["split", "scenario"])
    tot = flows.groupby("split")["label"].agg(flows="size", c2="sum")
    tot["benign"] = tot["flows"] - tot["c2"]
    tot["c2_ratio"] = (tot["c2"] / tot["flows"]).round(4)

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    dist.to_csv(REPORT_DIR / "class_distribution.csv", index=False)
    print("\n=== Phan bo lop theo scenario ===")
    print(dist[["split", "scenario", "c2_type", "flows", "benign", "c2", "c2_ratio"]].to_string(index=False))
    print("\n=== Tong theo split ===")
    print(tot.reindex(SPLITS).dropna().to_string())
    for s in SPLITS:
        if s in tot.index and (tot.loc[s, "c2"] == 0 or tot.loc[s, "benign"] == 0):
            print(f"[CANH BAO] split '{s}' chi co 1 lop -> khong danh gia duoc, hay doi scenario giua cac split.")
        elif s not in tot.index:
            print(f"[CANH BAO] split '{s}' rong.")

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    flows.to_parquet(PROCESSED_DIR / "flows.parquet", index=False)
    flows.to_csv(PROCESSED_DIR / "flows.csv", index=False)
    for k in ["dns", "http", "ssl"]:
        if len(tables[k]):
            tables[k].to_parquet(PROCESSED_DIR / f"{k}.parquet", index=False)
    (PROCESSED_DIR / "manifest.json").write_text(
        json.dumps({"built_at": datetime.now().astimezone().isoformat(), "scenarios": manifest},
                   indent=2, ensure_ascii=False))
    print(f"\nDa xuat Dataset v1 -> {PROCESSED_DIR}")


if __name__ == "__main__":
    main()
