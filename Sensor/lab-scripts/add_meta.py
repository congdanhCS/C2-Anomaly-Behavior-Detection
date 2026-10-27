#!/usr/bin/env python3
"""
add_meta.py - Them tham so scenario vao meta.json cua lan capture gan nhat (chay tren SENSOR).

Dung:
  python3 add_meta.py label=c2 mode=http interval=30 jitter=0.1 bot_ip=192.168.10.12 c2_ip=192.168.10.13
  python3 add_meta.py --dir /home/orca/Desktop/lab-data/raw/20261015_101010_c2_http_01 label=c2 ...

Chay SAU stop_capture.sh (luc do meta.json da thuoc quyen user orca).
Khong co --dir thi dung thu muc ghi trong /tmp/current_capture_dir.
"""
import json
import sys
from pathlib import Path


def main():
    argv = sys.argv[1:]
    outdir = None
    if argv[:1] == ["--dir"]:
        if len(argv) < 2:
            sys.exit("Thieu duong dan sau --dir")
        outdir, argv = Path(argv[1]), argv[2:]
    if outdir is None:
        cur = Path("/tmp/current_capture_dir")
        if not cur.exists():
            sys.exit("Khong tim thay /tmp/current_capture_dir, hay dung --dir <thu_muc_scenario>")
        outdir = Path(cur.read_text().strip())
    meta_path = outdir / "meta.json"
    if not meta_path.exists():
        sys.exit(f"Khong thay {meta_path}")
    if not argv:
        sys.exit("Thieu cap key=value")

    meta = json.loads(meta_path.read_text())
    for item in argv:
        if "=" not in item:
            sys.exit(f"Sai dinh dang '{item}', can key=value")
        k, v = item.split("=", 1)
        try:
            v = json.loads(v)  # so -> so, true/false -> bool, con lai giu chuoi
        except json.JSONDecodeError:
            pass
        meta[k] = v
    try:
        meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False))
    except PermissionError:
        sys.exit(f"Khong ghi duoc {meta_path}. Chay stop_capture.sh truoc, hoac dung sudo.")
    print(f"Da cap nhat {meta_path}")
    print(json.dumps(meta, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
