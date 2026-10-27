#!/bin/bash
set -e
OUTDIR=$(cat /tmp/current_capture_dir)
PID=$(cat "$OUTDIR/tcpdump.pid")
OWNER="${SUDO_USER:-orca}"

# 1. Stop tcpdump
kill -INT "$PID" 2>/dev/null || true
sleep 2

# 2. Ghi timestamp ket thúc vao meta.json
python3 - "$OUTDIR" <<'PY'
import json, sys, datetime
p = f"{sys.argv[1]}/meta.json"
meta = json.load(open(p))
meta["end"] = datetime.datetime.now().astimezone().isoformat()
json.dump(meta, open(p, "w"), indent=2)
PY

# 3. Zeek offline tren pcap cua scenario nay
mkdir -p "$OUTDIR/zeek_logs"
cd "$OUTDIR/zeek_logs"
/opt/zeek/bin/zeek -C -r ../capture.pcap local

# 4. Suricata offline tren pcap cua scenario nay
mkdir -p "$OUTDIR/suricata_logs"
suricata -c /etc/suricata/suricata.yaml -r "$OUTDIR/capture.pcap" -l "$OUTDIR/suricata_logs" -k none

# 5. Tra quyen so huu cho user orca
chown -R "$OWNER:$OWNER" "$OUTDIR"

echo "Da luu day du: $OUTDIR"
ls -la "$OUTDIR"
