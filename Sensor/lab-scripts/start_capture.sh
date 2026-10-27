#!/bin/bash
set -e
IFACE="ens34"
BASE="/home/orca/Desktop/lab-data/raw"
SCENARIO="${1:test}"
TS=$(date +%Y%m%d_%H%M%S)
OUTDIR="$BASE/${TS}_${SCENARIO}"
mkdir -p "$OUTDIR"

cat > "$OUTDIR/meta.json" <<EOF
{"scenario": "$SCENARIO", "iface": "$IFACE", "start": "$(date -Iseconds)"}
EOF

nohup tcpdump -i "$IFACE" -nn -U -w "$OUTDIR/capture.pcap" > "$OUTDIR/tcpdump.out" 2>&1 &
echo $! > "$OUTDIR/tcpdump.pid"
echo "$OUTDIR" > /tmp/current_capture_dir

sleep 1
echo "Đang capture scenario '$SCENARIO' -> $OUTDIR"
