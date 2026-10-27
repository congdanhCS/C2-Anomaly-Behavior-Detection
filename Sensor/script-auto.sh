#!/usr/bin/env bash

cd /home/orca/Desktop || exit 1

for i in 1 2 4 5 6 7 8 11 12 13; do
    SCEN_DIR="/home/orca/Desktop/scenario${i}"
    if [ -d "$SCEN_DIR" ]; then
        echo "=========================================="
        echo "[+] Đang xử lý CTU-13 Scenario ${i}..."
        
        # Tìm file .pcap
        PCAP_FILE=$(ls "$SCEN_DIR"/*.pcap 2>/dev/null | head -n 1)
        
        if [ -n "$PCAP_FILE" ]; then
            # 1. Chạy Zeek
            mkdir -p "$SCEN_DIR/zeek_logs"
            (
                cd "$SCEN_DIR/zeek_logs" || exit 1
                /opt/zeek/bin/zeek -C -r "$PCAP_FILE" local
            )
            echo "[✓] Hoàn tất Zeek log cho scenario${i}"

            # 2. Chạy Suricata
            mkdir -p "$SCEN_DIR/suricata_logs"
            suricata -c /etc/suricata/suricata.yaml -r "$PCAP_FILE" -l "$SCEN_DIR/suricata_logs" -k none
            echo "[✓] Hoàn tất Suricata log cho scenario${i}"
        else
            echo "[!] Không tìm thấy file .pcap trong $SCEN_DIR"
        fi
    else
        echo "[!] Thư mục $SCEN_DIR chưa tồn tại, bỏ qua."
    fi
done
