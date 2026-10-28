**🛡️ Hệ thống Phát hiện Lưu lượng Command-and-Control (C2) dựa trên Bất thường Hành vi Mạng (SME NSM)
📁 1. Cấu trúc Thư mục Dự án
Toàn bộ pipeline xử lý dữ liệu và mô hình được đặt trên máy **Sensor VM** (`192.168.10.10`, user `orca`):

/home/orca/Desktop/
├── lab-data/
│   └── raw/                        # Chứa dữ liệu capture trực tiếp từ Lab (PCAP, Zeek, Suricata, meta.json)
├── lab-scripts/
│   ├── start_capture.sh            # Script bắt đầu thu thập traffic theo scenario
│   └── stop_capture.sh             # Script dừng thu thập và gom log Zeek/Suricata
├── scenario1/ ... scenario13/      # Các thư mục chứa PCAP, .binetflow và zeek_logs của bộ CTU-13
└── thesis-pipeline/                # Thư mục mã nguồn chính của hệ thống
    ├── configs/
    │   └── splits.json             # Cấu hình phân chia tập Train / Val / Test theo Scenario
    ├── data/
    │   ├── processed/dataset_v1/   # Dữ liệu log đã làm sạch và gán nhãn (.parquet)
    │   ├── features/               # Vector đặc trưng 4 nhóm A, B, C, D (train.csv, val.csv, test.csv)
    │   └── alerts.db               # Cơ sở dữ liệu SQLite lưu trữ cảnh báo
    ├── models/
    │   └── rf_model.pkl            # Mô hình Random Forest tốt nhất đã huấn luyện
    ├── results/
    │   └── metrics.json            # Kết quả thực nghiệm (TP, FP, FN, TN, F1, PR-AUC, Latency...)
    └── src/
        ├── build_dataset.py        # Parse log Zeek, làm sạch, gán nhãn và chia tập
        ├── crosscheck_ctu13.py     # Đối chiếu chéo nhãn với file .binetflow của CTU-13
        ├── extract_features.py     # Trích xuất 4 nhóm đặc trưng trên cửa sổ trượt (W=300s, step=60s)
        ├── train_eval.py           # Huấn luyện mô hình & thực hiện Ablation Study
        ├── alert_api.py            # REST API (FastAPI) nhận và truy vấn cảnh báo
        ├── push_alerts.py          # Chấm điểm Risk Score (0-100) và đẩy cảnh báo vào API
        └── dashboard.py            # Giao diện giám sát SOC (Streamlit)
        
2. Yêu cầu Hệ thống & Cài đặt Môi trườngThực hiện
python3 -m venv venv
source venv/bin/activate

Cài đặt các thư viện cần thiết
pip install pandas numpy pyarrow scikit-learn tldextract fastapi uvicorn pydantic requests streamlit plotly psutil

