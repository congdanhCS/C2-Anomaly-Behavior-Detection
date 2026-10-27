# -*- coding: utf-8 -*-
import json
from pathlib import Path
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

# ==============================================================================
# CẤU HÌNH TRANG & GIAO DIỆN
# ==============================================================================
st.set_page_config(
    page_title="SO-VT C2 Hunting Console | SME NSM",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .stApp { background-color: #0b0f19; color: #e2e8f0; }
    section[data-testid="stSidebar"] { background-color: #111827; border-right: 1px solid #1f2937; }
    
    .soc-card {
        background: linear-gradient(145deg, #111827, #162032);
        border: 1px solid #1f2937;
        border-left: 4px solid #3b82f6;
        border-radius: 10px;
        padding: 16px 20px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.35);
        margin-bottom: 12px;
    }
    .soc-card-crit { border-left-color: #ef4444; }
    .soc-card-high { border-left-color: #f97316; }
    .soc-card-susp { border-left-color: #eab308; }
    .soc-card-ok   { border-left-color: #10b981; }
    
    .soc-title { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.08em; color: #94a3b8; margin-bottom: 4px; }
    .soc-value { font-size: 1.75rem; font-weight: 700; color: #f8fafc; font-family: 'JetBrains Mono', monospace; }
    .soc-sub   { font-size: 0.80rem; color: #64748b; margin-top: 4px; }

    /* Badge mức độ rủi ro kiểu */
    .vt-badge {
        display: inline-block; padding: 3px 10px; border-radius: 999px;
        font-size: 0.76rem; font-weight: 700; letter-spacing: 0.04em;
    }
    .badge-crit { background: rgba(239,68,68,0.18); color: #f87171; border: 1px solid #ef4444; }
    .badge-high { background: rgba(249,115,22,0.18); color: #fb923c; border: 1px solid #f97316; }
    .badge-susp { background: rgba(234,179,8,0.18);  color: #facc15; border: 1px solid #eab308; }
    .badge-norm { background: rgba(16,185,129,0.18); color: #34d399; border: 1px solid #10b981; }

    .xai-box {
        background-color: #111827;
        border: 1px solid #283548;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 10px;
    }
    
    /* Tùy chỉnh thanh Tabs trên cùng */
    button[data-baseweb="tab"] {
        font-size: 0.95rem !important;
        font-weight: 600 !important;
        padding: 10px 18px !important;
    }
</style>
""", unsafe_allow_html=True)

RESULTS_PATH = Path("results/metrics.json")
TEST_FEAT_PATH = Path("data/features/test.csv")
DB_PATH = Path("data/alerts.db")
API_URL = "http://localhost:8000/alerts"

# ==============================================================================
# HÀM TẢI DỮ LIỆU 
# ==============================================================================
@st.cache_data(ttl=15)
def load_alerts(min_score: int = 0):
    try:
        resp = requests.get(API_URL, params={"min_score": min_score, "limit": 0}, timeout=8)
        if resp.status_code == 200:
            df = pd.DataFrame(resp.json())
        else:
            df = pd.DataFrame()
    except Exception:
        df = pd.DataFrame()

    if (df.empty or len(df) == 200) and DB_PATH.exists():
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT id, ts, orig_h, resp_h, scenario, risk_score, severity, reason "
            "FROM alerts WHERE risk_score >= ? ORDER BY risk_score DESC, id DESC",
            conn,
            params=(min_score,),
        )
        conn.close()

    if not df.empty:
        # Loại bỏ trùng lặp nếu chạy push_alerts.py nhiều lần
        dedup_cols = [c for c in ["orig_h", "resp_h", "scenario", "risk_score", "reason"] if c in df.columns]
        df["raw_count"] = len(df)
        df["source_type"] = np.where(df["scenario"].astype(str).str.startswith("ctu13"), "CTU-13 Botnet", "SME Lab")

        # Tách thông số từ chuỗi reason: "n_conn=10, periodicity_score=0.66, dns_nx_ratio=40%"
        df["n_conn_val"] = df["reason"].str.extract(r"n_conn=([\d\.]+)").astype(float).fillna(0)
        df["ps_val"] = df["reason"].str.extract(r"periodicity(?:_score)?=([\d\.]+)").astype(float).fillna(0)
        df["nx_val"] = df["reason"].str.extract(r"nx_ratio=([\d\.]+)").astype(float).fillna(0)
    return df

@st.cache_data(ttl=30)
def load_metrics():
    if RESULTS_PATH.exists():
        with open(RESULTS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

@st.cache_data(ttl=60)
def load_test_features():
    if TEST_FEAT_PATH.exists():
        return pd.read_csv(TEST_FEAT_PATH)
    return pd.DataFrame()

# ==============================================================================
# SIDEBAR MENU & BỘ LỌC TOÀN CỤC (SECURITY ONION STYLE)
# ==============================================================================
with st.sidebar:
    st.markdown("## 🛡️ **SO-VT C2 HUNTER**")
    st.caption("Network Behavior Anomaly Detection Console (Zeek + ML Engine)")
    st.divider()

    st.markdown("### 🎛️ Bộ lọc Giám sát")
    min_score_filter = st.slider("Ngưỡng Risk Score tối thiểu", 0, 100, 30, help="Mặc định >= 30 (Suspicious trở lên)")
    dedup_toggle = st.checkbox("Gộp các bản ghi trùng khi push nhiều lần", value=False)

    alerts_raw = load_alerts(min_score=min_score_filter)
    if not alerts_raw.empty and dedup_toggle:
        alerts_df = alerts_raw.drop_duplicates(subset=["orig_h", "resp_h", "scenario", "risk_score", "reason"]).copy()
    else:
        alerts_df = alerts_raw.copy()

    all_scenarios = sorted(alerts_df["scenario"].dropna().unique().tolist()) if not alerts_df.empty else []
    selected_scenarios = st.multiselect("Kịch bản (Scenario)", options=all_scenarios, default=all_scenarios)

    all_severities = ["Critical", "High", "Suspicious", "Normal"]
    selected_severities = st.multiselect(
        "Mức độ cảnh báo (Severity)",
        options=all_severities,
        default=[s for s in all_severities if not alerts_df.empty and s in alerts_df["severity"].unique()],
    )

    ip_search = st.text_input("🔍 Tra cứu IP Nguồn / Đích (IOC Search)", placeholder="VD: 147.32.84.165 hoặc 192.168.10.12")

    if st.button("🔄 Làm mới dữ liệu (Refresh)", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.divider()
    st.markdown("### 📌 Thông tin Sensor")
    st.code(
        "Sensor  : sensor-pc (Ubuntu)\n"
        "Engine  : Zeek + Random Forest\n"
        "Window  : W=300s, Δ=60s\n"
        "Dataset : CTU-13 (12 Scen) + Lab",
        language="yaml",
    )

# Áp dụng bộ lọc
if not alerts_df.empty:
    if selected_scenarios:
        alerts_df = alerts_df[alerts_df["scenario"].isin(selected_scenarios)]
    if selected_severities:
        alerts_df = alerts_df[alerts_df["severity"].isin(selected_severities)]
    if ip_search.strip():
        q = ip_search.strip()
        alerts_df = alerts_df[
            alerts_df["orig_h"].astype(str).str.contains(q, case=False)
            | alerts_df["resp_h"].astype(str).str.contains(q, case=False)
        ]

metrics_list = load_metrics()
test_df = load_test_features()

# Header
st.markdown(
    "<h2 style='margin-bottom:0;'>🛡️ Hệ thống Giám sát & Phân tích Hành vi C2</h2>",
    unsafe_allow_html=True,
)

# ==============================================================================
# THANH MENU 5 TAB ĐỘC LẬP
# ==============================================================================
tab_risk, tab_eval, tab_c2, tab_fp, tab_xai = st.tabs([
    "Tổng quan Risk Score",
    "Đánh giá Mô hình (TP/FP/FN/TN)",
    "Phát hiện Giao tiếp C2",
    "Nghi ngờ Cảnh báo Giả (FP Triage)",
    "Giải thích Cảnh báo",
])

# ==============================================================================
# TAB 1: TỔNG QUAN RISK SCORE 
# ==============================================================================
with tab_risk:
    if alerts_df.empty:
        st.warning("Chưa có cảnh báo nào khớp bộ lọc. Hãy giảm ngưỡng Risk Score hoặc chạy lại push_alerts.py.")
    else:
        total_alerts = len(alerts_df)
        crit_cnt = int((alerts_df["severity"] == "Critical").sum())
        high_cnt = int((alerts_df["severity"] == "High").sum())
        susp_cnt = int((alerts_df["severity"] == "Suspicious").sum())
        avg_risk = float(alerts_df["risk_score"].mean())
        unique_pairs = alerts_df.groupby(["orig_h", "resp_h"]).ngroups

        # 4 thẻ KPI hàng đầu
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(f"""
            <div class="soc-card soc-card-crit">
                <div class="soc-title">Tổng số Cảnh báo C2 (Không giới hạn)</div>
                <div class="soc-value">{total_alerts:,}</div>
                <div class="soc-sub">Trên {unique_pairs:,} cặp (Host Nguồn ↔ Đích)</div>
            </div>""", unsafe_allow_html=True)
        with c2:
            st.markdown(f"""
            <div class="soc-card soc-card-crit">
                <div class="soc-title">🔴 Mức Critical (Risk ≥ 80)</div>
                <div class="soc-value">{crit_cnt:,}</div>
                <div class="soc-sub">Chiếm {(crit_cnt/total_alerts*100):.1f}% tổng cảnh báo</div>
            </div>""", unsafe_allow_html=True)
        with c3:
            st.markdown(f"""
            <div class="soc-card soc-card-high">
                <div class="soc-title">🟠 Mức High (Risk 60 – 79)</div>
                <div class="soc-value">{high_cnt:,}</div>
                <div class="soc-sub">Chiếm {(high_cnt/total_alerts*100):.1f}% tổng cảnh báo</div>
            </div>""", unsafe_allow_html=True)
        with c4:
            st.markdown(f"""
            <div class="soc-card soc-card-susp">
                <div class="soc-title">🟡 Mức Suspicious (Risk 30 – 59)</div>
                <div class="soc-value">{susp_cnt:,}</div>
                <div class="soc-sub">Điểm Risk trung bình: {avg_risk:.1f}/100</div>
            </div>""", unsafe_allow_html=True)

        col_gauge, col_dist, col_scen = st.columns([1.1, 1.2, 1.4])

        with col_gauge:
            # Đồng hồ đo Risk Score phong cách VirusTotal Community Score
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=avg_risk,
                number={"suffix": " / 100", "font": {"size": 34, "color": "#f8fafc"}},
                title={"text": "<b>Điểm Rủi Ro Trung Bình (VT Style)</b>", "font": {"size": 15, "color": "#cbd5e1"}},
                gauge={
                    "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#64748b"},
                    "bar": {"color": "#ef4444" if avg_risk >= 80 else "#f97316" if avg_risk >= 60 else "#eab308"},
                    "bgcolor": "#111827",
                    "borderwidth": 1,
                    "bordercolor": "#1f2937",
                    "steps": [
                        {"range": [0, 30], "color": "rgba(16, 185, 129, 0.25)"},
                        {"range": [30, 60], "color": "rgba(234, 179, 8, 0.25)"},
                        {"range": [60, 80], "color": "rgba(249, 115, 22, 0.25)"},
                        {"range": [80, 100], "color": "rgba(239, 68, 68, 0.30)"},
                    ],
                },
            ))
            fig_gauge.update_layout(height=300, margin=dict(l=20, r=20, t=50, b=20), paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_gauge, use_container_width=True)

        with col_dist:
            sev_counts = alerts_df["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            color_map = {"Critical": "#ef4444", "High": "#f97316", "Suspicious": "#eab308", "Normal": "#10b981"}
            fig_pie = px.pie(
                sev_counts, values="Count", names="Severity", hole=0.58,
                color="Severity", color_discrete_map=color_map,
                title="<b>Phân bố Mức độ Nghiêm trọng (Severity)</b>"
            )
            fig_pie.update_layout(height=300, margin=dict(l=10, r=10, t=50, b=10), paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
            st.plotly_chart(fig_pie, use_container_width=True)

        with col_scen:
            scen_counts = alerts_df.groupby(["scenario", "severity"]).size().reset_index(name="count")
            fig_bar = px.bar(
                scen_counts, x="count", y="scenario", color="severity", orientation="h",
                color_discrete_map=color_map,
                title="<b>Số lượng Cảnh báo theo Kịch bản (CTU-13 & Lab)</b>",
                labels={"count": "Số cửa sổ cảnh báo", "scenario": "Scenario"}
            )
            fig_bar.update_layout(height=300, margin=dict(l=10, r=10, t=50, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
            st.plotly_chart(fig_bar, use_container_width=True)

        st.markdown("#### 📊 Phân bố Điểm Rủi Ro (Risk Score 0 – 100) & Top Cặp Giao tiếp Đáng ngờ")
        c_hist, c_top = st.columns([1.2, 1.3])
        with c_hist:
            fig_hist = px.histogram(
                alerts_df, x="risk_score", nbins=25, color="severity",
                color_discrete_map=color_map,
                title="Phổ phân bố Risk Score trên toàn bộ Cảnh báo",
                labels={"risk_score": "Risk Score (0-100)", "count": "Số lượng cửa sổ"}
            )
            fig_hist.update_layout(height=320, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
            st.plotly_chart(fig_hist, use_container_width=True)

        with c_top:
            top_pairs = (
                alerts_df.groupby(["orig_h", "resp_h", "scenario"])
                .agg(
                    So_Canh_Bao=("id", "count"),
                    Risk_Max=("risk_score", "max"),
                    Risk_TB=("risk_score", "mean"),
                    Chu_Ky_TB=("ps_val", "mean"),
                )
                .reset_index()
                .sort_values(["Risk_Max", "So_Canh_Bao"], ascending=False)
                .head(15)
            )
            top_pairs["Risk_TB"] = top_pairs["Risk_TB"].round(1)
            top_pairs["Chu_Ky_TB"] = top_pairs["Chu_Ky_TB"].round(2)
            st.dataframe(top_pairs, use_container_width=True, height=320)

# ==============================================================================
# TAB 2: ĐÁNH GIÁ MÔ HÌNH TRỰC QUAN (TP, FP, FN, TN, PRECISION, RECALL, F1, FPR)
# ==============================================================================
with tab_eval:
    st.markdown("### 📊 Đánh giá Thực nghiệm & Ma trận Nhầm lẫn (Confusion Matrix: TP, FP, FN, TN)")
    if not metrics_list:
        st.error("Không tìm thấy tệp metrics.json. Hãy chạy train_eval.py trước.")
    else:
        m_df = pd.DataFrame(metrics_list)
        model_names = m_df["name"].tolist()
        default_idx = model_names.index("RF-A+B+C+D") if "RF-A+B+C+D" in model_names else 0

        col_sel, col_info = st.columns([1.2, 2.8])
        with col_sel:
            chosen_model_name = st.selectbox("Chọn Cấu hình / Mô hình để mổ xẻ:", model_names, index=default_idx)
        row_m = m_df[m_df["name"] == chosen_model_name].iloc[0]

        tp, fp, fn, tn = int(row_m["tp"]), int(row_m["fp"]), int(row_m["fn"]), int(row_m["tn"])
        prec, rec, f1_val, fpr_val = float(row_m["precision"]), float(row_m["recall"]), float(row_m["f1"]), float(row_m["fpr"])
        pr_auc = float(row_m["pr_auc"]) if row_m.get("pr_auc") not in [None, "None"] else 0.0
        roc_auc = float(row_m["roc_auc"]) if row_m.get("roc_auc") not in [None, "None"] else 0.0

        with col_info:
            st.info(
                f"**Mô hình đang chọn:** `{chosen_model_name}` | "
                f"**Tổng mẫu kiểm thử (Test Windows):** `{tp+fp+fn+tn:,}` cửa sổ "
                f"(`{tp+fn:,}` C2/Suspicious thực tế và `{tn+fp:,}` Benign thực tế)."
            )

        # 4 Thẻ TP, FP, FN, TN trực quan
        k1, k2, k3, k4 = st.columns(4)
        with k1:
            st.markdown(f"""
            <div class="soc-card soc-card-ok">
                <div class="soc-title">✅ True Positive (TP - Bắt đúng C2)</div>
                <div class="soc-value">{tp:,}</div>
                <div class="soc-sub">Tỷ lệ phát hiện (Recall): {rec*100:.2f}%</div>
            </div>""", unsafe_allow_html=True)
        with k2:
            st.markdown(f"""
            <div class="soc-card soc-card-crit">
                <div class="soc-title">🚨 False Positive (FP - Cảnh báo giả)</div>
                <div class="soc-value">{fp:,}</div>
                <div class="soc-sub">Tỷ lệ cảnh báo giả (FPR): {fpr_val*100:.2f}%</div>
            </div>""", unsafe_allow_html=True)
        with k3:
            st.markdown(f"""
            <div class="soc-card soc-card-high">
                <div class="soc-title">⚠️ False Negative (FN - Bỏ lọt C2)</div>
                <div class="soc-value">{fn:,}</div>
                <div class="soc-sub">Tỷ lệ bỏ sót (FNR): {(1-rec)*100:.2f}%</div>
            </div>""", unsafe_allow_html=True)
        with k4:
            st.markdown(f"""
            <div class="soc-card">
                <div class="soc-title">🛡️ True Negative (TN - Sạch đúng)</div>
                <div class="soc-value">{tn:,}</div>
                <div class="soc-sub">Độ đặc hiệu (Specificity): {(1-fpr_val)*100:.2f}%</div>
            </div>""", unsafe_allow_html=True)

        # Hàng chỉ số tổng hợp Precision, Recall, F1, PR-AUC, ROC-AUC, Latency
        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("Precision", f"{prec:.4f}")
        m2.metric("Recall (TPR)", f"{rec:.4f}")
        m3.metric("F1-Score", f"{f1_val:.4f}")
        m4.metric("FPR", f"{fpr_val*100:.2f}%")
        m5.metric("PR-AUC", f"{pr_auc:.4f}" if pr_auc else "N/A")
        lat_str = f"{float(row_m['latency_ms']):.4f} ms" if row_m.get("latency_ms") not in [None, "None"] else "< 0.01 ms"
        m6.metric("Độ trễ / mẫu", lat_str)

        c_cm, c_comp = st.columns([1.1, 1.4])
        with c_cm:
            # Vẽ Ma trận nhầm lẫn (Confusion Matrix Heatmap)
            z = [[tn, fp], [fn, tp]]
            text = [
                [f"<b>TN</b><br>{tn:,}<br>({tn/(tn+fp)*100:.1f}% Benign)", f"<b>FP (Cảnh báo giả)</b><br>{fp:,}<br>({fp/(tn+fp)*100:.2f}% Benign)"],
                [f"<b>FN (Bỏ lọt)</b><br>{fn:,}<br>({fn/(tp+fn)*100:.1f}% C2)", f"<b>TP (Bắt đúng C2)</b><br>{tp:,}<br>({tp/(tp+fn)*100:.1f}% C2)"]
            ]
            fig_cm = go.Figure(data=go.Heatmap(
                z=z,
                x=["Dự đoán: Benign (0)", "Dự đoán: C2/Suspicious (1)"],
                y=["Thực tế: Benign (0)", "Thực tế: C2/Suspicious (1)"],
                text=text,
                texttemplate="%{text}",
                colorscale="Blues",
                showscale=False,
            ))
            fig_cm.update_layout(
                title=f"<b>Ma trận Nhầm lẫn – {chosen_model_name}</b>",
                height=370,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0",
                yaxis=dict(autorange="reversed"),
            )
            st.plotly_chart(fig_cm, use_container_width=True)

        with c_comp:
            # Biểu đồ so sánh toàn bộ các phương pháp & Ablation Study (RQ1 & RQ2)
            melt_df = m_df.melt(
                id_vars=["name"],
                value_vars=["precision", "recall", "f1", "fpr"],
                var_name="Metric",
                value_name="Score",
            )
            melt_df["Metric"] = melt_df["Metric"].str.upper()
            fig_comp = px.bar(
                melt_df, x="name", y="Score", color="Metric", barmode="group",
                text_auto=".3f",
                title="<b>So sánh Hiệu năng giữa các Phương pháp & Ablation Study (RQ1, RQ2)</b>",
                labels={"name": "Cấu hình Mô hình", "Score": "Giá trị (0.0 – 1.0)"}
            )
            fig_comp.update_layout(height=370, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
            st.plotly_chart(fig_comp, use_container_width=True)

        st.markdown("#### 📋 Bảng Tổng hợp Toàn bộ Chỉ số Thực nghiệm (Trích xuất từ `results/metrics.json`)")
        disp_cols = ["name", "precision", "recall", "f1", "fpr", "pr_auc", "roc_auc", "tp", "fp", "fn", "tn", "threshold", "latency_ms"]
        disp_cols = [c for c in disp_cols if c in m_df.columns]
        st.dataframe(m_df[disp_cols], use_container_width=True)

# ==============================================================================
# TAB 3: PHÁT HIỆN GIAO TIẾP HÀNH VI C2 
# ==============================================================================
with tab_c2:
    st.markdown("### 🚨 Danh sách Phát hiện Giao tiếp có Hành vi Command & Control")
    if alerts_df.empty:
        st.info("Không có giao tiếp C2 nào thỏa mãn bộ lọc hiện tại.")
    else:
        col_a, col_b, col_c = st.columns([1.5, 1.2, 1.3])
        with col_a:
            st.success(f"Đang hiển thị **{len(alerts_df):,}** giao tiếp C2...")
        with col_b:
            page_size = st.selectbox("Số dòng mỗi trang:", [100, 500, 2000, 10000, len(alerts_df)], index=1)
        with col_c:
            total_pages = max(1, int(np.ceil(len(alerts_df) / page_size)))
            page_num = st.number_input(f"Trang (1 – {total_pages}):", min_value=1, max_value=total_pages, value=1, step=1)

        start_idx = (page_num - 1) * page_size
        end_idx = start_idx + page_size
        view_df = alerts_df.iloc[start_idx:end_idx].copy()

        st.dataframe(
            view_df[["id", "ts", "orig_h", "resp_h", "severity", "risk_score", "scenario", "source_type", "reason"]],
            column_config={
                "risk_score": st.column_config.ProgressColumn(
                    "Risk Score (0-100)",
                    help="Điểm rủi ro dự đoán từ Random Forest Detection Engine",
                    format="%d / 100",
                    min_value=0,
                    max_value=100,
                ),
                "orig_h": "IP Nguồn (Host nội bộ)",
                "resp_h": "IP Đích (C2 / External)",
                "severity": "Mức độ (Severity)",
                "scenario": "Kịch bản (Scenario)",
                "source_type": "Nguồn dữ liệu",
                "reason": "Chỉ báo hành vi (Telemetry Indicators)",
            },
            use_container_width=True,
            height=520,
        )

        # Nút tải xuống toàn bộ CSV
        csv_bytes = alerts_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label=f"⬇️ Tải xuống toàn bộ {len(alerts_df):,} cảnh báo C2 (.CSV)",
            data=csv_bytes,
            file_name="all_c2_alerts_export.csv",
            mime="text/csv",
        )

# ==============================================================================
# TAB 4: NGHI NGỜ CẢNH BÁO GIẢ (FALSE POSITIVE TRIAGE QUEUE)
# ==============================================================================
with tab_fp:
    st.markdown("### ⚠️ Trang Phân tích & Sàng lọc Nghi ngờ Cảnh báo Giả (False Positive Triage)")
    st.caption(
        "Giúp chuyên viên SOC nhanh chóng khoanh vùng các cảnh báo có khả năng là **Cảnh báo giả (False Positive)** "
        "do lưu lượng hợp lệ có tính định kỳ ngẫu nhiên, số lượng kết nối thấp (`n_conn < 4`), hoặc có điểm rủi ro nằm ở vùng biên."
    )

    if alerts_df.empty:
        st.info("Chưa có dữ liệu cảnh báo để phân tích.")
    else:
        f_col1, f_col2, f_col3 = st.columns(3)
        with f_col1:
            fp_max_score = st.slider("Ngưỡng trần Risk Score vùng nghi ngờ FP:", 30, 95, 85)
        with f_col2:
            include_low_conn = st.checkbox("Bao gồm cửa sổ có ít kết nối (n_conn < 4, thiếu mẫu chu kỳ)", value=True)
        with f_col3:
            include_benign_scen = st.checkbox("Bao gồm cảnh báo rơi vào scenario Benign / nền Lab", value=True)

        # Logic lọc các cảnh báo nghi ngờ là False Positive (Suspected FP)
        cond_borderline = (alerts_df["risk_score"] >= 30) & (alerts_df["risk_score"] <= fp_max_score)
        cond_low_evidence = (alerts_df["n_conn_val"] < 4) & (alerts_df["ps_val"] < 0.35) & (alerts_df["nx_val"] == 0)
        cond_benign = alerts_df["scenario"].astype(str).str.contains("benign", case=False)

        fp_mask = cond_borderline
        if include_low_conn:
            fp_mask = fp_mask | cond_low_evidence
        if include_benign_scen:
            fp_mask = fp_mask | cond_benign

        suspected_fp_df = alerts_df[fp_mask].copy()

        # Phân loại nguyên nhân nghi ngờ FP
        def classify_fp_reason(row):
            reasons = []
            if "benign" in str(row["scenario"]).lower():
                reasons.append("Thuộc kịch bản lưu lượng sạch (Benign Scenario)")
            if row["risk_score"] < 80:
                reasons.append(f"Risk Score vùng biên ({row['risk_score']}/100 < ngưỡng quyết định 95)")
            if row["n_conn_val"] < 4:
                reasons.append(f"Số kết nối thấp (n_conn={int(row['n_conn_val'])} < 4, cờ low_n=1)")
            if row["ps_val"] < 0.25 and row["nx_val"] == 0:
                reasons.append("Không có dấu hiệu Beaconing và NXDOMAIN=0%")
            return " | ".join(reasons) if reasons else "Cần chuyên viên SOC xác minh thêm"

        if not suspected_fp_df.empty:
            suspected_fp_df["Ly_Do_Nghi_Ngo_FP"] = suspected_fp_df.apply(classify_fp_reason, axis=1)

        # Đối chiếu trực tiếp với Ground Truth trong test.csv nếu có
        true_benign_alerts = 0
        if not test_df.empty and "label" in test_df.columns:
            benign_pairs = set(
                zip(
                    test_df[test_df["label"] == 0]["orig_h"],
                    test_df[test_df["label"] == 0]["resp_h"],
                    test_df[test_df["label"] == 0]["scenario"],
                )
            )
            suspected_fp_df["Ground_Truth_Check"] = suspected_fp_df.apply(
                lambda r: "False Positive Thật (Nhãn gốc: Benign)"
                if (r["orig_h"], r["resp_h"], r["scenario"]) in benign_pairs
                else "Cần thẩm định (Borderline / Low-evidence C2)",
                axis=1,
            )
            true_benign_alerts = int((suspected_fp_df["Ground_Truth_Check"].str.startswith("False Positive Thật")).sum())

        fp_c1, fp_c2, fp_c3 = st.columns(3)
        fp_c1.metric("Tổng Cảnh báo nằm trong diện Nghi ngờ FP", f"{len(suspected_fp_df):,}")
        fp_c2.metric("Cảnh báo vùng biên (30 ≤ Risk < 80)", f"{int((alerts_df['risk_score'] < 80).sum()):,}")
        fp_c3.metric("Khớp nhãn Benign trong Ground Truth", f"{true_benign_alerts:,}")

        if suspected_fp_df.empty:
            st.success("Không phát hiện cảnh báo nào có dấu hiệu Cảnh báo giả với tiêu chí hiện tại!")
        else:
            cols_show = ["id", "ts", "orig_h", "resp_h", "scenario", "severity", "risk_score", "reason", "Ly_Do_Nghi_Ngo_FP"]
            if "Ground_Truth_Check" in suspected_fp_df.columns:
                cols_show.append("Ground_Truth_Check")
            st.dataframe(suspected_fp_df[cols_show].head(2000), use_container_width=True, height=440)

# ==============================================================================
# TAB 5: NƠI GHI LÝ DO CẢNH BÁO & PHÂN TÍCH XAI
# ==============================================================================
with tab_xai:
    st.markdown("### 🔎 Giải thích Lý do Cảnh báo (Explainable AI – XAI & Behavioral Telemetry)")
    st.caption(
        "Mỗi cảnh báo đi kèm lý do kích hoạt cụ thể (Số kết nối `n_conn`, Điểm chu kỳ `periodicity_score`, "
        "Tỷ lệ tên miền lỗi `dns_nx_ratio`) và ánh xạ kỹ thuật MITRE ATT&CK TA0011."
    )

    if alerts_df.empty:
        st.info("Không có cảnh báo để hiển thị giải thích.")
    else:
        # Bộ chọn cặp Host Nguồn -> Đích để soi chi tiết kiểu VirusTotal Relations/Behavior
        pair_options = (
            alerts_df.groupby(["orig_h", "resp_h", "scenario"])
            .agg(count=("id", "count"), max_risk=("risk_score", "max"))
            .reset_index()
            .sort_values(["max_risk", "count"], ascending=False)
        )
        pair_options["label_str"] = (
            pair_options["orig_h"] + " ➔ " + pair_options["resp_h"]
            + "  [" + pair_options["scenario"] + " | "
            + pair_options["count"].astype(str) + " alerts | Max Risk: "
            + pair_options["max_risk"].astype(str) + "]"
        )

        selected_pair_str = st.selectbox("🎯 Chọn Cặp Giao tiếp (Host Nội bộ ➔ Máy chủ Đích) để xem Hồ sơ Giải thích:", pair_options["label_str"].tolist())
        sel_row = pair_options[pair_options["label_str"] == selected_pair_str].iloc[0]
        sub_alerts = alerts_df[
            (alerts_df["orig_h"] == sel_row["orig_h"])
            & (alerts_df["resp_h"] == sel_row["resp_h"])
            & (alerts_df["scenario"] == sel_row["scenario"])
        ].copy()

        # Suy luận kỹ thuật MITRE ATT&CK từ kịch bản & chỉ báo
        scen_name = str(sel_row["scenario"]).lower()
        if "dns" in scen_name or sub_alerts["nx_val"].mean() >= 20:
            mitre_tech = "T1071.004 (Application Layer Protocol: DNS) / T1568.002 (DGA)"
        elif "https" in scen_name:
            mitre_tech = "T1071.001 (Web Protocols) + T1573 (Encrypted Channel TLS)"
        elif "http" in scen_name:
            mitre_tech = "T1071.001 (Application Layer Protocol: Web Protocols - HTTP)"
        elif "p2p" in scen_name or "s6" in scen_name or "s8" in scen_name or "s12" in scen_name:
            mitre_tech = "TA0011 (Decentralized P2P Botnet C2 Communication)"
        else:
            mitre_tech = "T1095 (Non-Application Layer Protocol / Custom TCP-UDP Beaconing)"

        # Khung tóm tắt kiểu VirusTotal Detection Summary
        st.markdown(f"""
        <div class="soc-card soc-card-crit">
            <h4 style="margin:0; color:#f8fafc;">📌 Hồ sơ Cặp Giao tiếp: <code>{sel_row['orig_h']}</code> ➔ <code>{sel_row['resp_h']}</code></h4>
            <p style="margin:6px 0 0 0; color:#cbd5e1;">
                <b>Kịch bản:</b> <code>{sel_row['scenario']}</code> &nbsp;|&nbsp;
                <b>Số cửa sổ phát hiện:</b> <code>{len(sub_alerts):,}</code> &nbsp;|&nbsp;
                <b>Risk Score cao nhất:</b> <code>{int(sel_row['max_risk'])}/100</code> &nbsp;|&nbsp;
                <b>Ánh xạ MITRE ATT&CK:</b> <code>{mitre_tech}</code>
            </p>
        </div>
        """, unsafe_allow_html=True)

        # Hiển thị danh sách thẻ giải thích chi tiết từng cửa sổ
        num_explain = st.slider("Số lượng bản ghi giải thích chi tiết hiển thị:", 5, 100, 20)
        for _, r in sub_alerts.head(num_explain).iterrows():
            sev = r["severity"]
            badge_cls = "badge-crit" if sev == "Critical" else "badge-high" if sev == "High" else "badge-susp" if sev == "Suspicious" else "badge-norm"
            
            # Diễn giải ngôn ngữ tự nhiên từ thông số kỹ thuật
            human_reasons = []
            if r["n_conn_val"] >= 4:
                human_reasons.append(f"Tần suất lặp kết nối cao trong cửa sổ 300s (<b>{int(r['n_conn_val'])} kết nối</b>)")
            else:
                human_reasons.append(f"Số lượng kết nối trong cửa sổ: <b>{int(r['n_conn_val'])} kết nối</b> (kết hợp đặc trưng hình dạng Flow/Host)")
            
            if r["ps_val"] >= 0.60:
                human_reasons.append(f"Tính chu kỳ Beaconing rất rõ rệt (<b>Periodicity Score = {r['ps_val']:.2f}</b>)")
            elif r["ps_val"] > 0:
                human_reasons.append(f"Có dấu hiệu giãn cách thời gian có quy luật (<b>Periodicity Score = {r['ps_val']:.2f}</b>)")
                
            if r["nx_val"] > 0:
                human_reasons.append(f"Phát hiện truy vấn tên miền không tồn tại bất thường (<b>NXDOMAIN Ratio = {r['nx_val']:.0f}%</b>)")

            st.markdown(f"""
            <div class="xai-box">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="vt-badge {badge_cls}">{sev.upper()} • RISK {r['risk_score']}/100</span>
                        <strong style="margin-left:10px; color:#f8fafc;">{r['orig_h']} ➔ {r['resp_h']}</strong>
                        <span style="color:#94a3b8; font-size:0.85rem; margin-left:8px;">(Scenario: {r['scenario']})</span>
                    </div>
                    <div style="color:#64748b; font-size:0.82rem;">🕒 {r['ts']}</div>
                </div>
                <div style="margin-top:8px; color:#cbd5e1; font-size:0.92rem;">
                    • <b>Thông số Telemetry gốc:</b> <code>{r['reason']}</code><br>
                    • <b>Diễn giải Hành vi (XAI):</b> {"; ".join(human_reasons)}.
                </div>
            </div>
            """, unsafe_allow_html=True)