import streamlit as st
import pandas as pd
import time
import random
import hashlib
from datetime import datetime
from sklearn.ensemble import IsolationForest
import altair as alt
import pydeck as pdk

# -------------------------------
# CONFIG
# -------------------------------
st.set_page_config(page_title="ThreatWatch", layout="wide")
st.title("ThreatWatch")
st.caption("AI-assisted SOC log anomaly detection and threat scoring.")

# -------------------------------
# SESSION STATE
# -------------------------------
if "logs" not in st.session_state:
    st.session_state.logs = []

# -------------------------------
# LOG GENERATOR
# -------------------------------
def generate_log(mode="normal", intensity: int = 0):
    normal_actions = ["LOGIN_SUCCESS", "FILE_ACCESS"]

    intensity = max(0, min(100, int(intensity)))
    brute_weight = 1 + (intensity // 10)  # 1..11
    data_weight = 1 + (intensity // 12)   # 1..9

    attack_bruteforce = ["LOGIN_FAILED"] * (2 * brute_weight) + ["LOGIN_SUCCESS"]
    attack_data = ["DATA_DOWNLOAD"] * (2 * data_weight) + ["FILE_ACCESS"]

    ips = ["192.168.1.1", "10.0.0.5", "172.16.0.3", "192.168.1.9"]

    if mode == "normal":
        # Intensity controls how often "attack-like" actions appear during normal traffic.
        p_attack = intensity / 100.0
        if random.random() < p_attack:
            action = random.choice(attack_bruteforce + attack_data)
        else:
            action = random.choice(normal_actions)
    elif mode == "brute":
        action = random.choice(attack_bruteforce)
    elif mode == "data":
        action = random.choice(attack_data)

    return {
        "timestamp": datetime.now(),
        "ip": random.choice(ips),
        "action": action
    }


def ip_to_fake_geo(ip: str) -> tuple[float, float]:
    """
    Deterministically maps an IP string to a plausible lat/lon.
    This is intentionally "fake" for demo visualization only.
    """
    h = hashlib.md5(ip.encode("utf-8")).hexdigest()
    a = int(h[:8], 16)
    b = int(h[8:16], 16)
    lat = (a / 0xFFFFFFFF) * 140 - 70     # -70..70 (avoid polar extremes)
    lon = (b / 0xFFFFFFFF) * 360 - 180    # -180..180
    return float(lat), float(lon)

# -------------------------------
# FEATURE ENGINEERING
# -------------------------------
def prepare_features(df):
    df["failed_login"] = df["action"].apply(lambda x: 1 if x == "LOGIN_FAILED" else 0)
    df["download"] = df["action"].apply(lambda x: 1 if x == "DATA_DOWNLOAD" else 0)

    ip_counts = df["ip"].value_counts().to_dict()
    df["ip_freq"] = df["ip"].map(ip_counts)

    return df[["failed_login", "download", "ip_freq"]]

# -------------------------------
# AI ANOMALY DETECTION
# -------------------------------
def detect_ai_anomalies(df):
    if len(df) < 10:
        return [0] * len(df)

    features = prepare_features(df)
    model = IsolationForest(contamination=0.2)
    preds = model.fit_predict(features)

    return preds  # -1 = anomaly, 1 = normal

# -------------------------------
# THREAT SCORING
# -------------------------------
def calculate_threat_scores(df, anomalies):
    scores = {}

    for i, row in df.iterrows():
        ip = row["ip"]

        if ip not in scores:
            scores[ip] = 0

        # Rule-based scoring
        if row["action"] == "LOGIN_FAILED":
            scores[ip] += 10
        if row["action"] == "DATA_DOWNLOAD":
            scores[ip] += 15

        # AI anomaly boost
        if anomalies[i] == -1:
            scores[ip] += 25

    return scores

st.sidebar.header("ThreatWatch Controls")
data_source = st.sidebar.radio("Data source", ["Simulated logs", "Upload CSV"], index=0)

mode = "normal"
intensity = 30
if data_source == "Simulated logs":
    with st.sidebar.expander("Simulation", expanded=True):
        mode = st.selectbox("Traffic mode", ["normal", "brute", "data"])
        intensity = st.slider("Attack intensity", min_value=0, max_value=100, value=30, step=5)
        if st.button("Clear simulated logs"):
            st.session_state.logs = []

uploaded = None
if data_source == "Upload CSV":
    with st.sidebar.expander("Upload", expanded=True):
        uploaded = st.file_uploader(
            "Upload CSV logs",
            type=["csv"],
            help="Expected columns: ip, action, timestamp (timestamp optional)",
        )


# Start/Stop toggle
if "running" not in st.session_state:
    st.session_state.running = False

if data_source == "Simulated logs":
    col1, col2 = st.columns([1, 1])
    if col1.button("Start monitoring", type="primary"):
        st.session_state.running = True
    if col2.button("Stop"):
        st.session_state.running = False


# Real-time simulation (no rerun crash)
if data_source == "Simulated logs" and st.session_state.running:
    log = generate_log(mode, intensity=intensity)
    st.session_state.logs.append(log)

    # keep logs limited (better performance)
    if len(st.session_state.logs) > 100:
        st.session_state.logs = st.session_state.logs[-100:]

    time.sleep(0.5)
    st.rerun()

# -------------------------------
# DISPLAY
# -------------------------------
df = None

if data_source == "Upload CSV" and uploaded is not None:
    try:
        df = pd.read_csv(uploaded)
    except Exception as e:
        st.error(f"Could not read CSV: {e}")
        df = None

    if df is not None:
        df.columns = [c.strip() for c in df.columns]
        required = {"ip", "action"}
        missing = required - set(df.columns)
        if missing:
            st.error(f"Missing required columns: {', '.join(sorted(missing))}")
            df = None
        else:
            if "timestamp" not in df.columns:
                df["timestamp"] = datetime.now()
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df["timestamp"] = df["timestamp"].fillna(pd.Timestamp(datetime.now()))

            df["ip"] = df["ip"].astype(str)
            df["action"] = df["action"].astype(str)

elif st.session_state.logs:
    df = pd.DataFrame(st.session_state.logs)

if df is not None and not df.empty:

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["timestamp"] = df["timestamp"].fillna(pd.Timestamp(datetime.now()))

    anomalies = detect_ai_anomalies(df)
    df["anomaly"] = anomalies

    # -------------------------------
    # LAYOUT
    # -------------------------------
    tab_overview, tab_logs, tab_analytics, tab_intelligence = st.tabs(
        ["Overview", "Logs", "Analytics", "Threat Intelligence"]
    )

    # -------------------------------
    # SHARED DERIVATIONS
    # -------------------------------
    alerts = []
    if (df["action"] == "LOGIN_FAILED").sum() >= 5:
        alerts.append("Potential brute force attack detected (high login failures).")
    if (df["action"] == "DATA_DOWNLOAD").sum() >= 4:
        alerts.append("Possible data exfiltration pattern detected (high downloads).")
    if -1 in anomalies:
        alerts.append("AI anomaly detection flagged suspicious behavior.")

    scores = calculate_threat_scores(df, anomalies)
    score_df = pd.DataFrame(scores.items(), columns=["IP", "Threat Score"]).sort_values(
        by="Threat Score", ascending=False
    )
    top_ip = None if score_df.empty else score_df.iloc[0]

    action_counts = df["action"].value_counts().rename_axis("action").reset_index(name="count")

    # -------------------------------
    # OVERVIEW TAB
    # -------------------------------
    with tab_overview:
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total events", f"{len(df):,}")
        m2.metric("Unique IPs", f"{df['ip'].nunique():,}")
        m3.metric("Anomalies", f"{(df['anomaly'] == -1).sum():,}")
        m4.metric("Top threat score", "—" if top_ip is None else int(top_ip["Threat Score"]))

        st.subheader("Alerts")
        if alerts:
            for a in alerts:
                st.warning(a)
        else:
            st.success("No active alerts based on current rules.")

        st.subheader("Most suspicious IP")
        if top_ip is None:
            st.info("Not enough data yet to rank suspicious IPs.")
        else:
            st.error(f"{top_ip['IP']}  •  Threat score: {int(top_ip['Threat Score'])}")

    # -------------------------------
    # LOGS TAB
    # -------------------------------
    with tab_logs:
        st.subheader("Event log (latest)")
        st.dataframe(
            df.sort_values("timestamp", ascending=False).head(50),
            use_container_width=True,
        )

    # -------------------------------
    # ANALYTICS TAB
    # -------------------------------
    with tab_analytics:
        c1, c2 = st.columns([2, 1])
        with c1:
            st.subheader("Activity over time")
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

            df = df.dropna(subset=["timestamp"])  # remove invalid timestamps

            df = df.sort_values("timestamp")

            activity = df.set_index("timestamp").resample("2s").size().reset_index()
            activity.columns = ["time", "count"]

            st.line_chart(activity.set_index("time"))
        with c2:
            st.subheader("Action breakdown")
            pie = (
                alt.Chart(action_counts)
                .mark_arc(innerRadius=45)
                .encode(
                    theta=alt.Theta(field="count", type="quantitative"),
                    color=alt.Color(field="action", type="nominal", legend=alt.Legend(title="Action")),
                    tooltip=["action:N", "count:Q"],
                )
            )
            st.altair_chart(pie, use_container_width=True)

        st.subheader("Threat scoring by IP")
        st.dataframe(score_df, use_container_width=True)

    # -------------------------------
    # THREAT INTEL TAB (FAKE GEO)
    # -------------------------------
    with tab_intelligence:
        st.subheader("IP geo view (demo)")
        st.caption("Locations are deterministically generated for visualization only.")

        unique_ips = pd.Series(df["ip"].unique(), name="ip")
        geo_rows = []
        for ip in unique_ips:
            lat, lon = ip_to_fake_geo(str(ip))
            threat = int(scores.get(str(ip), 0))
            geo_rows.append({"ip": str(ip), "lat": lat, "lon": lon, "threat": threat})
        geo_df = pd.DataFrame(geo_rows)

        if not geo_df.empty:
            layer = pdk.Layer(
                "ScatterplotLayer",
                data=geo_df,
                get_position="[lon, lat]",
                get_radius="threat * 120 + 800",
                radius_min_pixels=4,
                radius_max_pixels=40,
                get_fill_color="[220, 60, 60, 160]",
                pickable=True,
            )
            view_state = pdk.ViewState(
                latitude=float(geo_df["lat"].mean()),
                longitude=float(geo_df["lon"].mean()),
                zoom=0.8,
                pitch=0,
            )
            deck = pdk.Deck(
                layers=[layer],
                initial_view_state=view_state,
                map_style="mapbox://styles/mapbox/dark-v10",
                tooltip={"text": "IP: {ip}\nThreat: {threat}"},
            )
            st.pydeck_chart(deck, use_container_width=True)

            with st.expander("Show IP → demo geo mapping"):
                st.dataframe(geo_df.sort_values("threat", ascending=False), use_container_width=True)
        else:
            st.info("No IPs available to map yet.")

else:
    if data_source == "Upload CSV" and uploaded is None:
        st.info("Upload a CSV file to analyze logs.")
    else:
        st.info("Click Start Monitoring to simulate logs")