
import os
from datetime import datetime

import mysql.connector
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st


# ============================================================
# 1. PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="API Sentinel | SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# 2. DARK SOC THEME
# ============================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Manrope', sans-serif;
}

.stApp {
    background: #080d16;
    color: #e5edf8;
}

[data-testid="stSidebar"] {
    background: #0d1522;
    border-right: 1px solid #1d2a3d;
}

[data-testid="stHeader"] {
    background: #080d16;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}

div[data-testid="stMetric"] {
    background: linear-gradient(145deg, #111d2d, #0d1725);
    border: 1px solid #203149;
    border-radius: 13px;
    padding: 17px;
}

div[data-testid="stMetricLabel"] {
    color: #8fa2ba;
}

div[data-testid="stMetricValue"] {
    color: #f1f6ff;
}

h1, h2, h3 {
    color: #edf4ff !important;
}

.eyebrow {
    color: #42d6b5;
    font-size: 11px;
    letter-spacing: 2px;
    font-weight: 700;
}

div[data-testid="stDataFrame"] {
    border: 1px solid #203149;
    border-radius: 10px;
}

.stButton button {
    border-radius: 8px;
}
</style>
""", unsafe_allow_html=True)


# ============================================================
# 3. DATABASE CONFIGURATION
# ============================================================

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "api_user"),
    "password": os.getenv(
        "DB_PASSWORD",
        os.getenv("MYSQL_PASSWORD", "api123")
    ),
    "database": os.getenv("DB_NAME", "api_abuse"),
    "connection_timeout": 5,
}


# ============================================================
# 4. DATABASE FUNCTIONS
# ============================================================

@st.cache_data(ttl=5, show_spinner=False)
def load_data():

    connection = mysql.connector.connect(**DB_CONFIG)

    try:
        events = pd.read_sql(
            """
            SELECT *
            FROM processed_events
            ORDER BY event_timestamp DESC
            """,
            connection,
        )

        alerts = pd.read_sql(
            """
            SELECT *
            FROM alerts
            ORDER BY created_at DESC
            """,
            connection,
        )

    finally:
        connection.close()

    if not events.empty:

        events["event_timestamp"] = pd.to_datetime(
            events["event_timestamp"],
            errors="coerce"
        )

        numeric_columns = [
            "status_code",
            "latency_ms",
            "requests_per_10s",
            "failure_ratio",
            "avg_latency_ms",
            "endpoint_diversity",
            "anomaly_score",
        ]

        for col in numeric_columns:
            if col in events.columns:
                events[col] = pd.to_numeric(
                    events[col],
                    errors="coerce"
                )

        for col in ["is_anomaly", "burst_detected"]:
            if col in events.columns:
                events[col] = (
                    pd.to_numeric(
                        events[col],
                        errors="coerce"
                    )
                    .fillna(0)
                    .astype(bool)
                )

    if not alerts.empty:

        alerts["created_at"] = pd.to_datetime(
            alerts["created_at"],
            errors="coerce"
        )

        if "anomaly_score" in alerts.columns:
            alerts["anomaly_score"] = pd.to_numeric(
                alerts["anomaly_score"],
                errors="coerce"
            )

    return events, alerts


# ============================================================
# 5. HELPER FUNCTIONS
# ============================================================

def show_metric(label, value):
    st.metric(label, value)


def style_chart(fig, height=350):

    fig.update_layout(
        template="plotly_dark",
        height=height,
        paper_bgcolor="#0d1725",
        plot_bgcolor="#0d1725",
        font=dict(
            family="Manrope",
            color="#dce6f5"
        ),
        margin=dict(
            l=20,
            r=20,
            t=55,
            b=20
        ),
        hovermode="x unified",
    )

    return fig


def get_suspicious_events(data):

    return data[
        data["is_anomaly"] | data["burst_detected"]
    ].copy()


# ============================================================
# 6. SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown(
        '<div class="eyebrow">SECURITY OPERATIONS CENTER</div>',
        unsafe_allow_html=True
    )

    st.title("🛡️ API SENTINEL")
    st.caption("API Abuse Detection System")

    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "Overview",
            "Live Traffic",
            "Threat Detection",
            "Client Intelligence",
            "API Analytics",
            "Event Logs",
        ],
    )

    st.divider()

    refresh = st.selectbox(
        "Auto Refresh Interval",
        [5, 10, 15, 30, 60],
        index=1,
        format_func=lambda x: f"{x} seconds"
    )

    if st.button("↻ Refresh Now", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.caption("Dashboard refreshes automatically.")


# ============================================================
# 7. DASHBOARD
# ============================================================

@st.fragment(run_every=refresh)
def dashboard():

    # --------------------------------------------------------
    # LOAD DATA
    # --------------------------------------------------------

    try:
        events, alerts = load_data()

    except Exception as error:

        st.error("Unable to connect to MySQL.")
        st.code(str(error))

        st.info(
            "Check Docker, MySQL and your database credentials."
        )

        return

    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------

    st.markdown(
        '<div class="eyebrow">THREAT MONITORING / API TELEMETRY</div>',
        unsafe_allow_html=True
    )

    st.title("Security Operations Center")

    st.caption(
        "Monitor API activity, detect abnormal behaviour "
        "and investigate suspicious clients."
    )

    st.divider()

    if events.empty:
        st.warning("No processed events found.")
        return

    # --------------------------------------------------------
    # VALIDATE DATABASE COLUMNS
    # --------------------------------------------------------

    required_columns = [
        "event_id",
        "event_timestamp",
        "client_id",
        "endpoint",
        "status_code",
        "latency_ms",
        "is_anomaly",
        "burst_detected",
        "anomaly_score",
    ]

    missing = [
        col for col in required_columns
        if col not in events.columns
    ]

    if missing:
        st.error(f"Missing database columns: {missing}")
        return

    # --------------------------------------------------------
    # SYSTEM-WIDE METRICS
    # IMPORTANT: CALCULATED BEFORE FILTERING
    # --------------------------------------------------------

    all_events_count = len(events)

    all_anomalies_count = int(
        events["is_anomaly"].sum()
    )

    all_burst_count = int(
        events["burst_detected"].sum()
    )

    system_anomaly_rate = (
        all_anomalies_count / all_events_count * 100
        if all_events_count else 0
    )

    system_burst_rate = (
        all_burst_count / all_events_count * 100
        if all_events_count else 0
    )

    # --------------------------------------------------------
    # GLOBAL FILTERS
    # --------------------------------------------------------

    clients = sorted(
        events["client_id"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    endpoints = sorted(
        events["endpoint"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    with st.sidebar:

        st.divider()
        st.subheader("Traffic Filters")

        selected_clients = st.multiselect(
            "Client IDs",
            clients
        )

        selected_endpoints = st.multiselect(
            "Endpoints",
            endpoints
        )

        anomaly_only = st.checkbox(
            "Anomalies Only",
            value=False
        )

    filtered = events.copy()

    if selected_clients:
        filtered = filtered[
            filtered["client_id"]
            .astype(str)
            .isin(selected_clients)
        ]

    if selected_endpoints:
        filtered = filtered[
            filtered["endpoint"]
            .astype(str)
            .isin(selected_endpoints)
        ]

    if anomaly_only:
        filtered = filtered[
            filtered["is_anomaly"]
        ]

    if filtered.empty:
        st.warning("No events match your filters.")
        return

    # --------------------------------------------------------
    # FILTERED METRICS
    # --------------------------------------------------------

    total_events = len(filtered)

    anomalies = int(
        filtered["is_anomaly"].sum()
    )

    bursts = int(
        filtered["burst_detected"].sum()
    )

    failed = int(
        (filtered["status_code"] >= 400).sum()
    )

    average_latency = filtered["latency_ms"].mean()

    total_alerts = len(alerts)

    # --------------------------------------------------------
    # CONNECTION STATUS
    # --------------------------------------------------------

    left, right = st.columns(2)

    with left:
        st.markdown(
            '<span style="color:#42d6b5;">● MYSQL CONNECTED</span>',
            unsafe_allow_html=True
        )

    with right:
        st.markdown(
            f'<div style="text-align:right;color:#8192a9;">'
            f'Last updated: {datetime.now().strftime("%d %b %Y · %H:%M:%S")}'
            '</div>',
            unsafe_allow_html=True
        )

    # --------------------------------------------------------
    # KPI CARDS
    # --------------------------------------------------------

    st.subheader("System Overview")

    k1, k2, k3, k4, k5 = st.columns(5)

    with k1:
        show_metric(
            "Requests Analysed",
            f"{total_events:,}"
        )

    with k2:
        show_metric(
            "Anomalies Detected",
            f"{anomalies:,}"
        )

    with k3:
        show_metric(
            "Total Alerts",
            f"{total_alerts:,}"
        )

    with k4:
        show_metric(
            "Failed Requests",
            f"{failed:,}"
        )

    with k5:
        show_metric(
            "Average Latency",
            f"{average_latency:.1f} ms"
            if pd.notna(average_latency)
            else "N/A"
        )

    st.divider()

    # ========================================================
    # PAGE 1: OVERVIEW
    # ========================================================

    if page == "Overview":

        st.subheader("Traffic Overview")

        left, right = st.columns(2)

        # ----------------------------------------------------
        # FIVE-MINUTE TRAFFIC TIMELINE
        # ----------------------------------------------------

        with left:

            st.markdown("### API Traffic Timeline")

            traffic = filtered.dropna(
                subset=["event_timestamp"]
            ).copy()

            if not traffic.empty:

                traffic = traffic.set_index(
                    "event_timestamp"
                ).sort_index()

                timeline = traffic.resample("5min").agg(
                    Total=("event_id", "count"),
                    Anomalies=("is_anomaly", "sum")
                )

                timeline["Normal"] = (
                    timeline["Total"] -
                    timeline["Anomalies"]
                )

                fig = go.Figure()

                fig.add_trace(
                    go.Scatter(
                        x=timeline.index,
                        y=timeline["Total"],
                        name="Total Requests",
                        mode="lines"
                    )
                )

                fig.add_trace(
                    go.Scatter(
                        x=timeline.index,
                        y=timeline["Normal"],
                        name="Normal Requests",
                        mode="lines"
                    )
                )

                fig.add_trace(
                    go.Scatter(
                        x=timeline.index,
                        y=timeline["Anomalies"],
                        name="Anomalous Requests",
                        mode="lines"
                    )
                )

                fig.update_layout(
                    title="API Requests — 5 Minute Intervals",
                    xaxis_title="Time",
                    yaxis_title="Requests"
                )

                st.plotly_chart(
                    style_chart(fig),
                    use_container_width=True
                )

            else:
                st.info("No timestamp data available.")

        # ----------------------------------------------------
        # HTTP STATUS DISTRIBUTION
        # ----------------------------------------------------

        with right:

            st.markdown("### HTTP Response Distribution")

            status = (
                filtered["status_code"]
                .value_counts()
                .rename_axis("Status Code")
                .reset_index(name="Requests")
            )

            fig = px.pie(
                status,
                names="Status Code",
                values="Requests",
                hole=0.55,
                title="HTTP Response Codes"
            )

            st.plotly_chart(
                style_chart(fig),
                use_container_width=True
            )

        # ----------------------------------------------------
        # TOP ENDPOINTS
        # ----------------------------------------------------

        st.subheader("Most Active Endpoints")

        endpoint_data = (
            filtered["endpoint"]
            .value_counts()
            .head(10)
            .rename_axis("Endpoint")
            .reset_index(name="Requests")
        )

        fig = px.bar(
            endpoint_data,
            x="Requests",
            y="Endpoint",
            orientation="h"
        )

        fig.update_layout(
            title="Top 10 API Endpoints",
            yaxis={"categoryorder": "total ascending"}
        )

        st.plotly_chart(
            style_chart(fig),
            use_container_width=True
        )

        # ----------------------------------------------------
        # THREAT SUMMARY
        # SYSTEM-WIDE RATE, NOT FILTERED RATE
        # ----------------------------------------------------

        st.subheader("Threat Summary")

        a, b, c = st.columns(3)

        with a:
            show_metric(
                "System Anomaly Rate",
                f"{system_anomaly_rate:.1f}%"
            )

        with b:
            show_metric(
                "System Burst Events",
                f"{all_burst_count:,}"
            )

        with c:
            show_metric(
                "Unique Clients",
                f"{events['client_id'].nunique():,}"
            )

        st.caption(
            "Threat summary uses all loaded database events, "
            "independent of the sidebar filters."
        )

        st.subheader("Latest Alerts")

        if alerts.empty:
            st.info("No alerts recorded.")

        else:
            st.dataframe(
                alerts.head(10),
                use_container_width=True,
                hide_index=True
            )

    # ========================================================
    # PAGE 2: LIVE TRAFFIC
    # ========================================================

    elif page == "Live Traffic":

        st.subheader("Live API Traffic")

        a, b, c = st.columns(3)

        with a:
            show_metric("Filtered Requests", f"{total_events:,}")

        with b:
            show_metric("Filtered Failed Requests", f"{failed:,}")

        with c:
            show_metric(
                "Average Latency",
                f"{average_latency:.1f} ms"
                if pd.notna(average_latency)
                else "N/A"
            )

        # ----------------------------------------------------
        # REQUESTS PER MINUTE
        # ----------------------------------------------------

        st.markdown("### Requests Per Minute")

        traffic = filtered.dropna(
            subset=["event_timestamp"]
        ).copy()

        if not traffic.empty:

            traffic = traffic.set_index(
                "event_timestamp"
            ).sort_index()

            minute_data = traffic.resample("1min").agg(
                Total=("event_id", "count"),
                Anomalies=("is_anomaly", "sum")
            )

            minute_data["Normal"] = (
                minute_data["Total"] -
                minute_data["Anomalies"]
            )

            fig = go.Figure()

            fig.add_trace(
                go.Scatter(
                    x=minute_data.index,
                    y=minute_data["Total"],
                    name="Total Requests",
                    mode="lines"
                )
            )

            fig.add_trace(
                go.Scatter(
                    x=minute_data.index,
                    y=minute_data["Anomalies"],
                    name="Anomalies",
                    mode="lines"
                )
            )

            fig.add_trace(
                go.Scatter(
                    x=minute_data.index,
                    y=minute_data["Normal"],
                    name="Normal",
                    mode="lines"
                )
            )

            fig.update_layout(
                title="Traffic Timeline",
                xaxis_title="Time",
                yaxis_title="Requests"
            )

            st.plotly_chart(
                style_chart(fig, 400),
                use_container_width=True
            )

        # ----------------------------------------------------
        # STATUS AND ENDPOINTS
        # ----------------------------------------------------

        left, right = st.columns(2)

        with left:

            st.markdown("### HTTP Status Codes")

            status = (
                filtered["status_code"]
                .value_counts()
                .rename_axis("Status")
                .reset_index(name="Requests")
            )

            fig = px.bar(
                status,
                x="Status",
                y="Requests"
            )

            st.plotly_chart(
                style_chart(fig),
                use_container_width=True
            )

        with right:

            st.markdown("### Endpoint Usage")

            endpoint_counts = (
                filtered["endpoint"]
                .value_counts()
                .head(10)
            )

            fig = px.bar(
                endpoint_counts,
                orientation="h"
            )

            st.plotly_chart(
                style_chart(fig),
                use_container_width=True
            )

        # ----------------------------------------------------
        # LATENCY
        # ----------------------------------------------------

        st.markdown("### API Response Latency")

        latency_data = filtered.sort_values(
            "event_timestamp"
        ).tail(500)

        fig = px.line(
            latency_data,
            x="event_timestamp",
            y="latency_ms",
            title="Response Latency Over Time"
        )

        st.plotly_chart(
            style_chart(fig),
            use_container_width=True
        )

    # ========================================================
    # PAGE 3: THREAT DETECTION
    # ========================================================

    elif page == "Threat Detection":

        st.subheader("Threat Detection Centre")

        a, b, c = st.columns(3)

        with a:
            show_metric("Filtered Anomalies", f"{anomalies:,}")

        with b:
            show_metric("Filtered Burst Events", f"{bursts:,}")

        with c:
            show_metric("Total Alert Records", f"{total_alerts:,}")

        suspicious = get_suspicious_events(filtered)

        st.divider()

        st.markdown("### Suspicious Event Queue")

        if suspicious.empty:

            st.success("No suspicious events found.")

        else:

            suspicious = suspicious.sort_values(
                "anomaly_score",
                ascending=False
            )

            display_columns = [
                "event_timestamp",
                "client_id",
                "endpoint",
                "status_code",
                "requests_per_10s",
                "failure_ratio",
                "burst_detected",
                "is_anomaly",
                "anomaly_score",
            ]

            st.dataframe(
                suspicious[display_columns].head(500),
                use_container_width=True,
                hide_index=True
            )

        # ----------------------------------------------------
        # ANOMALY SCORES
        # ----------------------------------------------------

        left, right = st.columns(2)

        with left:

            st.markdown("### Anomaly Score Distribution")

            scores = filtered["anomaly_score"].dropna()

            if not scores.empty:

                fig = px.histogram(
                    scores,
                    nbins=25,
                    title="Anomaly Score Distribution"
                )

                st.plotly_chart(
                    style_chart(fig),
                    use_container_width=True
                )

            else:
                st.info("No anomaly scores available.")

        with right:

            st.markdown("### Alert Types")

            if not alerts.empty:

                alert_types = (
                    alerts["alert_type"]
                    .fillna("Unknown")
                    .value_counts()
                    .rename_axis("Alert Type")
                    .reset_index(name="Count")
                )

                fig = px.pie(
                    alert_types,
                    names="Alert Type",
                    values="Count",
                    hole=0.5
                )

                st.plotly_chart(
                    style_chart(fig),
                    use_container_width=True
                )

            else:
                st.info("No alert records available.")

        # ----------------------------------------------------
        # ALERT HISTORY
        # ----------------------------------------------------

        st.markdown("### Alert History")

        if alerts.empty:
            st.info("No alerts to display.")

        else:
            st.dataframe(
                alerts.head(500),
                use_container_width=True,
                hide_index=True
            )

    # ========================================================
    # PAGE 4: CLIENT INTELLIGENCE
    # ========================================================

    elif page == "Client Intelligence":

        st.subheader("Client Intelligence")

        client_summary = (
            filtered.groupby("client_id", dropna=False)
            .agg(
                Requests=("event_id", "count"),
                Anomalies=("is_anomaly", "sum"),
                Bursts=("burst_detected", "sum"),
                Failed=(
                    "status_code",
                    lambda x: (x >= 400).sum()
                ),
                Average_Latency=("latency_ms", "mean"),
                Average_Failure_Ratio=("failure_ratio", "mean"),
                Average_Anomaly_Score=("anomaly_score", "mean"),
            )
            .reset_index()
            .sort_values(
                ["Anomalies", "Requests"],
                ascending=False
            )
        )

        st.markdown("### Client Activity Ranking")

        st.dataframe(
            client_summary,
            use_container_width=True,
            hide_index=True
        )

        st.divider()

        st.markdown("### Investigate Individual Client")

        available_clients = sorted(
            filtered["client_id"]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

        selected_client = st.selectbox(
            "Select Client ID",
            available_clients
        )

        client_events = filtered[
            filtered["client_id"].astype(str)
            == selected_client
        ].copy()

        a, b, c, d = st.columns(4)

        with a:
            show_metric("Requests", f"{len(client_events):,}")

        with b:
            show_metric(
                "Anomalies",
                f"{int(client_events['is_anomaly'].sum()):,}"
            )

        with c:
            show_metric(
                "Failed Requests",
                f"{int((client_events['status_code'] >= 400).sum()):,}"
            )

        with d:

            latency = client_events["latency_ms"].mean()

            show_metric(
                "Average Latency",
                f"{latency:.1f} ms"
                if pd.notna(latency)
                else "N/A"
            )

        left, right = st.columns(2)

        with left:

            st.markdown("### Endpoint Activity")

            fig = px.bar(
                client_events["endpoint"].value_counts().head(10),
                orientation="h"
            )

            st.plotly_chart(
                style_chart(fig),
                use_container_width=True
            )

        with right:

            st.markdown("### Anomaly Distribution")

            anomaly_counts = pd.Series({
                "Normal": int(
                    (~client_events["is_anomaly"]).sum()
                ),
                "Anomalous": int(
                    client_events["is_anomaly"].sum()
                ),
            })

            fig = px.pie(
                anomaly_counts,
                values=anomaly_counts.values,
                names=anomaly_counts.index,
                hole=0.5
            )

            st.plotly_chart(
                style_chart(fig),
                use_container_width=True
            )

        st.markdown("### Client Event History")

        st.dataframe(
            client_events.sort_values(
                "event_timestamp",
                ascending=False
            ),
            use_container_width=True,
            hide_index=True
        )

    # ========================================================
    # PAGE 5: API ANALYTICS
    # ========================================================

    elif page == "API Analytics":

        st.subheader("API Endpoint Analytics")

        endpoint_summary = (
            filtered.groupby("endpoint", dropna=False)
            .agg(
                Requests=("event_id", "count"),
                Failed=(
                    "status_code",
                    lambda x: (x >= 400).sum()
                ),
                Anomalies=("is_anomaly", "sum"),
                Average_Latency=("latency_ms", "mean"),
                Average_Requests_Per_10s=("requests_per_10s", "mean"),
                Average_Failure_Ratio=("failure_ratio", "mean"),
            )
            .reset_index()
        )

        endpoint_summary["Failure_Percent"] = (
            endpoint_summary["Failed"]
            / endpoint_summary["Requests"].replace(0, pd.NA)
            * 100
        )

        st.markdown("### Endpoint Performance")

        st.dataframe(
            endpoint_summary.sort_values(
                "Requests",
                ascending=False
            ),
            use_container_width=True,
            hide_index=True
        )

        left, right = st.columns(2)

        with left:

            st.markdown("### Most Used Endpoints")

            fig = px.bar(
                endpoint_summary.nlargest(10, "Requests"),
                x="Requests",
                y="endpoint",
                orientation="h"
            )

            st.plotly_chart(
                style_chart(fig),
                use_container_width=True
            )

        with right:

            st.markdown("### Slowest Endpoints")

            slow = endpoint_summary.nlargest(
                10,
                "Average_Latency"
            )

            fig = px.bar(
                slow,
                x="Average_Latency",
                y="endpoint",
                orientation="h"
            )

            st.plotly_chart(
                style_chart(fig),
                use_container_width=True
            )

        st.markdown("### Endpoint Failure Rate")

        fig = px.bar(
            endpoint_summary.sort_values(
                "Failure_Percent",
                ascending=False
            ).head(15),
            x="endpoint",
            y="Failure_Percent"
        )

        st.plotly_chart(
            style_chart(fig),
            use_container_width=True
        )

    # ========================================================
    # PAGE 6: EVENT LOGS
    # ========================================================

    elif page == "Event Logs":

        st.subheader("Event Investigation")

        search = st.text_input(
            "Search Client ID, Endpoint or Event ID"
        )

        logs = filtered.copy()

        if search.strip():

            query = search.strip().lower()

            mask = (
                logs["client_id"]
                .astype(str)
                .str.lower()
                .str.contains(query, na=False)

                |

                logs["endpoint"]
                .astype(str)
                .str.lower()
                .str.contains(query, na=False)

                |

                logs["event_id"]
                .astype(str)
                .str.lower()
                .str.contains(query, na=False)
            )

            logs = logs[mask]

        only_suspicious = st.checkbox(
            "Show only suspicious events"
        )

        if only_suspicious:

            logs = logs[
                logs["is_anomaly"] |
                logs["burst_detected"]
            ]

        st.caption(
            f"{len(logs):,} matching events"
        )

        logs = logs.sort_values(
            "event_timestamp",
            ascending=False
        )

        st.dataframe(
            logs.head(2000),
            use_container_width=True,
            hide_index=True
        )

        csv = logs.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            "⬇ Export Events as CSV",
            data=csv,
            file_name="api_abuse_event_logs.csv",
            mime="text/csv"
        )

    # ========================================================
    # FOOTER
    # ========================================================

    st.divider()

    st.caption(
        "API SENTINEL | API ABUSE DETECTION SYSTEM | MYSQL TELEMETRY"
    )


# ============================================================
# 8. RUN DASHBOARD
# ============================================================

dashboard()
