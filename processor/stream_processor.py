
import json
import os
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

import joblib
import mysql.connector
from kafka import KafkaConsumer


# =========================================================
# CONFIGURATION
# =========================================================

TOPIC = "api-requests"
BOOTSTRAP_SERVERS = ["localhost:9092"]
CONSUMER_GROUP = "api-stream-processor-db"

WINDOW_SECONDS = 10
BURST_THRESHOLD = 15
MIN_EVENTS_FOR_ML = 5

MODEL_PATH = Path("ml/isolation_forest.joblib")

DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "api_user",
    "password": os.getenv("MYSQL_PASSWORD", "api123"),
    "database": "api_abuse",
}


# =========================================================
# LOAD MACHINE LEARNING MODEL
# =========================================================

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Model not found: {MODEL_PATH}. "
        "Run python ml/train_model.py first."
    )

model = joblib.load(MODEL_PATH)

# Maintain separate rolling event windows for each client.
client_events = defaultdict(deque)


# =========================================================
# MYSQL CONNECTION
# =========================================================

def connect_database():
    connection = mysql.connector.connect(**DB_CONFIG)
    print("Connected to MySQL: api_abuse", flush=True)
    return connection


# =========================================================
# SAVE EVENTS AND ALERTS
# =========================================================

def save_event(connection, event, metrics):
    """Save processed events and generate anomaly alerts."""

    timestamp = datetime.fromisoformat(
        event["timestamp"].replace("Z", "+00:00")
    ).astimezone(timezone.utc).replace(tzinfo=None)

    values = (
        str(event["event_id"]),
        timestamp,
        str(event["client_id"]),
        str(event["endpoint"]),
        int(event["status_code"]),
        float(event["latency_ms"]),
        int(metrics["requests"]),
        float(metrics["failure_ratio"]),
        float(metrics["avg_latency"]),
        int(metrics["endpoint_diversity"]),
        bool(metrics["burst"]),
        bool(metrics["anomaly"]),
        float(metrics["score"]),
    )

    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO processed_events (
                event_id,
                event_timestamp,
                client_id,
                endpoint,
                status_code,
                latency_ms,
                requests_per_10s,
                failure_ratio,
                avg_latency_ms,
                endpoint_diversity,
                burst_detected,
                is_anomaly,
                anomaly_score
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s
            )
            ON DUPLICATE KEY UPDATE
                requests_per_10s = VALUES(requests_per_10s),
                failure_ratio = VALUES(failure_ratio),
                avg_latency_ms = VALUES(avg_latency_ms),
                endpoint_diversity = VALUES(endpoint_diversity),
                burst_detected = VALUES(burst_detected),
                is_anomaly = VALUES(is_anomaly),
                anomaly_score = VALUES(anomaly_score)
            """,
            values,
        )

        # Generate an alert if either detection method flags traffic.
        if metrics["anomaly"]:

            if metrics["ml_anomaly"] and metrics["burst"]:
                alert_type = "HYBRID_DETECTION"

            elif metrics["ml_anomaly"]:
                alert_type = "ISOLATION_FOREST"

            else:
                alert_type = "BURST_DETECTION"

            details = json.dumps({
                "endpoint": str(event["endpoint"]),
                "status_code": int(event["status_code"]),
                "requests_per_10s": int(metrics["requests"]),
                "failure_ratio": float(metrics["failure_ratio"]),
                "avg_latency_ms": float(metrics["avg_latency"]),
                "endpoint_diversity": int(
                    metrics["endpoint_diversity"]
                ),
                "ml_anomaly": bool(metrics["ml_anomaly"]),
                "burst_detected": bool(metrics["burst"]),
            })

            cursor.execute(
                """
                INSERT INTO alerts (
                    event_id,
                    client_id,
                    alert_type,
                    anomaly_score,
                    details
                )
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    anomaly_score = VALUES(anomaly_score),
                    details = VALUES(details)
                """,
                (
                    str(event["event_id"]),
                    str(event["client_id"]),
                    alert_type,
                    float(metrics["score"]),
                    details,
                ),
            )

        connection.commit()

    except mysql.connector.Error:
        connection.rollback()
        raise

    finally:
        cursor.close()


# =========================================================
# EVENT PROCESSING
# =========================================================

def process_event(event, connection):

    required_fields = {
        "event_id",
        "timestamp",
        "client_id",
        "endpoint",
        "status_code",
        "latency_ms",
    }

    if not isinstance(event, dict):
        print("Skipping event: expected a JSON object.", flush=True)
        return

    if not required_fields.issubset(event):
        print("Skipping event: missing required fields.", flush=True)
        return

    try:
        event_timestamp = datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )

        if event_timestamp.tzinfo is None:
            event_timestamp = event_timestamp.replace(
                tzinfo=timezone.utc
            )

        event_time = event_timestamp.timestamp()
        status_code = int(event["status_code"])
        latency_ms = float(event["latency_ms"])

        if not 100 <= status_code <= 599:
            print("Skipping event: invalid HTTP status.", flush=True)
            return

        if not (0 <= latency_ms < float("inf")):
            print("Skipping event: invalid latency.", flush=True)
            return

    except (ValueError, TypeError, AttributeError):
        print("Skipping event: invalid data or timestamp.", flush=True)
        return

    client_id = str(event["client_id"])

    record = {
        "time": event_time,
        "status": status_code,
        "latency": latency_ms,
        "endpoint": str(event["endpoint"]),
    }

    events = client_events[client_id]
    events.append(record)

    # Maintain a rolling 10-second event window.
    while (
        events
        and event_time - events[0]["time"] > WINDOW_SECONDS
    ):
        events.popleft()

    request_count = len(events)

    failures = sum(
        item["status"] >= 400
        for item in events
    )

    failure_ratio = failures / request_count

    avg_latency = sum(
        item["latency"]
        for item in events
    ) / request_count

    endpoint_diversity = len({
        item["endpoint"]
        for item in events
    })

    # -----------------------------------------------------
    # RULE-BASED BURST DETECTION
    # -----------------------------------------------------

    burst = request_count >= BURST_THRESHOLD

    # Keep feature order consistent with model training.
    features = [[
        request_count,
        failure_ratio,
        avg_latency,
        endpoint_diversity,
    ]]

    # -----------------------------------------------------
    # ISOLATION FOREST DETECTION
    # -----------------------------------------------------

    prediction = int(model.predict(features)[0])
    score = float(model.decision_function(features)[0])

    ml_anomaly = (
        request_count >= MIN_EVENTS_FOR_ML
        and prediction == -1
    )

    # -----------------------------------------------------
    # HYBRID DETECTION
    # -----------------------------------------------------

    anomaly = ml_anomaly or burst

    metrics = {
        "requests": request_count,
        "failure_ratio": failure_ratio,
        "avg_latency": avg_latency,
        "endpoint_diversity": endpoint_diversity,
        "burst": bool(burst),
        "ml_anomaly": bool(ml_anomaly),
        "anomaly": bool(anomaly),
        "score": score,
    }

    # Save event before reporting success.
    save_event(connection, event, metrics)

    if ml_anomaly and burst:
        detection = "ML + BURST"

    elif ml_anomaly:
        detection = "ML ANOMALY"

    elif burst:
        detection = "BURST RULE"

    else:
        detection = "NORMAL"

    print(
        f"Client: {client_id:10} | "
        f"Requests/10s: {request_count:3} | "
        f"Failures: {failure_ratio * 100:5.1f}% | "
        f"Avg latency: {avg_latency:7.2f} ms | "
        f"Endpoints: {endpoint_diversity} | "
        f"Burst: {'YES' if burst else 'no':3} | "
        f"ML: {'ANOMALY' if ml_anomaly else 'NORMAL':8} | "
        f"Detection: {detection:12} | "
        f"Score: {score: .4f} | DB: saved",
        flush=True,
    )

    if anomaly:
        print(
            f"  ALERT saved for client {client_id}",
            flush=True,
        )


# =========================================================
# KAFKA CONSUMER
# =========================================================

def main():

    connection = None
    consumer = None

    try:
        connection = connect_database()

        consumer = KafkaConsumer(
            TOPIC,
            bootstrap_servers=BOOTSTRAP_SERVERS,
            value_deserializer=lambda value: json.loads(
                value.decode("utf-8")
            ),
            auto_offset_reset="latest",
            enable_auto_commit=False,
            group_id=CONSUMER_GROUP,
        )

        print(f"Listening to Kafka topic: {TOPIC}", flush=True)
        print("Writing processed events to MySQL.", flush=True)
        print(
            "Detection: Isolation Forest + Burst Rules.",
            flush=True,
        )
        print("Press Ctrl+C to stop.\n", flush=True)

        for message in consumer:

            try:
                process_event(message.value, connection)

                # Commit Kafka offset after successful processing.
                consumer.commit()

            except mysql.connector.Error as error:
                print(f"MySQL write failed: {error}", flush=True)
                print(
                    "Stopping to avoid committing an unsaved event.",
                    flush=True,
                )
                break

            except (ValueError, TypeError, KeyError) as error:
                print(f"Invalid event: {error}", flush=True)
                consumer.commit()

    except KeyboardInterrupt:
        print("\nProcessor stopped by user.", flush=True)

    finally:
        if consumer is not None:
            consumer.close()

        if connection is not None and connection.is_connected():
            connection.close()

        print("Connections closed.", flush=True)


if __name__ == "__main__":
    main()
