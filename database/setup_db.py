
import os
import mysql.connector
from mysql.connector import Error

DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "api_user",
    "password": os.getenv(
        "MYSQL_PASSWORD",
        "local_api_password_change_me",
    ),
    "database": "api_abuse",
}


def setup_database():
    connection = None
    cursor = None

    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS processed_events (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                event_id VARCHAR(36) NOT NULL UNIQUE,
                event_timestamp DATETIME(6) NOT NULL,
                client_id VARCHAR(100) NOT NULL,
                endpoint VARCHAR(255) NOT NULL,
                status_code INT NOT NULL,
                latency_ms DOUBLE NOT NULL,
                requests_per_10s INT NOT NULL,
                failure_ratio DOUBLE NOT NULL,
                avg_latency_ms DOUBLE NOT NULL,
                endpoint_diversity INT NOT NULL,
                burst_detected BOOLEAN NOT NULL,
                is_anomaly BOOLEAN NOT NULL,
                anomaly_score DOUBLE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_client_timestamp (client_id, event_timestamp),
                INDEX idx_anomaly (is_anomaly, event_timestamp)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                event_id VARCHAR(36) NOT NULL,
                client_id VARCHAR(100) NOT NULL,
                alert_type VARCHAR(50) NOT NULL,
                anomaly_score DOUBLE NOT NULL,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_alert_client (client_id),
                INDEX idx_alert_created (created_at)
            )
        """)

        connection.commit()

        print("Database connection successful!")
        print("Table ready: processed_events")
        print("Table ready: alerts")

    except Error as error:
        print(f"Database setup failed: {error}")
        raise

    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()


if __name__ == "__main__":
    setup_database()
