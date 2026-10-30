
import json
import random
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from kafka import KafkaProducer


CLIENTS = [f"client_{i:03d}" for i in range(1, 21)]

ENDPOINTS = [
    "/api/products",
    "/api/products/123",
    "/api/search",
    "/api/profile",
    "/api/orders",
]

ATTACK_TYPES = [
    "bot_burst",
    "brute_force",
    "endpoint_scanning",
]

BURST_INTERVAL = 20
BURST_DURATION = 5
EVENT_INTERVAL = 0.2


def generate_event(attack_type=None):
    """Generate normal or suspicious API traffic."""

    if attack_type == "bot_burst":
        client_id = "bot_001"
        endpoint = "/api/products"
        status_code = random.choice([200, 200, 200, 429, 500])
        latency = random.uniform(5, 100)
        traffic_type = "bot_burst"

    elif attack_type == "brute_force":
        client_id = "bot_002"
        endpoint = "/api/profile"
        status_code = random.choice([401, 401, 403, 403, 429])
        latency = random.uniform(20, 150)
        traffic_type = "brute_force"

    elif attack_type == "endpoint_scanning":
        client_id = "bot_003"
        endpoint = random.choice(ENDPOINTS)
        status_code = random.choice([200, 404, 404, 403])
        latency = random.uniform(10, 180)
        traffic_type = "endpoint_scanning"

    else:
        client_id = random.choice(CLIENTS)
        endpoint = random.choice(ENDPOINTS)
        status_code = random.choices(
            [200, 201, 400, 404, 500],
            weights=[75, 10, 7, 5, 3],
        )[0]
        latency = random.uniform(20, 400)
        traffic_type = "normal"

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_id": client_id,
        "endpoint": endpoint,
        "status_code": status_code,
        "latency_ms": round(latency, 2),
        "traffic_type": traffic_type,
    }


def main():
    output_file = Path("data/api_events.jsonl")
    output_file.parent.mkdir(parents=True, exist_ok=True)

    print("Connecting to Kafka at localhost:9092...")

    producer = KafkaProducer(
        bootstrap_servers=["localhost:9092"],
        value_serializer=lambda event: json.dumps(event).encode("utf-8"),
        acks="all",
    )

    start_time = time.monotonic()
    total_events = 0
    suspicious_events = 0

    print("Connected to Kafka.")
    print(f"Saving events to: {output_file.resolve()}")
    print("Publishing to Kafka topic: api-requests")
    print("Attack cycle: bot burst, brute force, endpoint scanning.")
    print("Each attack lasts 5 seconds and repeats every 20 seconds.")
    print("Press Ctrl+C to stop.\n")

    try:
        with output_file.open("a", encoding="utf-8") as file:
            while True:
                elapsed = time.monotonic() - start_time
                cycle_number = int(elapsed // BURST_INTERVAL)
                position_in_cycle = elapsed % BURST_INTERVAL

                in_attack = position_in_cycle < BURST_DURATION

                attack_type = None

                if in_attack and random.random() < 0.8:
                    attack_type = ATTACK_TYPES[
                        cycle_number % len(ATTACK_TYPES)
                    ]

                event = generate_event(attack_type)

                future = producer.send("api-requests", value=event)
                future.get(timeout=10)

                line = json.dumps(event)
                print(line, flush=True)

                file.write(line + "\n")
                file.flush()

                total_events += 1

                if attack_type:
                    suspicious_events += 1

                if total_events % 25 == 0:
                    print(
                        f"# Progress: {total_events} events published, "
                        f"{suspicious_events} suspicious",
                        flush=True,
                    )

                time.sleep(EVENT_INTERVAL)

    except KeyboardInterrupt:
        print("\nGenerator stopped.")

    finally:
        producer.flush()
        producer.close()

        print(f"Total events generated: {total_events}")
        print(f"Suspicious events: {suspicious_events}")
        print(f"Data saved to: {output_file.resolve()}")


if __name__ == "__main__":
    main()
