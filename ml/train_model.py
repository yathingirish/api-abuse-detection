
from pathlib import Path

import joblib
import numpy as np

from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


RANDOM_STATE = 42
NORMAL_SAMPLES = 5000
SUSPICIOUS_SAMPLES = 1000


def generate_training_data():
    """Generate simulated normal and suspicious API traffic."""

    rng = np.random.default_rng(RANDOM_STATE)

    # Normal traffic: approximately 2-3 requests per client
    # in a 10-second window.
    normal = np.column_stack([
        rng.poisson(2.5, NORMAL_SAMPLES),
        rng.beta(1.2, 7, NORMAL_SAMPLES),
        rng.uniform(20, 400, NORMAL_SAMPLES),
        rng.integers(1, 6, NORMAL_SAMPLES),
    ])

    samples_per_attack = SUSPICIOUS_SAMPLES // 3

    # Attack 1: High-volume bot bursts.
    bot_burst = np.column_stack([
        rng.integers(15, 31, samples_per_attack),
        rng.beta(2, 4, samples_per_attack),
        rng.uniform(5, 100, samples_per_attack),
        np.ones(samples_per_attack),
    ])

    # Attack 2: Repeated authentication failures.
    brute_force = np.column_stack([
        rng.integers(15, 31, samples_per_attack),
        rng.beta(12, 2, samples_per_attack),
        rng.uniform(20, 150, samples_per_attack),
        np.ones(samples_per_attack),
    ])

    # Attack 3: Rapid endpoint scanning.
    endpoint_scanning = np.column_stack([
        rng.integers(15, 31, samples_per_attack),
        rng.beta(3, 3, samples_per_attack),
        rng.uniform(10, 180, samples_per_attack),
        rng.integers(2, 6, samples_per_attack),
    ])

    suspicious = np.vstack([
        bot_burst,
        brute_force,
        endpoint_scanning,
    ])

    X = np.vstack([normal, suspicious])

    y = np.concatenate([
        np.zeros(len(normal), dtype=int),
        np.ones(len(suspicious), dtype=int),
    ])

    indices = rng.permutation(len(X))

    return X[indices], y[indices]


def main():
    X, y = generate_training_data()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("isolation_forest", IsolationForest(
            n_estimators=150,
            contamination=1 / 6,
            random_state=RANDOM_STATE,
        )),
    ])

    # Train the unsupervised model without using labels.
    model.fit(X_train)

    predictions = (
        model.predict(X_test) == -1
    ).astype(int)

    print("=== Isolation Forest Evaluation ===")

    print(classification_report(
        y_test,
        predictions,
        target_names=["Normal", "Suspicious"],
        zero_division=0,
    ))

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    output = Path("ml/isolation_forest.joblib")
    output.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, output)

    print(f"\nModel saved to: {output.resolve()}")
    print("\nFeature order:")
    print("1. requests_per_10s")
    print("2. failure_ratio")
    print("3. avg_latency_ms")
    print("4. endpoint_diversity")


if __name__ == "__main__":
    main()
