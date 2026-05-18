from sklearn.ensemble import IsolationForest
import pandas as pd

def run_isolation_forest(rows, numeric_columns, contamination=0.05):

    if not numeric_columns:
        return [
            {"is_anomaly": False, "score": 0}
            for _ in rows
        ]

    df = pd.DataFrame(rows)

    X = df[numeric_columns].astype(float)

    model = IsolationForest(
        contamination=contamination,
        random_state=42
    )

    preds = model.fit_predict(X)

    scores = model.decision_function(X)

    results = []

    for p, s in zip(preds, scores):

        results.append({
            "is_anomaly": bool(p == -1),
            "score": float(s)
        })

    return results

