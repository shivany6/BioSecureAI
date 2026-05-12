# anomaly.py
from sklearn.ensemble import IsolationForest
import pandas as pd

def pick_numeric_columns_from_rows(rows: list):
    """
    Given list of dict rows (string values), detect which keys are numeric.
    Use first row as reference but attempt coercion safely.
    Returns list of column names that can be used as numeric features.
    """
    if not rows:
        return []
    # Build DataFrame (pandas will make non-parsable values NaN)
    df = pd.DataFrame(rows)
    # Convert every column to numeric if possible
    numeric = []
    for col in df.columns:
        # try conversion
        s = pd.to_numeric(df[col], errors="coerce")
        # if at least one value is numeric (not all NaN) consider it numeric
        if s.notna().sum() > 0:
            numeric.append(col)
    return numeric

def run_isolation_forest(rows: list, numeric_columns: list, contamination=0.05):
    """
    rows: list of dicts (strings), numeric_columns: subset to use
    returns: list of dicts [{is_anomaly:bool, score:float}, ...] aligned with rows order
    """
    if not rows or not numeric_columns:
        return [{"is_anomaly": False, "score": 0.0} for _ in rows]

    df = pd.DataFrame(rows)
    df_num = df[numeric_columns].apply(pd.to_numeric, errors="coerce")

    # Fill NaNs with median to be robust
    for col in df_num.columns:
        med = df_num[col].median()
        df_num[col] = df_num[col].fillna(med)

    # IsolationForest expects >1 sample
    if df_num.shape[0] < 2:
        return [{"is_anomaly": False, "score": 0.0} for _ in range(df_num.shape[0])]

    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(df_num)
    labels = model.predict(df_num)  # 1 normal, -1 anomaly
    scores = model.decision_function(df_num)  # higher = more normal
    # convert so higher score => more anomalous (flip and normalize)
    out = []
    for lab, sc in zip(labels, scores):
        out.append({"is_anomaly": True if lab == -1 else False, "score": float(-sc)})
    return out
