# roles.py

def role_permissions(columns, numeric_columns):
    """
    Dynamically compute allowed columns per role.

    columns = all CSV columns (strings)
    numeric_columns = auto-detected float/int columns
    """

    # Identify personal / identity columns safely
    personal_keys = ["id", "patient_id", "name", "patient", "identifier"]
    personal = [c for c in columns if c.lower() in personal_keys]

    # Identify diagnosis-related columns
    diagnosis_keys = ["diagnosis", "diagnosis_label"]
    diagnosis_cols = [c for c in columns if c.lower() in diagnosis_keys]

    # Medical = everything except personal
    medical = [c for c in columns if c not in personal]

    return {
        # FULL ACCESS — decrypts everything
        "admin": columns,

        # DOCTOR: medical + diagnosis (cannot see identity)
        "doctor": list(set(medical + diagnosis_cols)),

        # LAB TECHNICIAN: numeric columns only
        "lab": numeric_columns,

        # RESEARCHER: numeric columns only + anomaly scores (frontend shows scores)
        "researcher": numeric_columns
    }


