# roles.py

def role_permissions(columns, numeric_columns):
    """
    Dynamic RBAC permissions.
    """

    # Personal identity fields
    personal_keywords = ["id", "patient_id", "name"]

    personal_cols = [
        c for c in columns
        if c.lower() in personal_keywords
    ]

    # Diagnosis fields
    diagnosis_keywords = ["diagnosis"]

    diagnosis_cols = [
        c for c in columns
        if c.lower() in diagnosis_keywords
    ]

    # Medical columns
    medical_cols = [
        c for c in columns
        if c not in personal_cols
    ]

    return {

        # Full access
        "admin": columns,

        # Doctor sees diagnosis + medical metrics
        "doctor": diagnosis_cols + numeric_columns[:10],

        # Lab sees only numeric lab metrics
        "lab": numeric_columns[:6],

        # Researcher sees anonymized analytics only
        "researcher": numeric_columns[:4]
    }
    


