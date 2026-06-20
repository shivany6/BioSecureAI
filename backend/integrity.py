import hashlib


def generate_patient_hash(
    patient_id,
    first_name,
    last_name,
    date_of_birth,
    gender,
    phone,
    email,
    address
):
    data = (
        f"{patient_id}|"
        f"{first_name}|"
        f"{last_name}|"
        f"{date_of_birth}|"
        f"{gender}|"
        f"{phone}|"
        f"{email}|"
        f"{address}"
    )

    return hashlib.sha256(
        data.encode()
    ).hexdigest()
    