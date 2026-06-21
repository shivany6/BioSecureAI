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
    
def verify_patient_integrity(
    patient
):
    current_hash = generate_patient_hash(
        patient.patient_id,
        patient.first_name,
        patient.last_name,
        patient.date_of_birth,
        patient.gender,
        patient.phone,
        patient.email,
        patient.address
    )

    return current_hash == patient.record_hash

def generate_medical_record_hash(
    patient_id,
    field_id,
    value
):
    data = (
        f"{patient_id}|"
        f"{field_id}|"
        f"{value}"
    )

    return hashlib.sha256(
        data.encode()
    ).hexdigest()
    