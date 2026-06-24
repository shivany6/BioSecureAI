# app.py
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import uuid
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from roles import role_permissions
from encryption import MASTER_KEY, encrypt_row, decrypt_row_columns
from anomaly import run_isolation_forest
from db_utils import save_encrypted_db, load_encrypted_db
from fastapi import Depends
from sqlalchemy.orm import Session
from integrity import verify_patient_integrity, verify_medical_record_integrity
from auth_dependencies import get_current_user
from schemas import (
    PatientCreate,
    PatientResponse,
    PatientUpdate,
    MedicalFieldCreate,
    MedicalFieldResponse,
    MedicalRecordCreate,
    MedicalRecordResponse,
    MedicalRecordUpdate,
    AppointmentCreate,
    AppointmentResponse,
    AppointmentUpdate,
    PrescriptionCreate,
    PrescriptionResponse,
    PrescriptionUpdate
)
from fastapi import status
from database import SessionLocal
from db_utils import (
    create_user,
    authenticate_user,
    create_patient,
    get_all_patients,
    get_patient_by_id,
    update_patient,
    create_medical_field,
    create_medical_record,
    get_medical_field,
    get_medical_record_by_id,
    update_medical_record,
    create_audit_log,
    get_medical_records_by_patient,
    get_all_audit_logs,
    get_audit_logs_by_patient,
    create_appointment,
    get_all_appointments,
    get_patient_appointments,
    get_appointment_by_id,
    update_appointment,
    create_prescription,
    get_all_prescriptions,
    get_patient_prescriptions,
    get_prescription_by_id,
    update_prescription
)
from auth import create_access_token

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI(title="BioSecureAI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev only. Narrow this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {
        "application": "BioSecureAI",
        "status": "running",
        "version": "1.0.0"
    }

@app.post("/upload_encrypt")
async def upload_encrypt(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """
    Upload CSV -> server reads it -> encrypts each row (per-cell) with admin-derived key -> store JSON -> return dataset_id & columns
    """
    try:
        df = pd.read_csv(file.file)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read CSV: {e}")

    all_columns = list(df.columns)
    dataset_id = str(uuid.uuid4())[:8]
    encrypted_rows = []
    # Encrypt all rows using MASTER_KEY
    for _, row in df.iterrows():
        row_dict = {col: row[col] for col in all_columns}
        enc = encrypt_row(MASTER_KEY, row_dict)

        encrypted_rows.append(enc)
    save_encrypted_db(dataset_id, encrypted_rows)
    return {"status":"ok", "dataset_id": dataset_id, "columns": all_columns, "rows": len(encrypted_rows)}

@app.post("/analyze_role")
async def analyze_role(
    dataset_id: str = Form(...),
    current_user: dict = Depends(get_current_user),
    contamination: float = Form(0.05)
):
    role = current_user["role"]
    try:
        enc_rows = load_encrypted_db(dataset_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="dataset not found")

    if not enc_rows:
        return {"status": "ok", "rows": []}
    # full columns
    all_columns = list(enc_rows[0].keys())
    admin_key = MASTER_KEY
    # decrypt only first row using admin for type detection
    first_dec = {}
    for col in all_columns:
        try:
            first_dec[col] = decrypt_row_columns(admin_key, enc_rows[0], [col])[col]
        except:
            first_dec[col] = None
    # detect numeric columns
    numeric_candidates = []
    for col, val in first_dec.items():
        try:
            float(val)
            numeric_candidates.append(col)
        except:
            pass

    # Role-based allowed columns (NEW SYSTEM)
    permissions = role_permissions(all_columns, numeric_candidates)
    allowed = permissions.get(role, [])

    # decrypt allowed columns safely
    decrypted_rows = []
    for enc in enc_rows:
        try:
            dec = decrypt_row_columns(MASTER_KEY, enc, allowed)
        except:
            # if role is restricted from decrypting a column -> skip
            dec = {col: "ACCESS_DENIED" for col in allowed}

        decrypted_rows.append(dec)

    # subset numeric columns for anomaly detection
    numeric_cols_allowed = [c for c in allowed if c in numeric_candidates]

    anomalies = run_isolation_forest(
        decrypted_rows,
        numeric_cols_allowed,
        contamination=contamination
    )

    # attach anomaly flags
    output_rows = []
    for row, a in zip(decrypted_rows, anomalies):
        r = row.copy()
        r["_is_anomaly"] = a["is_anomaly"]
        r["_anomaly_score"] = a["score"]
        output_rows.append(r)

    return JSONResponse({
        "status": "ok",
        "dataset_id": dataset_id,
        "columns": allowed,
        "rows": output_rows,
        "counts": {"anomaly_count": sum(r["_is_anomaly"] for r in output_rows)}
    })

@app.post("/decrypt_full")
async def decrypt_full(
    dataset_id: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    # ONLY ADMIN ALLOWED
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )
    try:
        enc_rows = load_encrypted_db(dataset_id)

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="dataset not found"
        )
    admin_key = MASTER_KEY

    all_columns = list(enc_rows[0].keys())

    out_rows = []

    for enc in enc_rows:

        dec_row = decrypt_row_columns(
            admin_key,
            enc,
            all_columns
        )

        out_rows.append(dec_row)

    return JSONResponse({
        "status": "ok",
        "dataset_id": dataset_id,
        "rows": out_rows
    })

@app.post("/encrypt_file")
async def encrypt_file(file: UploadFile = File(...)):
    """
    Encrypt the entire CSV file as a single binary using AES-GCM.
    Returns ciphertext, iv, and tag (all base64 encoded).
    """
    try:
        raw_data = await file.read()   # read file bytes
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {e}")

    # STEP 1: generate random AES key
    aes_key = get_random_bytes(32)  # 256-bit key

    # STEP 2: generate random IV (nonce)
    iv = get_random_bytes(12)       # GCM recommended size

    # STEP 3: create AES-GCM cipher with IV
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)

    # STEP 4: encrypt the file
    ciphertext, tag = cipher.encrypt_and_digest(raw_data)

    # STEP 5: return all important values to client
    return {
        "status": "ok",
        "key_b64": base64.b64encode(aes_key).decode(),
        "iv_b64": base64.b64encode(iv).decode(),
        "tag_b64": base64.b64encode(tag).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "file_name": file.filename
    }

@app.post("/register")
def register(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    db: Session = Depends(get_db)
):

    user = create_user(
        db,
        username,
        email,
        password,
        role
    )

    return {
        "message": "User created successfully",
        "user_id": user.id
    }

@app.post("/login")
def login(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):

    user = authenticate_user(
        db,
        username,
        password
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    token = create_access_token(
        data={
            "sub": user.username,
            "role": user.role
        }
    )

    return {
        "access_token": token,
        "token_type": "bearer"
    }

@app.post(
    "/patients",
    response_model=PatientResponse,
    status_code=status.HTTP_201_CREATED
)
def add_patient(
    patient: PatientCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # RBAC check
    allowed_roles = ["admin", "doctor", "receptionist"]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="You are not allowed to create patients."
        )

    # Create patient
    new_patient = create_patient(
        db=db,
        first_name=patient.first_name,
        last_name=patient.last_name,
        date_of_birth=patient.date_of_birth,
        gender=patient.gender,
        phone=patient.phone,
        email=patient.email,
        address=patient.address
    )

    return new_patient

@app.get(
    "/patients",
    response_model=list[PatientResponse]
)
def get_patients(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    allowed_roles = [
        "admin",
        "doctor",
        "receptionist"
    ]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    return get_all_patients(db)

@app.get(
    "/patients/{patient_id}",
    response_model=PatientResponse
)
def get_patient(
    patient_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    allowed_roles = [
        "admin",
        "doctor",
        "receptionist"
    ]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    patient = get_patient_by_id(
        db,
        patient_id
    )

    if not patient:
        raise HTTPException(
            status_code=404,
            detail="Patient not found"
        )
    return patient

@app.put(
    "/patients/{patient_id}",
    response_model=PatientResponse
)
def edit_patient(
    patient_id: str,
    patient_data: PatientUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    allowed_roles = [
        "admin",
        "doctor",
        "receptionist"
    ]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    patient = get_patient_by_id(
        db,
        patient_id
    )

    if not patient:
        raise HTTPException(
            status_code=404,
            detail="Patient not found"
        )

    update_data = patient_data.model_dump(
        exclude_unset=True
    )

    old_values = {}

    for field in update_data.keys():
        old_values[field] = getattr(
            patient,
            field
        )

    updated_patient = update_patient(
        db,
        patient,
        patient_data
    )

    for field, new_value in update_data.items():

        old_value = old_values[field]

        if str(old_value) != str(new_value):

            create_audit_log(
                db=db,
                patient_id=patient.patient_id,
                changed_by=current_user["username"],
                user_role=current_user["role"],
                field_name=field,
                old_value=old_value,
                new_value=new_value
            )

    return updated_patient

@app.get(
    "/patients/{patient_id}/verify"
)
def verify_patient(
    patient_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    allowed_roles = [
        "admin",
        "doctor"
    ]
    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )
    patient = get_patient_by_id(
        db,
        patient_id
    )
    if not patient:
        raise HTTPException(
            status_code=404,
            detail="Patient not found"
        )
    is_valid = verify_patient_integrity(
        patient
    )
    return {
        "patient_id": patient.patient_id,
        "integrity_status":
            "VALID" if is_valid else "TAMPERED"
    }
@app.post(
    "/medical-fields",
    response_model=MedicalFieldResponse,
    status_code=status.HTTP_201_CREATED
)
def add_medical_field(
    field: MedicalFieldCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    allowed_roles = [
        "admin",
        "doctor"
    ]
    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )
    return create_medical_field(
        db=db,
        field_name=field.field_name,
        field_type=field.field_type,
        created_by=current_user["username"]
    )
@app.post(
    "/medical-records",
    response_model=MedicalRecordResponse,
    status_code=status.HTTP_201_CREATED
)
def add_medical_record(
    record: MedicalRecordCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    allowed_roles = [
        "admin",
        "doctor",
        "nurse"
    ]
    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    field = get_medical_field(
        db,
        record.field_id
    )
    if not field:
        raise HTTPException(
            status_code=404,
            detail="Medical field not found"
        )
    if field.field_type == "number":
        try:
            float(record.value)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"{field.field_name} requires a numeric value"
            )
    return create_medical_record(
        db=db,
        patient_id=record.patient_id,
        field_id=record.field_id,
        value=record.value,
        created_by=current_user["username"]
    )

@app.get(
    "/medical-records/{record_id}/verify"
)
def verify_medical_record(
    record_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    allowed_roles = [
        "admin",
        "doctor",
        "nurse"
    ]
    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )
    record = get_medical_record_by_id(
        db,
        record_id
    )
    if not record:
        raise HTTPException(
            status_code=404,
            detail="Medical record not found"
        )
    return {
        "record_id": record.id,
        "integrity_status":
            verify_medical_record_integrity(
                record
            )
    }

@app.put(
    "/medical-records/{record_id}",
    response_model=MedicalRecordResponse
)
def edit_medical_record(
    record_id: int,
    record_data: MedicalRecordUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    allowed_roles = [
        "admin",
        "doctor",
        "nurse"
    ]
    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )
    record = get_medical_record_by_id(
        db,
        record_id
    )
    if not record:
        raise HTTPException(
            status_code=404,
            detail="Medical record not found"
        )
    old_value = record.value
    field = get_medical_field(
    db,
    record.field_id
    )
    create_audit_log(
    db=db,
    patient_id=record.patient_id,
    changed_by=current_user["username"],
    user_role=current_user["role"],
    field_name=field.field_name,
    old_value=old_value,
    new_value=record_data.value
    )

    return update_medical_record(
        db,
        record,
        record_data.value
    )

@app.get(
    "/patients/{patient_id}/medical-records"
)
def get_patient_medical_records(
    patient_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    allowed_roles = [
        "admin",
        "doctor",
        "nurse"
    ]
    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )
    patient = get_patient_by_id(
        db,
        patient_id
    )
    if not patient:
        raise HTTPException(
            status_code=404,
            detail="Patient not found"
        )
    records = get_medical_records_by_patient(
        db,
        patient_id
    )
    result = []
    for record in records:
        field = get_medical_field(
            db,
            record.field_id
        )
        result.append(
            {
                "record_id": record.id,
                "field_name": field.field_name,
                "field_type": field.field_type,
                "value": record.value,
                "created_by": record.created_by,
                "created_at": record.created_at
            }
        )
    return result

@app.get("/audit-logs")
def view_audit_logs(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    allowed_roles = [
        "admin",
        "doctor"
    ]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    logs = get_all_audit_logs(db)

    result = []

    for log in logs:

        result.append(
            {
                "id": log.id,
                "patient_id": log.patient_id,
                "changed_by": log.changed_by,
                "user_role": log.user_role,
                "field_name": log.field_name,
                "old_value": log.old_value,
                "new_value": log.new_value,
                "timestamp": log.timestamp
            }
        )

    return result

@app.get(
    "/patients/{patient_id}/audit-logs"
)
def get_patient_audit_logs(
    patient_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    allowed_roles = [
        "admin",
        "doctor",
        "nurse"
    ]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    patient = get_patient_by_id(
        db,
        patient_id
    )

    if not patient:
        raise HTTPException(
            status_code=404,
            detail="Patient not found"
        )

    logs = get_audit_logs_by_patient(
        db,
        patient_id
    )

    result = []

    for log in logs:

        result.append(
            {
                "id": log.id,
                "field_name": log.field_name,
                "old_value": log.old_value,
                "new_value": log.new_value,
                "changed_by": log.changed_by,
                "user_role": log.user_role,
                "timestamp": log.timestamp
            }
        )

    return result

@app.post(
    "/appointments",
    response_model=AppointmentResponse,
    status_code=status.HTTP_201_CREATED
)
def create_new_appointment(
    appointment_data: AppointmentCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    allowed_roles = [
        "admin",
        "receptionist"
    ]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    patient = get_patient_by_id(
        db,
        appointment_data.patient_id
    )

    if not patient:
        raise HTTPException(
            status_code=404,
            detail="Patient not found"
        )

    return create_appointment(
        db=db,
        patient_id=appointment_data.patient_id,
        doctor_username=appointment_data.doctor_username,
        appointment_date=appointment_data.appointment_date,
        appointment_time=appointment_data.appointment_time,
        reason=appointment_data.reason,
        created_by=current_user["username"]
    )
@app.get(
    "/appointments",
    response_model=list[AppointmentResponse]
)
def get_appointments(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    allowed_roles = [
        "admin",
        "receptionist"
    ]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    return get_all_appointments(db)
@app.get(
    "/patients/{patient_id}/appointments",
    response_model=list[AppointmentResponse]
)
def get_patient_appointment_history(
    patient_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    allowed_roles = [
        "admin",
        "doctor",
        "nurse",
        "receptionist"
    ]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    patient = get_patient_by_id(
        db,
        patient_id
    )

    if not patient:
        raise HTTPException(
            status_code=404,
            detail="Patient not found"
        )

    return get_patient_appointments(
        db,
        patient_id
    )
@app.put(
    "/appointments/{appointment_id}",
    response_model=AppointmentResponse
)
def edit_appointment(
    appointment_id: str,
    appointment_data: AppointmentUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    allowed_roles = [
        "admin",
        "receptionist"
    ]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    appointment = get_appointment_by_id(
        db,
        appointment_id
    )

    if not appointment:
        raise HTTPException(
            status_code=404,
            detail="Appointment not found"
        )

    return update_appointment(
        db,
        appointment,
        appointment_data
    )
@app.post(
    "/prescriptions",
    response_model=PrescriptionResponse,
    status_code=status.HTTP_201_CREATED
)
def create_new_prescription(
    prescription_data: PrescriptionCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    allowed_roles = [
        "admin",
        "doctor"
    ]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    patient = get_patient_by_id(
        db,
        prescription_data.patient_id
    )

    if not patient:
        raise HTTPException(
            status_code=404,
            detail="Patient not found"
        )

    return create_prescription(
        db=db,
        patient_id=prescription_data.patient_id,
        doctor_username=current_user["username"],
        medication_name=prescription_data.medication_name,
        dosage=prescription_data.dosage,
        frequency=prescription_data.frequency,
        duration=prescription_data.duration,
        instructions=prescription_data.instructions
    )
@app.get(
    "/prescriptions",
    response_model=list[PrescriptionResponse]
)
def get_prescriptions(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    allowed_roles = [
        "admin",
        "doctor"
    ]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    return get_all_prescriptions(db)
@app.get(
    "/patients/{patient_id}/prescriptions",
    response_model=list[PrescriptionResponse]
)
def get_patient_prescription_history(
    patient_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    allowed_roles = [
        "admin",
        "doctor",
        "nurse"
    ]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    patient = get_patient_by_id(
        db,
        patient_id
    )

    if not patient:
        raise HTTPException(
            status_code=404,
            detail="Patient not found"
        )

    return get_patient_prescriptions(
        db,
        patient_id
    )
@app.put(
    "/prescriptions/{prescription_id}",
    response_model=PrescriptionResponse
)
def edit_prescription(
    prescription_id: str,
    prescription_data: PrescriptionUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    allowed_roles = [
        "admin",
        "doctor"
    ]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    prescription = get_prescription_by_id(
        db,
        prescription_id
    )

    if not prescription:
        raise HTTPException(
            status_code=404,
            detail="Prescription not found"
        )

    return update_prescription(
        db,
        prescription,
        prescription_data
    )
    

