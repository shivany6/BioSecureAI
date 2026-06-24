import uuid
import json

from database import SessionLocal
from models import EncryptedDataset
from sqlalchemy.orm import Session
from models import (
    User,
    Patient,
    AuditLog,
    MedicalField,
    MedicalRecord,
    Appointment,
    Prescription
)
from auth import hash_password
from integrity import generate_patient_hash
from integrity import generate_medical_record_hash

def create_user(
    db: Session,
    username: str,
    email: str,
    password: str,
    role: str
):
    hashed_pw = hash_password(password)

    user = User(
        username=username,
        email=email,
        hashed_password=hashed_pw,
        role=role
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user

def save_encrypted_db(dataset_id, encrypted_rows):

    db = SessionLocal()

    data_json = json.dumps(encrypted_rows)

    record = EncryptedDataset(
        dataset_id=dataset_id,
        encrypted_data=data_json
    )

    db.add(record)

    db.commit()

    db.close()


def load_encrypted_db(dataset_id):

    db = SessionLocal()

    record = db.query(EncryptedDataset).filter(
        EncryptedDataset.dataset_id == dataset_id
    ).first()

    db.close()

    if not record:
        raise FileNotFoundError("Dataset not found")

    return json.loads(record.encrypted_data)
from auth import verify_password

def authenticate_user(
    db: Session,
    username: str,
    password: str
):
    user = db.query(User).filter(
        User.username == username
    ).first()

    if not user:
        return None

    if not verify_password(
        password,
        user.hashed_password
    ):
        return None

    return user

def create_patient(
    db: Session,
    first_name: str,
    last_name: str,
    date_of_birth,
    gender: str,
    phone: str = None,
    email: str = None,
    address: str = None
):
    generated_patient_id = (
        f"PAT-{uuid.uuid4().hex[:8].upper()}"
    )

    record_hash = generate_patient_hash(
        generated_patient_id,
        first_name,
        last_name,
        date_of_birth,
        gender,
        phone,
        email,
        address
    )

    patient = Patient(
        patient_id=generated_patient_id,
        first_name=first_name,
        last_name=last_name,
        date_of_birth=date_of_birth,
        gender=gender,
        phone=phone,
        email=email,
        address=address,
        record_hash=record_hash
    )

    db.add(patient)
    db.commit()
    db.refresh(patient)

    return patient

def get_all_patients(db: Session):
    return db.query(Patient).all()

def get_patient_by_id(
    db: Session,
    patient_id: str
):
    return db.query(Patient).filter(
        Patient.patient_id == patient_id
    ).first()

def update_patient(
    db: Session,
    patient,
    patient_data
):
    update_data = patient_data.model_dump(
        exclude_unset=True
    )

    for field, value in update_data.items():
        setattr(
            patient,
            field,
            value
        )

    db.commit()
    db.refresh(patient)

    return patient

def create_audit_log(
    db: Session,
    patient_id: str,
    changed_by: str,
    user_role: str,
    field_name: str,
    old_value,
    new_value
):
    log = AuditLog(
        patient_id=patient_id,
        changed_by=changed_by,
        user_role=user_role,
        field_name=field_name,
        old_value=str(old_value) if old_value is not None else None,
        new_value=str(new_value) if new_value is not None else None
    )

    db.add(log)
    db.commit()
    db.refresh(log)

    return log
def create_medical_field(
    db: Session,
    field_name: str,
    field_type: str,
    created_by: str
):
    field = MedicalField(
        field_name=field_name,
        field_type=field_type,
        created_by=created_by
    )

    db.add(field)
    db.commit()
    db.refresh(field)

    return field

from integrity import generate_medical_record_hash


def create_medical_record(
    db: Session,
    patient_id: str,
    field_id: int,
    value: str,
    created_by: str
):
    record_hash = generate_medical_record_hash(
        patient_id,
        field_id,
        value
    )

    record = MedicalRecord(
        patient_id=patient_id,
        field_id=field_id,
        value=value,
        record_hash=record_hash,
        created_by=created_by
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    return record

def update_medical_record(
    db: Session,
    record,
    new_value: str
):
    record.value = new_value

    record.record_hash = (
        generate_medical_record_hash(
            record.patient_id,
            record.field_id,
            new_value
        )
    )

    db.commit()
    db.refresh(record)

    return record

def get_medical_field(
    db: Session,
    field_id: int
):
    return db.query(MedicalField).filter(
        MedicalField.id == field_id
    ).first()

def get_medical_record_by_id(
    db: Session,
    record_id: int
):
    return db.query(MedicalRecord).filter(
        MedicalRecord.id == record_id
    ).first()

def get_medical_records_by_patient(
    db: Session,
    patient_id: str
):
    return db.query(MedicalRecord).filter(
        MedicalRecord.patient_id == patient_id
    ).all()

def get_all_audit_logs(
    db: Session
):
    return db.query(AuditLog).all()
    
def get_audit_logs_by_patient(
    db: Session,
    patient_id: str
):
    return db.query(AuditLog).filter(
        AuditLog.patient_id == patient_id
    ).all()
def create_appointment(
    db: Session,
    patient_id: str,
    doctor_username: str,
    appointment_date,
    appointment_time,
    reason: str,
    created_by: str
):
    appointment = Appointment(
        appointment_id=f"APT-{uuid.uuid4().hex[:8].upper()}",
        patient_id=patient_id,
        doctor_username=doctor_username,
        appointment_date=appointment_date,
        appointment_time=appointment_time,
        reason=reason,
        created_by=created_by
    )

    db.add(appointment)
    db.commit()
    db.refresh(appointment)

    return appointment
def get_all_appointments(
    db: Session
):
    return db.query(
        Appointment
    ).all()
def get_patient_appointments(
    db: Session,
    patient_id: str
):
    return db.query(
        Appointment
    ).filter(
        Appointment.patient_id == patient_id
    ).all()
def get_appointment_by_id(
    db: Session,
    appointment_id: str
):
    return db.query(
        Appointment
    ).filter(
        Appointment.appointment_id == appointment_id
    ).first()
def update_appointment(
    db: Session,
    appointment,
    appointment_data
):
    update_data = appointment_data.model_dump(
        exclude_unset=True
    )

    for field, value in update_data.items():
        setattr(
            appointment,
            field,
            value
        )
    db.commit()
    db.refresh(appointment)

    return appointment
def create_prescription(
    db: Session,
    patient_id: str,
    doctor_username: str,
    medication_name: str,
    dosage: str,
    frequency: str,
    duration: str,
    instructions: str
):

    prescription = Prescription(
        prescription_id=f"RX-{uuid.uuid4().hex[:8].upper()}",
        patient_id=patient_id,
        doctor_username=doctor_username,
        medication_name=medication_name,
        dosage=dosage,
        frequency=frequency,
        duration=duration,
        instructions=instructions
    )
    db.add(prescription)
    db.commit()
    db.refresh(prescription)
    return prescription

def get_all_prescriptions(
    db: Session
):
    return db.query(
        Prescription
    ).all()
def get_patient_prescriptions(
    db: Session,
    patient_id: str
):
    return db.query(
        Prescription
    ).filter(
        Prescription.patient_id == patient_id
    ).all()
def get_prescription_by_id(
    db: Session,
    prescription_id: str
):
    return db.query(
        Prescription
    ).filter(
        Prescription.prescription_id == prescription_id
    ).first()
def update_prescription(
    db: Session,
    prescription,
    prescription_data
):

    update_data = prescription_data.model_dump(
        exclude_unset=True
    )

    for field, value in update_data.items():

        setattr(
            prescription,
            field,
            value
        )

    db.commit()

    db.refresh(
        prescription
    )

    return prescription
    

    