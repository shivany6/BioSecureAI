from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from auth_dependencies import get_current_user
from database import SessionLocal
from schemas import (
    MedicalRecordCreate,
    MedicalRecordResponse,
    MedicalRecordUpdate,
)
from db_utils import (
    create_medical_record,
    get_medical_field,
    get_medical_record_by_id,
    update_medical_record,
    create_audit_log,
    get_medical_records_by_patient,
    get_patient_by_id,
)
from integrity import verify_medical_record_integrity


router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post(
    "/medical-records",
    response_model=MedicalRecordResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_medical_record(
    record: MedicalRecordCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    allowed_roles = ["admin", "doctor", "nurse"]
    if current_user["role"] not in allowed_roles:
        raise HTTPException(status_code=403, detail="Access denied")

    field = get_medical_field(db, record.field_id)
    if not field:
        raise HTTPException(status_code=404, detail="Medical field not found")

    if field.field_type == "number":
        try:
            float(record.value)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"{field.field_name} requires a numeric value",
            )

    return create_medical_record(
        db=db,
        patient_id=record.patient_id,
        field_id=record.field_id,
        value=record.value,
        created_by=current_user["username"],
    )


@router.get("/medical-records/{record_id}/verify")
def verify_medical_record(
    record_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    allowed_roles = ["admin", "doctor", "nurse"]
    if current_user["role"] not in allowed_roles:
        raise HTTPException(status_code=403, detail="Access denied")

    record = get_medical_record_by_id(db, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Medical record not found")

    return {
        "record_id": record.id,
        "integrity_status": verify_medical_record_integrity(record),
    }


@router.put(
    "/medical-records/{record_id}",
    response_model=MedicalRecordResponse,
)
def edit_medical_record(
    record_id: int,
    record_data: MedicalRecordUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    allowed_roles = ["admin", "doctor", "nurse"]
    if current_user["role"] not in allowed_roles:
        raise HTTPException(status_code=403, detail="Access denied")

    record = get_medical_record_by_id(db, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Medical record not found")

    old_value = record.value
    field = get_medical_field(db, record.field_id)

    create_audit_log(
        db=db,
        patient_id=record.patient_id,
        changed_by=current_user["username"],
        user_role=current_user["role"],
        field_name=field.field_name,
        old_value=old_value,
        new_value=record_data.value,
    )

    return update_medical_record(db, record, record_data.value)


@router.get("/patients/{patient_id}/medical-records")
def get_patient_medical_records(
    patient_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    allowed_roles = ["admin", "doctor", "nurse"]
    if current_user["role"] not in allowed_roles:
        raise HTTPException(status_code=403, detail="Access denied")

    patient = get_patient_by_id(db, patient_id)
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    records = get_medical_records_by_patient(db, patient_id)
    result = []

    for record in records:
        field = get_medical_field(db, record.field_id)
        result.append(
            {
                "record_id": record.id,
                "field_name": field.field_name,
                "field_type": field.field_type,
                "value": record.value,
                "created_by": record.created_by,
                "created_at": record.created_at,
            }
        )

    return result
    