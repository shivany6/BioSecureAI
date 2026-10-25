
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from auth_dependencies import get_current_user
from database import SessionLocal
from schemas import PatientCreate, PatientResponse, PatientUpdate
from db_utils import (
    create_patient,
    get_all_patients,
    get_patient_by_id,
    update_patient,
    create_audit_log,
)
from integrity import verify_patient_integrity

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post(
    "/patients",
    response_model=PatientResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_patient(
    patient: PatientCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    allowed_roles = ["admin", "doctor", "receptionist"]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="You are not allowed to create patients.",
        )

    new_patient = create_patient(
        db=db,
        first_name=patient.first_name,
        last_name=patient.last_name,
        date_of_birth=patient.date_of_birth,
        gender=patient.gender,
        phone=patient.phone,
        email=patient.email,
        address=patient.address,
    )

    return new_patient


@router.get("/patients", response_model=list[PatientResponse])
def get_patients(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    allowed_roles = ["admin", "doctor", "receptionist"]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(status_code=403, detail="Access denied")

    return get_all_patients(db)


@router.get("/patients/{patient_id}", response_model=PatientResponse)
def get_patient(
    patient_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    allowed_roles = ["admin", "doctor", "receptionist"]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(status_code=403, detail="Access denied")

    patient = get_patient_by_id(db, patient_id)

    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    return patient


@router.put("/patients/{patient_id}", response_model=PatientResponse)
def edit_patient(
    patient_id: str,
    patient_data: PatientUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    allowed_roles = ["admin", "doctor", "receptionist"]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(status_code=403, detail="Access denied")

    patient = get_patient_by_id(db, patient_id)

    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    update_data = patient_data.model_dump(exclude_unset=True)

    old_values = {
        field: getattr(patient, field)
        for field in update_data
    }

    updated_patient = update_patient(db, patient, patient_data)

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
                new_value=new_value,
            )

    return updated_patient


@router.get("/patients/{patient_id}/verify")
def verify_patient(
    patient_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    allowed_roles = ["admin", "doctor"]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(status_code=403, detail="Access denied")

    patient = get_patient_by_id(db, patient_id)

    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    is_valid = verify_patient_integrity(patient)

    return {
        "patient_id": patient.patient_id,
        "integrity_status": "VALID" if is_valid else "TAMPERED",
    }
