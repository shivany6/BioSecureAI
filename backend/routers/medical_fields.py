from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from auth_dependencies import get_current_user
from database import SessionLocal
from schemas import MedicalFieldCreate, MedicalFieldResponse
from db_utils import create_medical_field

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post(
    "/medical-fields",
    response_model=MedicalFieldResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_medical_field(
    field: MedicalFieldCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    allowed_roles = ["admin", "doctor"]

    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Access denied",
        )

    return create_medical_field(
        db=db,
        field_name=field.field_name,
        field_type=field.field_type,
        ai_enabled=field.ai_enabled,
        created_by=current_user["username"],
    )
    