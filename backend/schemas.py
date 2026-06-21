from datetime import date
from typing import Optional

from pydantic import BaseModel, ConfigDict

# Patient Creation Schema

class PatientCreate(BaseModel):
    first_name: str
    last_name: str
    date_of_birth: date
    gender: str
    phone: Optional[str] = None
    email: Optional[str] = None
    address: Optional[str] = None

# Patient Response Schema

class PatientResponse(BaseModel):
    patient_id: str
    first_name: str
    last_name: str
    date_of_birth: date
    gender: str
    phone: Optional[str]
    email: Optional[str]
    address: Optional[str]

    model_config = ConfigDict(from_attributes=True)

class PatientUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    date_of_birth: Optional[date] = None
    gender: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    address: Optional[str] = None

# Medical Field Creation Schema

class MedicalFieldCreate(BaseModel):
    field_name: str
    field_type: str


# Medical Field Response Schema

class MedicalFieldResponse(BaseModel):
    id: int
    field_name: str
    field_type: str
    created_by: str

    model_config = ConfigDict(
        from_attributes=True
    )

# Medical Record Creation Schema

class MedicalRecordCreate(BaseModel):
    patient_id: str
    field_id: int
    value: str


# Medical Record Response Schema

class MedicalRecordResponse(BaseModel):
    id: int
    patient_id: str
    field_id: int
    value: str
    created_by: str

    model_config = ConfigDict(
        from_attributes=True
    )
    