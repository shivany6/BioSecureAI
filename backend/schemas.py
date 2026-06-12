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
    
