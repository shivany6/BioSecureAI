import uuid
import json

from database import SessionLocal
from models import EncryptedDataset
from sqlalchemy.orm import Session
from models import User, Patient
from auth import hash_password

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
    patient = Patient(
        patient_id=f"PAT-{uuid.uuid4().hex[:8].upper()}",
        first_name=first_name,
        last_name=last_name,
        date_of_birth=date_of_birth,
        gender=gender,
        phone=phone,
        email=email,
        address=address
    )

    db.add(patient)
    db.commit()
    db.refresh(patient)

    return patient
    
        