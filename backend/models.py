from sqlalchemy import Column, Integer, String, Text, DateTime, Date
from database import Base
from datetime import datetime

class EncryptedDataset(Base):

    __tablename__ = "encrypted_datasets"

    id = Column(Integer, primary_key=True, index=True)

    dataset_id = Column(String, unique=True, index=True, nullable=False)

    encrypted_data = Column(Text, nullable=False)
    
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(String(50), unique=True, index=True, nullable=False)

    email = Column(String(255), unique=True, index=True, nullable=False)

    hashed_password = Column(String(255), nullable=False)

    role = Column(String(30), nullable=False)

    created_at = Column(
    DateTime,
    default=datetime.utcnow,
    nullable=False
)

    updated_at = Column(
    DateTime,
    default=datetime.utcnow,
    onupdate=datetime.utcnow
)

class Patient(Base):
    __tablename__ = "patients"

    id = Column(Integer, primary_key=True, index=True)

    patient_id = Column(String(20), unique=True, index=True, nullable=False)

    first_name = Column(String(100), nullable=False)

    last_name = Column(String(100), nullable=False)

    date_of_birth = Column(Date, nullable=False)

    gender = Column(String(20), nullable=False)

    phone = Column(String(20))

    email = Column(String(255))

    address = Column(Text)

    created_at = Column(
    DateTime,
    default=datetime.utcnow,
    nullable=False
)

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    