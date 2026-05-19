from sqlalchemy import Column, Integer, String, Text, DateTime
from database import Base
from datetime import datetime

class EncryptedDataset(Base):

    __tablename__ = "encrypted_datasets"

    id = Column(Integer, primary_key=True, index=True)

    dataset_id = Column(String, unique=True, index=True)

    encrypted_data = Column(Text)
    
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(String, unique=True, index=True)

    email = Column(String, unique=True, index=True)

    hashed_password = Column(String)

    role = Column(String)

    created_at = Column(DateTime, default=datetime.utcnow)