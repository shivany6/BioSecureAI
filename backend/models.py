from sqlalchemy import Column, Integer, String, Text
from database import Base

class EncryptedDataset(Base):

    __tablename__ = "encrypted_datasets"

    id = Column(Integer, primary_key=True, index=True)

    dataset_id = Column(String, unique=True, index=True)

    encrypted_data = Column(Text)
    
