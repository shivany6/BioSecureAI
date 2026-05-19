import json

from database import SessionLocal
from models import EncryptedDataset

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
    