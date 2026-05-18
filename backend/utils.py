import json
import os

BASE_DIR = os.path.dirname(__file__)
STORAGE_DIR = os.path.join(BASE_DIR, "storage")

os.makedirs(STORAGE_DIR, exist_ok=True)

def save_encrypted(dataset_id, data):

    path = os.path.join(STORAGE_DIR, f"{dataset_id}.json")

    with open(path, "w") as f:
        json.dump(data, f)

def load_encrypted(dataset_id):

    path = os.path.join(STORAGE_DIR, f"{dataset_id}.json")

    with open(path, "r") as f:
        return json.load(f)
        
