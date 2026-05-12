# utils.py
import os
import json

BASE_DIR = os.path.dirname(__file__)
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

def save_encrypted(dataset_id: str, encrypted_rows: list):
    path = os.path.join(STORAGE_DIR, f"{dataset_id}.json")
    with open(path, "w", encoding="utf8") as f:
        json.dump(encrypted_rows, f)
    return path

def load_encrypted(dataset_id: str):
    path = os.path.join(STORAGE_DIR, f"{dataset_id}.json")
    if not os.path.exists(path):
        raise FileNotFoundError("dataset not found")
    with open(path, "r", encoding="utf8") as f:
        return json.load(f)
