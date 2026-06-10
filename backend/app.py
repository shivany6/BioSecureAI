# app.py
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import uuid
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from roles import role_permissions


from encryption import MASTER_KEY, encrypt_row, decrypt_row_columns
from anomaly import run_isolation_forest
from db_utils import save_encrypted_db, load_encrypted_db
from fastapi import Depends
from sqlalchemy.orm import Session
from auth_dependencies import get_current_user

from database import SessionLocal
from db_utils import (
    create_user,
    authenticate_user
)

from auth import create_access_token

def get_db():
    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()


app = FastAPI(title="BioSecureAI Option3")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev only. Narrow this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "BioSecureAI Option3 backend running"}

@app.post("/upload_encrypt")
async def upload_encrypt(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """
    Upload CSV -> server reads it -> encrypts each row (per-cell) with admin-derived key -> store JSON -> return dataset_id & columns
    """
    try:
        df = pd.read_csv(file.file)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read CSV: {e}")

    all_columns = list(df.columns)
    dataset_id = str(uuid.uuid4())[:8]
    encrypted_rows = []

    # Encrypt all rows using MASTER_KEY
    for _, row in df.iterrows():
        row_dict = {col: row[col] for col in all_columns}
        enc = encrypt_row(MASTER_KEY, row_dict)

        encrypted_rows.append(enc)

    save_encrypted_db(dataset_id, encrypted_rows)
    return {"status":"ok", "dataset_id": dataset_id, "columns": all_columns, "rows": len(encrypted_rows)}

@app.post("/analyze_role")
async def analyze_role(
    dataset_id: str = Form(...),
    current_user: dict = Depends(get_current_user),
    contamination: float = Form(0.05)
):
    role = current_user["role"]
    try:
        enc_rows = load_encrypted_db(dataset_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="dataset not found")

    if not enc_rows:
        return {"status": "ok", "rows": []}

    # full columns
    all_columns = list(enc_rows[0].keys())

    admin_key = MASTER_KEY

    # decrypt only first row using admin for type detection
    first_dec = {}
    for col in all_columns:
        try:
            first_dec[col] = decrypt_row_columns(admin_key, enc_rows[0], [col])[col]
        except:
            first_dec[col] = None

    # detect numeric columns
    numeric_candidates = []
    for col, val in first_dec.items():
        try:
            float(val)
            numeric_candidates.append(col)
        except:
            pass

    # Role-based allowed columns (NEW SYSTEM)
    permissions = role_permissions(all_columns, numeric_candidates)
    allowed = permissions.get(role, [])

    # decrypt allowed columns safely
    decrypted_rows = []
    for enc in enc_rows:
        try:
            dec = decrypt_row_columns(MASTER_KEY, enc, allowed)
        except:
            # if role is restricted from decrypting a column -> skip
            dec = {col: "ACCESS_DENIED" for col in allowed}

        decrypted_rows.append(dec)

    # subset numeric columns for anomaly detection
    numeric_cols_allowed = [c for c in allowed if c in numeric_candidates]

    anomalies = run_isolation_forest(
        decrypted_rows,
        numeric_cols_allowed,
        contamination=contamination
    )

    # attach anomaly flags
    output_rows = []
    for row, a in zip(decrypted_rows, anomalies):
        r = row.copy()
        r["_is_anomaly"] = a["is_anomaly"]
        r["_anomaly_score"] = a["score"]
        output_rows.append(r)

    return JSONResponse({
        "status": "ok",
        "dataset_id": dataset_id,
        "columns": allowed,
        "rows": output_rows,
        "counts": {"anomaly_count": sum(r["_is_anomaly"] for r in output_rows)}
    })

@app.post("/decrypt_full")
async def decrypt_full(
    dataset_id: str = Form(...),
    current_user: dict = Depends(get_current_user)
):

    # ONLY ADMIN ALLOWED
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    try:
        enc_rows = load_encrypted_db(dataset_id)

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="dataset not found"
        )

    admin_key = MASTER_KEY

    all_columns = list(enc_rows[0].keys())

    out_rows = []

    for enc in enc_rows:

        dec_row = decrypt_row_columns(
            admin_key,
            enc,
            all_columns
        )

        out_rows.append(dec_row)

    return JSONResponse({
        "status": "ok",
        "dataset_id": dataset_id,
        "rows": out_rows
    })

@app.get("/get_master_key_dev")
def get_master_key_dev():
    """DEV only: return base64 encoded master key. REMOVE for public deployment."""
    return {"master_key_b64": base64.b64encode(MASTER_KEY).decode()}
@app.post("/encrypt_file")
async def encrypt_file(file: UploadFile = File(...)):
    """
    Encrypt the entire CSV file as a single binary using AES-GCM.
    Returns ciphertext, iv, and tag (all base64 encoded).
    """
    try:
        raw_data = await file.read()   # read file bytes
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {e}")

    # STEP 1: generate random AES key
    aes_key = get_random_bytes(32)  # 256-bit key

    # STEP 2: generate random IV (nonce)
    iv = get_random_bytes(12)       # GCM recommended size

    # STEP 3: create AES-GCM cipher with IV
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)

    # STEP 4: encrypt the file
    ciphertext, tag = cipher.encrypt_and_digest(raw_data)

    # STEP 5: return all important values to client
    return {
        "status": "ok",
        "key_b64": base64.b64encode(aes_key).decode(),
        "iv_b64": base64.b64encode(iv).decode(),
        "tag_b64": base64.b64encode(tag).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "file_name": file.filename
    }

from fastapi import Form

@app.post("/register")
def register(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    db: Session = Depends(get_db)
):

    user = create_user(
        db,
        username,
        email,
        password,
        role
    )

    return {
        "message": "User created successfully",
        "user_id": user.id
    }

@app.post("/login")
def login(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):

    user = authenticate_user(
        db,
        username,
        password
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    token = create_access_token(
        data={
            "sub": user.username,
            "role": user.role
        }
    )

    return {
        "access_token": token,
        "token_type": "bearer"
    }
    