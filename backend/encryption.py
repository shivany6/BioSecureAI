# encryption.py
import os
import json
import base64
from typing import Dict, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

BASE_DIR = os.path.dirname(__file__)
MASTER_KEY_PATH = os.path.join(BASE_DIR, "master.key")

# Create/load persistent 32-byte master key
if os.path.exists(MASTER_KEY_PATH):
    MASTER_KEY = open(MASTER_KEY_PATH, "rb").read()
else:
    MASTER_KEY = AESGCM.generate_key(bit_length=256)
    with open(MASTER_KEY_PATH, "wb") as f:
        f.write(MASTER_KEY)

def derive_role_key(role: str) -> bytes:
    """
    Deterministic role-based key derivation from MASTER_KEY using HKDF.
    This allows server to derive same role key on demand without storing multiple keys.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=role.encode(),
    )
    return hkdf.derive(MASTER_KEY)

def encrypt_cell(aes_key: bytes, plaintext: str) -> Dict[str,str]:
    """
    Encrypt a single value with AES-GCM, return base64-encoded nonce + ciphertext.
    """
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, ("" if plaintext is None else str(plaintext)).encode("utf8"), None)
    return {"nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ct).decode()}

def decrypt_cell(aes_key: bytes, encobj: Dict[str,str]) -> str:
    aesgcm = AESGCM(aes_key)
    nonce = base64.b64decode(encobj["nonce"])
    ct = base64.b64decode(encobj["ciphertext"])
    pt = aesgcm.decrypt(nonce, ct, None)
    return pt.decode("utf8")

def encrypt_row(master_or_role_key: bytes, row: dict) -> dict:
    """
    row: dict col->value (any)
    returns: dict col -> {nonce,ciphertext}
    """
    enc = {}
    for col, val in row.items():
        enc[col] = encrypt_cell(master_or_role_key, "" if val is None else str(val))
    return enc

def decrypt_row_columns(role_key: bytes, enc_row: dict, cols: List[str]) -> dict:
    """
    Decrypt only the columns in 'cols' from enc_row.
    """
    out = {}
    for c in cols:
        if c in enc_row:
            try:
                out[c] = decrypt_cell(role_key, enc_row[c])
            except Exception as e:
                out[c] = f"<decrypt_err:{str(e)}>"
        else:
            out[c] = None
    return out
