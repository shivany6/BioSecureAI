from fastapi import APIRouter, Depends, Form, HTTPException
from sqlalchemy.orm import Session

from database import SessionLocal
from db_utils import create_user, authenticate_user
from auth import create_access_token


router = APIRouter()


def get_db():
    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()


@router.post("/register")
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


@router.post("/login")
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
    
    