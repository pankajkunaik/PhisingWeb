"""
PhishGuard AI — Auth Router
Handles: /api/auth/register, /api/auth/login, /api/auth/me
"""
import os
import sys

# Absolute path resolution
_app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _app_dir not in sys.path:
    sys.path.insert(0, _app_dir)

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from database import get_db, User
from schemas.models import UserRegisterSchema, UserLoginSchema, TokenResponse, UserMeResponse
from services.auth import get_password_hash, verify_password, create_access_token, require_user

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(user_data: UserRegisterSchema, db: Session = Depends(get_db)):
    """Register a new user account."""
    existing = db.query(User).filter(User.email == user_data.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email is already registered")

    hashed_pwd = get_password_hash(user_data.password)
    new_user = User(email=user_data.email, password_hash=hashed_pwd)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "Registration successful", "email": new_user.email}


@router.post("/login", response_model=TokenResponse)
def login_user(user_data: UserLoginSchema, db: Session = Depends(get_db)):
    """Authenticate a user and return a JWT bearer token."""
    user = db.query(User).filter(User.email == user_data.email).first()
    if not user or not verify_password(user_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    token = create_access_token({"sub": user.email})
    return TokenResponse(access_token=token, token_type="bearer", email=user.email)


@router.get("/me")
def get_user_me(user: User = Depends(require_user)):
    """Return the currently authenticated user's profile."""
    return {"email": user.email, "id": user.id, "created_at": user.created_at}
