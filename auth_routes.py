import os
from datetime import timedelta
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi_jwt_auth import AuthJWT
import models, schemas, database

auth_router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

###User signup
@auth_router.post("/signup", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
async def signup(
    user: schemas.UserCreate,
    db: Session = Depends(database.get_db),
    Authorize: AuthJWT = Depends(AuthJWT)
):
    # 🔐 Admin signup requires secret key
    if user.role.value == "ADMIN":
        if user.secret_key != os.getenv("ADMIN_SECRET_KEY"):
            raise HTTPException(
                status_code=401,
                detail="Invalid Admin secret key provided. Please check again!"
            )

    # 🔐 Staff/Delivery user can only be created by an Admin
    elif user.role.value in ["STAFF", "DELIVERY"]:
        try:
            Authorize.jwt_required()
            claims = Authorize.get_raw_jwt()
            if claims.get("role") != "ADMIN":
                raise HTTPException(
                    status_code=403,
                    detail="Only admins can create staff/delivery users. Please provide a valid admin token."
                )
        except Exception:
            raise HTTPException(
                status_code=401,
                detail="Authorization token is required to create staff or delivery user."
            )

    # 📧 Check if email or username already exists
    if db.query(models.User).filter(models.User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if db.query(models.User).filter(models.User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")

    # 🔐 Hash password and create new user
    hashed_password = pwd_context.hash(user.password)
    new_user = models.User(
        username=user.username,
        email=user.email,
        password=hashed_password,
        role=user.role.value,
        is_active=True,
        is_staff=user.role in ["ADMIN", "STAFF"]
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user
