import os
from datetime import timedelta
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi_jwt_auth import AuthJWT
import models, schemas, database

auth_router = APIRouter(prefix="/auth", tags=["auth"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@auth_router.post("/signup", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
async def signup(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    hashed_password = pwd_context.hash(user.password)
    db_user = models.User(username=user.username, email=user.email, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@auth_router.post("/login")
async def login(user: schemas.UserLogin, db: Session = Depends(database.get_db), Authorize: AuthJWT = Depends()):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user is None or not pwd_context.verify(user.password, db_user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token_expires = timedelta(minutes=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES")))
    refresh_token_expires = timedelta(minutes=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_MINUTES")))

    access_token = Authorize.create_access_token(subject=db_user.email, expires_time=access_token_expires)
    refresh_token = Authorize.create_refresh_token(subject=db_user.email, expires_time=refresh_token_expires)
    return {"access_token": access_token, "refresh_token": refresh_token}

#refreshing tokens
@auth_router.get('/refresh')
async def refresh_token(Authorize:AuthJWT=Depends()):
    try:
        Authorize.jwt_refresh_token_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="PLease provide a valid refresh token")

    current_user = Authorize.get_jwt_subject()
    access_token = Authorize.create_access_token(subject=current_user)
    response = {
        "access": access_token,
    }
    return response


@auth_router.get("/validate", status_code=status.HTTP_200_OK)
async def validate_user(Authorize: AuthJWT = Depends(), db: Session = Depends(database.get_db)):
    try:
        Authorize.jwt_required()
        current_user_email = Authorize.get_jwt_subject()
        db_user = db.query(models.User).filter(models.User.email == current_user_email).first()

        if not db_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"is_valid": False, "message": "User not found"}
            )

        return {"is_valid": True, "username": db_user.username, "email": db_user.email}

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"is_valid": False, "message": "Invalid token"}
        )


