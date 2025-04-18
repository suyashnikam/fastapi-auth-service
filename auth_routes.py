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

#login to get access token and refresh token
@auth_router.post("/login")
async def login(user: schemas.UserLogin, db: Session = Depends(database.get_db), Authorize: AuthJWT = Depends()):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user is None or not pwd_context.verify(user.password, db_user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token_expires = timedelta(minutes=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES")))
    refresh_token_expires = timedelta(minutes=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_MINUTES")))

    # Include role and user_id in the JWT custom claims
    user_claims = {
        "username": db_user.username,
        "role": db_user.role.value,
        "user_id": db_user.id
    }

    access_token = Authorize.create_access_token(
        subject=db_user.email,
        user_claims=user_claims,
        expires_time=access_token_expires
    )
    refresh_token = Authorize.create_refresh_token(
        subject=db_user.email,
        expires_time=refresh_token_expires
    )

    return {"access_token": access_token, "refresh_token": refresh_token}

#refresh your access token using refresh token
@auth_router.get('/refresh')
async def refresh_token(Authorize: AuthJWT = Depends(), db: Session = Depends(database.get_db)):
    try:
        Authorize.jwt_refresh_token_required()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please provide a valid refresh token"
        )

    current_user_email = Authorize.get_jwt_subject()
    db_user = db.query(models.User).filter(models.User.email == current_user_email).first()

    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    access_token = Authorize.create_access_token(
        subject=db_user.email,
        user_claims={
            "user_id": db_user.id,
            "username": db_user.username,
            "role": db_user.role.value
        }
    )

    return {"access_token": access_token}


#validate token
@auth_router.get("/validate", status_code=status.HTTP_200_OK)
async def validate_user(Authorize: AuthJWT = Depends()):
    try:
        Authorize.jwt_required()

        raw_jwt = Authorize.get_raw_jwt()
        return {
            "is_valid": True,
            "email": Authorize.get_jwt_subject(),
            "user_id": raw_jwt.get("user_id"),
            "username": raw_jwt.get("username"),
            "role": raw_jwt.get("role")
        }

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"is_valid": False, "message": "Invalid token"}
        )

#Get all active users (Admin access)
@auth_router.get("/users")
async def get_users(
    db: Session = Depends(database.get_db),
    Authorize: AuthJWT = Depends()
):
    try:
        Authorize.jwt_required()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please provide a valid access token"
        )

    claims = Authorize.get_raw_jwt()
    if claims.get("role") != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can access this endpoint"
        )

    active_users = db.query(models.User).filter(models.User.is_active == True).all()

    response = [
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_staff": user.is_staff,
            "is_active": user.is_active,
            "role": user.role.value
        }
        for user in active_users
    ]
    return response


##validate user by id
@auth_router.get("/validate-user/{user_id}", response_model=schemas.UserValidationOut)
async def validate_user_by_id(
    user_id: int,
    Authorize: AuthJWT = Depends(),
    db: Session = Depends(database.get_db)
):
    try:
        Authorize.jwt_required()
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")

    claims = Authorize.get_raw_jwt()
    if claims.get("role") not in ["ADMIN", "STAFF"]:
        raise HTTPException(status_code=403, detail="Access denied")

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "is_active": user.is_active,
        "is_valid_delivery_person": user.role.value == "DELIVERY" and user.is_active
    }
