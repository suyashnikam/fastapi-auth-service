import os
from datetime import timedelta
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi_jwt_auth import AuthJWT
import models, schemas, database
from schemas import UserRole

auth_router = APIRouter(prefix="/auth", tags=["auth"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

#create user(customer registration)
@auth_router.post("/signup", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
async def signup(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")

    hashed_password = pwd_context.hash(user.password)

    db_user = models.User(
        username=user.username,
        email=user.email,
        password=hashed_password,
        role=UserRole.CUSTOMER,
        is_staff=False,
        is_active=True
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

#create admin user (admin secret key is required)
@auth_router.post("/create-admin-user", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
async def create_admin(user: schemas.AdminUserCreate, db: Session = Depends(database.get_db)):
    if user.secret_key != os.getenv("ADMIN_SECRET_KEY"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid secret key")

    db_user = db.query(models.User).filter(models.User.email == user.email).first()

    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    hashed_password = pwd_context.hash(user.password)

    admin_user = models.User(
        username=user.username,
        email=user.email,
        password=hashed_password,
        role=UserRole.ADMIN,
        is_staff=True,
        is_active=True
    )
    db.add(admin_user)
    db.commit()
    db.refresh(admin_user)
    return admin_user


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
        "role": db_user.role.value,  # Assuming db_user.role is an Enum
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


#create staff user( only admin access)
@auth_router.post("/create-staff-user", response_model=schemas.UserOut)
async def create_staff(
    user: schemas.UserCreate,
    db: Session = Depends(database.get_db),
    Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required()
    claims = Authorize.get_raw_jwt()
    if claims.get("role") != "ADMIN":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can create staff users")

    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already exists")

    hashed_password = pwd_context.hash(user.password)
    new_user = models.User(
        username=user.username,
        email=user.email,
        password=hashed_password,
        role="STAFF",
        is_active=True,
        is_staff=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

#create delivery type user( Only admin Access)
@auth_router.post("/create-delivery-user", response_model=schemas.UserOut)
async def create_delivery(
    user: schemas.UserCreate,
    db: Session = Depends(database.get_db),
    Authorize: AuthJWT = Depends()
):
    try:
        Authorize.jwt_required()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please provide a valid access token in headers"
        )
    claims = Authorize.get_raw_jwt()
    if claims.get("role") != "ADMIN":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can create delivery users")

    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already exists")

    hashed_password = pwd_context.hash(user.password)
    new_user = models.User(
        username=user.username,
        email=user.email,
        password=hashed_password,
        role="DELIVERY",
        is_active=True,
        is_staff=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

#Get all active users (Admin access)
@auth_router.get("/active-users")
async def get_active_users(
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
            "role": user.role.value  # Assuming it's an Enum
        }
        for user in active_users
    ]

    return response
