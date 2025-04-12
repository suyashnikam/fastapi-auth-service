from pydantic import BaseModel, EmailStr
from typing import Optional
from enum import Enum

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    STAFF = "STAFF"
    DELIVERY = "DELIVERY"
    CUSTOMER = "CUSTOMER"

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class AdminUserCreate(UserCreate):
    secret_key: str

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    is_staff: bool
    is_active: bool

    class Config:
        orm_mode = True

class UserLogin(BaseModel):
    email: str
    password: str

class UserValidationOut(BaseModel):
    user_id: int
    username: str
    email: str
    role: str
    is_active: bool
    is_valid: bool
