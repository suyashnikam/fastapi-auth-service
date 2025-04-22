from pydantic import BaseModel, EmailStr
from typing import Optional
from enum import Enum
from models import UserRole

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: Optional[UserRole] = UserRole.CUSTOMER
    secret_key: Optional[str] = None

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    is_staff: bool
    is_active: bool
    role: UserRole

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
    is_valid_delivery_person: bool
