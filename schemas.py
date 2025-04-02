from pydantic import BaseModel
from typing import Optional

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

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
