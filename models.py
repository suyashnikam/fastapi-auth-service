from sqlalchemy import Column, Integer, String, Boolean, Text, Enum
from sqlalchemy.orm import relationship
from database import Base
import enum

class UserRole(enum.Enum):
    ADMIN = "ADMIN"
    STAFF = "STAFF"
    DELIVERY = "DELIVERY"
    CUSTOMER = "CUSTOMER"

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(25), unique=True)
    email = Column(String(80), unique=True)
    password = Column(Text, nullable=True)
    is_staff = Column(Boolean, default=False)
    is_active = Column(Boolean, default=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.CUSTOMER)

    def __repr__(self):
        return f"<User {self.username} - {self.role.value}>"