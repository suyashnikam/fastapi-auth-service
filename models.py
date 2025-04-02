from sqlalchemy import Column, Integer, String, Boolean, Text, Enum
from sqlalchemy.orm import relationship
from database import Base
import enum
#
# class RoleEnum(str, enum.Enum):
#     admin = "admin"
#     customer = "customer"
#     delivery_person = "delivery_person"


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(25), unique=True)
    email = Column(String(80), unique=True)
    password = Column(Text, nullable=True)
    is_staff = Column(Boolean, default=False)
    is_active = Column(Boolean, default=False)

    def __repr__(self):
        return f"<User {self.username}>"