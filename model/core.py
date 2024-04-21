from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship, declarative_base

from model.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    role = Column(String,default='user')


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    nameofproject = Column(String, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))

class Role(Base):
    __tablename__ = 'roles'

    id= Column(Integer,primary_key=True,index=True)
    name= Column(String)
    permissions= Column(String)

