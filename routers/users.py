from sqlalchemy.orm import Session
from model import core


def get_users(db: Session, skip: int =0, limit: int=100):
    return db.query(core.User).offset(skip).limit(limit).all()


