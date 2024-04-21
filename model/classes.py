from pydantic import BaseModel

import redis
class UserBase(BaseModel):
    email: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    is_active: bool

    class Config:
        orm_mode = True

class ProjectBase(BaseModel):
    nameofproject: str

class ProjectCreate(ProjectBase):
    owner_id: int

    class Config:
        orm_mode = True


class ProjectRename(ProjectBase):
    pass

class Token(BaseModel):
    access_token: str
    token_type: str



class RedisManager:
    def __init__(self, url: str):
        self.redis_client = redis.from_url(url)

    async def set_token_expire(self, token: str):
        self.redis_client.setex(token, 7200, "active")

    async def update_token_expire(self, token: str):
        self.redis_client.expire(token, 7200)