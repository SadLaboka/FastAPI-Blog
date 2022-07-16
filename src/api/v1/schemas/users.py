import uuid as uuid_pkg

from datetime import datetime

from pydantic import BaseModel

__all__ = (
    "Token",
    "UserModel",
    "UserCreate",
)


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenPayload(BaseModel):
    uuid: uuid_pkg.UUID
    username: int
    email: int


class UserBase(BaseModel):
    username: str
    email: str


class UserCreate(UserBase):
    password: str


class UserModel(UserBase):
    uuid: uuid_pkg.UUID
    created_at: datetime
    is_superuser: bool
    is_active: bool
