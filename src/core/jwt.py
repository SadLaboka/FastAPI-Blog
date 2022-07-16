import jwt

from datetime import datetime, timedelta

from src.core.config import (
    JWT_ALGORITHM,
    JWT_SECRET_KEY,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

access_token_jwt_subject = "access"


def create_access_token(*, data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "sub": access_token_jwt_subject})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, JWT_ALGORITHM)
    return encoded_jwt
