from functools import lru_cache
from typing import Optional

from fastapi import Depends
from sqlmodel import Session

from src.api.v1.schemas import UserCreate
from src.core.security import verify_password, get_password_hash
from src.db import AbstractCache, get_cache, get_session
from src.models import User
from src.services import ServiceMixin

__all__ = ("UserService", "get_user_service")


class UserService(ServiceMixin):
    def get_by_username(self, username: str) -> Optional[User]:
        return self.session.query(User).filter(User.username == username).first()

    def create_user(self, user: UserCreate) -> dict:
        """Creates user"""
        password_hash = get_password_hash(user.password)
        print(f'---\nusername={user.username}\nemail={user.email}\npass={password_hash}\n---')
        new_user = User(
            username=user.username,
            hashed_password=password_hash,
            email=user.email
        )
        self.session.add(new_user)
        self.session.commit()
        self.session.refresh(new_user)
        return new_user.dict()

    def authenticate(self, username: str, password: str) -> Optional[User]:
        user = self.get_by_username(username)
        if not user:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user


@lru_cache()
def get_user_service(
    cache: AbstractCache = Depends(get_cache),
    session: Session = Depends(get_session),
) -> UserService:
    return UserService(cache=cache, session=session)
