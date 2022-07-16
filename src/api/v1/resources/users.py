from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from src.api.v1.schemas import Token, UserCreate, UserModel
from src.core import config
from src.core.jwt import create_access_token
from src.services import UserService, get_user_service

router = APIRouter()


@router.post(
    path="/login",
    response_model=Token
)
def login(post_service: UserService = Depends(get_user_service),
          form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
    user = post_service.authenticate(username=form_data.username,
                                     password=form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    return Token(**{
        "access_token": create_access_token(
            data={"uuid": str(user.uuid),
                  "username": user.username,
                  "email": user.email
                  },
            expires_delta=access_token_expires
        ),
        "token_type": "bearer",
    })


@router.post(
    path="/signup",
    response_model=UserModel,
    summary="Зарегистрировать пользователя",
)
def user_create(
        user: UserCreate, post_service: UserService = Depends(get_user_service),
) -> UserModel:
    user: dict = post_service.create_user(user=user)
    return UserModel(**user)
