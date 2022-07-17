import jwt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jwt import PyJWTError
from starlette.status import HTTP_403_FORBIDDEN

from src.api.v1.schemas import Token, UserCreate, UserModel, UserLogin, UserUpdate
from src.core.config import JWT_SECRET_KEY, JWT_ALGORITHM
from src.core.jwt import create_access_token, create_refresh_token
from src.services import UserService, get_user_service

router = APIRouter()
reusable_oauth2 = OAuth2PasswordBearer(tokenUrl="/api/v1/login")


@router.post(
    path="/logout_all",
    summary="Выйти со всех устройств",
    tags=["users"]
)
def logout_all(user_service: UserService = Depends(get_user_service),
               token: str = Depends(reusable_oauth2)) -> dict:
    """Signs out from all devices"""
    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    jti = payload["jti"]
    uuid = payload["uuid"]
    user_service.block_access_token(jti)
    user_service.remove_all_refresh_tokens(uuid)
    return {"msg": "You have been logged out from all devices."}


@router.post(
    path="/logout",
    summary="Выйти",
    tags=["users"]
)
def logout(user_service: UserService = Depends(get_user_service),
           token: str = Depends(reusable_oauth2)) -> dict:
    """Logging out of this device"""
    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    jti = payload["jti"]
    uuid = payload["uuid"]
    refresh_jti = payload["refresh_jti"]
    user_service.block_access_token(jti)
    user_service.remove_refresh_token(uuid, refresh_jti)
    return {"msg": "You have been logged out."}


@router.post(
    path="/refresh",
    response_model=Token,
    summary="Обновить токен",
    tags=["users"]
)
def refresh_token(user_service: UserService = Depends(get_user_service),
                  token: str = Depends(reusable_oauth2)) -> Token:
    """Refreshes token"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except PyJWTError:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail="Could not validate credentials"
        )
    user_uuid = payload["uuid"]
    jti = payload["jti"]
    user_service.remove_refresh_token(user_uuid, jti)

    user = user_service.get_by_uuid(user_uuid)
    user_data = dict(UserModel(**user.dict()))
    user_data["uuid"] = str(user_data["uuid"])
    user_data["created_at"] = str(user_data["created_at"])

    refresh_token = create_refresh_token(user_uuid=user_uuid)
    refresh_jti = user_service.get_jti(refresh_token)

    return Token(**{
        "access_token": create_access_token(
            data=user_data,
            refresh_jti=refresh_jti
        ),
        "refresh_token": refresh_token
    })


@router.patch(
    path="/users/me",
    summary="Обновить профиль",
    tags=["users"]
)
def update_user_me(new_data: UserUpdate,
                   user_service: UserService = Depends(get_user_service),
                   token: str = Depends(reusable_oauth2)) -> dict:
    """Updates user information"""
    current_user = user_service.get_current_user(token)
    new_user = user_service.update_user(current_user, new_data)
    new_user_data = dict(UserModel(**new_user))
    new_user_data["uuid"] = str(new_user_data["uuid"])
    new_user_data["created_at"] = str(new_user_data["created_at"])

    user_service.block_access_token(token)

    response = {"msg": "Update is successful. Please use new access token."}

    response.update({"user": new_user_data})

    refresh_token = create_refresh_token(user_uuid=new_user_data["uuid"])
    refresh_jti = user_service.get_jti(refresh_token)

    access_token = create_access_token(
        refresh_jti=refresh_jti,
        data=new_user_data
    )
    response.update({"access_token": access_token})

    return response


@router.get(
    path="/users/me",
    summary="Профиль",
    tags=["users"]
)
def read_user_me(user_service: UserService = Depends(get_user_service),
                 token: str = Depends(reusable_oauth2)) -> dict:
    """Get current user"""
    current_user = user_service.get_current_user(token)
    response = {"user": UserModel(**current_user)}
    return response


@router.post(
    path="/login",
    response_model=Token,
    summary="Войти",
    tags=["users"]
)
def login(user: UserLogin, user_service: UserService = Depends(get_user_service), ) -> Token:
    """Authorizes the user"""
    user = user_service.authenticate(username=user.username,
                                     password=user.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user_data = dict(UserModel(**user.dict()))
    user_uuid = str(user_data["uuid"])
    user_data["uuid"] = user_uuid
    user_data["created_at"] = str(user_data["created_at"])

    refresh_token = create_refresh_token(user_uuid=user_uuid)
    refresh_jti = user_service.get_jti(refresh_token)

    access_token = create_access_token(
        refresh_jti=refresh_jti,
        data=user_data
    )

    user_service.add_refresh_token(refresh_token)

    return Token(**{
        "access_token": access_token,
        "refresh_token": refresh_token,
    })


@router.post(
    path="/signup",
    status_code=201,
    summary="Зарегистрировать пользователя",
    tags=["users"]
)
def user_create(
        user: UserCreate, user_service: UserService = Depends(get_user_service),
) -> dict:
    """Registers a user"""
    response = {"msg": "User created."}
    user: dict = user_service.create_user(user=user)
    response.update({"user": UserModel(**user)})
    return response
