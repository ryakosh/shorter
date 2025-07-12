from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from pydantic import BaseModel
from fastapi import HTTPException, Depends, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from sqlalchemy import Engine
from sqlmodel import Session, select

from settings import Settings, get_settings

from ..models import User
from ..db import get_engine

from .exceptions import CredentialsException, InvalidUsernamePassword

router = APIRouter(prefix="/auth")
pass_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str


def verify_passwd(plain: str, hashed: str) -> bool:
    """Compare a plain password against a provided hashed version.

    Args:
        plain (str): The plain passowrd to compare.
        hashed (str): The hashed version of the password to compare against.

    Returns:
        bool: 'True' if 'hashed' is the hashed version of the 'plain', False otherwise."""

    return pass_ctx.verify(plain, hashed)


def hash_passwd(plain: str) -> str:
    """Hash the provided password.

    Args:
        plain (str): The plain password to be hashed.

    Returns:
        str: The hashed password.
    """

    return pass_ctx.hash(plain)


def get_user(engine: Engine, username: str) -> User | None:
    """Get user using the provided criteria.

    Args:
        engine: The database engine.
        username (str): User's username.

    Returns:
        User: If user was found.
        None: If user was not found.

    """

    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == username)).first()
        return user


def authenticate_user(engine: Engine, username: str, passwd: str) -> User | None:
    """Authenticate the user using the provided username and password.

    Args:
        engine (Engine): The database engine.
        username (str): User's username.
        password (str): User's password.

    Returns:
        User: If authentication was successful.
        None: If authentication was not successful.
    """

    user = get_user(engine, username)

    if user is None or verify_passwd(passwd, user.hashed_passwd):
        return None
    return user


def gen_access_token(
    payload: dict, expires_after: timedelta, secret: str, secret_alg: str
) -> str:
    """Generate a fresh access token for the user.

    Args:
        payload (dict): The payload to encode.
        expires_after (timedelta): Calculates and sets the 'exp' JWT claim.

    Returns:
        str: The encoded JWT.
    """

    payload_cpy = payload.copy()
    payload_cpy.update({"exp": datetime.now(timezone.utc) + expires_after})
    encoded_jwt = jwt.encode(payload_cpy, secret, secret_alg)

    return encoded_jwt


async def get_current_user(
    engine: Annotated[Engine, Depends(get_engine)],
    token: Annotated[str, Depends(oauth2_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> User:
    """Get the current authenticated user.

    Args:
        engine (Engine): The database engine.
        token (str): User's token.

    Returns:
        User: If token is valid and user exists.

    Raises:
        HTTPException: If token is invalid or user does not exist.
    """

    try:
        payload = jwt.decode(token, settings.secret, algorithms=[settings.secret_alg])
        username = payload.get("sub")

        if username is None:
            raise CredentialsException
        token_data = TokenData(username=username)
    except jwt.InvalidTokenError:
        raise CredentialsException
    user = get_user(engine, token_data.username)
    if user is None:
        raise CredentialsException

    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Get the current active user.

    Args:
        current_user (User): The current authenticated user.

    Returns:
        User: If user is activated.

    Raises:
        HTTPException: If user is not activated.
    """

    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    return current_user


@router.post("/token")
async def login_for_access_token(
    engine: Annotated[Engine, Depends(get_engine)],
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Token:
    user = authenticate_user(engine, form_data.username, form_data.password)
    if user is None:
        raise InvalidUsernamePassword
    expires_delta = timedelta(minutes=settings.token_expires_mins)
    access_token = gen_access_token(
        payload={"sub": user.username},
        expires_after=expires_delta,
        secret=settings.secret,
        secret_alg=settings.secret_alg,
    )

    return Token(access_token=access_token, token_type="bearer")
