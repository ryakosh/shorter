from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from pydantic import BaseModel
from fastapi import HTTPException, Depends, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Session, select

from ..settings import Settings, get_settings
from ..models import User
from ..db import get_session

from .hashing import verify_passwd
from .exceptions import CredentialsException, InvalidUsernamePassword

router = APIRouter(prefix="/auth")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str


def get_user(session: Session, username: str) -> User | None:
    """Get user using the provided criteria.

    Args:
        session: The database session.
        username (str): User's username.

    Returns:
        User: If user was found.
        None: If user was not found.

    """

    user = session.exec(select(User).where(User.username == username)).first()
    return user


def authenticate_user(session: Session, username: str, passwd: str) -> User | None:
    """Authenticate the user using the provided username and password.

    Args:
        session (Session): The database session.
        username (str): User's username.
        password (str): User's password.

    Returns:
        User: If authentication was successful.
        None: If authentication was not successful.
    """

    user = get_user(session, username)

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
    session: Annotated[Session, Depends(get_session)],
    token: Annotated[str, Depends(oauth2_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> User:
    """Get the current authenticated user.

    Args:
        session (Session): The database session.
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
    user = get_user(session, token_data.username)
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
    session: Annotated[Session, Depends(get_session)],
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Token:
    user = authenticate_user(session, form_data.username, form_data.password)
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
