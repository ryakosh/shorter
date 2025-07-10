from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import Engine
from sqlmodel import SQLModel, Session, create_engine, select

import jwt

from passlib.context import CryptContext

from .settings import Settings
from .models import User, UserRead
from .deps import get_settings


app = FastAPI()
settings = get_settings()
engine = create_engine(
    settings.shorter_sql_url, connect_args={"check_same_thread": False}
)
pass_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str


CredentialsException = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)
InvalidUsernamePassword = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid email or password",
    headers={"WWW-Authenticate": "Bearer"},
)


def verify_password(plain: str, hashed: str) -> bool:
    return pass_ctx.verify(plain, hashed)


def get_password_hash(plain: str) -> str:
    return pass_ctx.hash(plain)


def get_user(engine: Engine, username: str) -> User | None:
    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == username)).first()
        return user


def authenticate_user(engine: Engine, username: str, password: str):
    user = get_user(engine, username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def gen_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.shorter_secret, settings.shorter_secret_alg
    )

    return encoded_jwt


async def get_engine() -> Engine:
    return engine


async def get_current_user(
    engine: Annotated[Engine, Depends(get_engine)],
    token: Annotated[str, Depends(oauth2_scheme)],
) -> User | None:
    try:
        payload = jwt.decode(
            token, settings.shorter_secret, algorithms=[settings.shorter_secret_alg]
        )
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
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    return current_user


@app.post("/token")
async def login_for_access_token(
    engine: Annotated[Engine, Depends(get_engine)],
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Token:
    user = authenticate_user(engine, form_data.username, form_data.password)
    if not user:
        raise InvalidUsernamePassword
    expires_delta = timedelta(minutes=settings.shorter_token_expires_mins)
    access_token = gen_access_token(
        data={"sub": user.username}, expires_delta=expires_delta
    )

    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=UserRead)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


def init_db(engine: Engine):
    SQLModel.metadata.create_all(engine)


@app.on_event("startup")  # TODO: Switch to Lifespans
async def on_startup():
    init_db(engine)
