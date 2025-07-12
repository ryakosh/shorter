from datetime import timedelta
from typing import Annotated

from fastapi import Depends, FastAPI
from fastapi.security import OAuth2PasswordRequestForm

from sqlalchemy import Engine
from sqlmodel import SQLModel


from .settings import Settings, get_settings
from .models import User, UserRead
from .db import get_engine
from .auth import (
    Token,
    InvalidUsernamePassword,
    gen_access_token,
    authenticate_user,
    get_current_active_user,
)


app = FastAPI()


@app.post("/token")
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


@app.get("/users/me/", response_model=UserRead)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


def init_db(engine: Engine):
    """Initialize the database.

    Args:
        engine (Engine): The database engine.
    """

    SQLModel.metadata.create_all(engine)


@app.on_event("startup")  # TODO: Switch to Lifespans
async def on_startup():
    engine = get_engine()
    init_db(engine)
