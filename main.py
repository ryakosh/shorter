from typing import Annotated

from fastapi import Depends, FastAPI

from sqlalchemy import Engine
from sqlmodel import SQLModel

from .models import User, UserRead
from .db import get_engine
from .auth import get_current_active_user


app = FastAPI()


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
