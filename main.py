from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI

from sqlalchemy import Engine
from sqlmodel import SQLModel

from .models import User, UserRead
from .db import get_engine
from .auth import get_current_active_user


@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = get_engine()
    init_db(engine)
    yield


app = FastAPI(lifespan=lifespan)


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
