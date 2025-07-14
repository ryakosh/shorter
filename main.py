from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status

from sqlalchemy import Engine
from sqlmodel import SQLModel, Session, select

from .auth.hashing import hash_passwd

from .models import User, UserCreate, UserRead
from .db import get_session
from .auth import get_current_active_user

AlreadyExistsException = HTTPException(
    status_code=status.HTTP_409_CONFLICT,
    detail="Already exists.",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    from .db import engine

    init_db(engine)
    yield


app = FastAPI(lifespan=lifespan)


@app.post("/users", status_code=status.HTTP_201_CREATED, response_model=UserRead)
def create_user(user_c: UserCreate, session: Annotated[Session, Depends(get_session)]):
    existing_user = session.exec(
        select(User).where(
            (User.username == user_c.username) | (User.email == user_c.email)
        )
    ).first()

    if existing_user is not None:
        raise AlreadyExistsException

    user = User(**user_c.model_dump(), hashed_passwd=hash_passwd(user_c.passwd))

    session.add(user)
    session.commit()
    session.refresh(user)

    return user


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
