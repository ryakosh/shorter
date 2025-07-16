from contextlib import asynccontextmanager
from typing import Annotated, cast

from fastapi import Depends, FastAPI, HTTPException, Path, status

from fastapi.responses import RedirectResponse
from sqlalchemy import Engine
from sqlmodel import SQLModel, Session, select

from .encoder import build_encoder
from .settings import get_settings

from .auth.hashing import hash_passwd

from .models import URL, Resolution, URLCreate, URLRead, User, UserCreate, UserRead
from .db import get_session

from . import auth
from .auth import get_current_active_user

AlreadyExistsException = HTTPException(
    status_code=status.HTTP_409_CONFLICT,
    detail="Already exists.",
)

NotFoundException = HTTPException(
    status_code=status.HTTP_404_NOT_FOUND, detail="Not found."
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    from .db import engine

    init_db(engine)
    yield


app = FastAPI(lifespan=lifespan)
encode = build_encoder(get_settings().alphabet)

app.include_router(auth.router)


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


@app.post("/urls", status_code=status.HTTP_201_CREATED, response_model=URLRead)
def create_url(
    url_c: URLCreate,
    user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_session)],
):
    url = URL(url=str(url_c.url), user_id=cast(int, user.id))

    session.add(url)
    session.commit()
    session.refresh(url)

    url.s_url = encode(cast(int, url.id))

    session.commit()
    session.refresh(url)

    return url


@app.get("/resolve_s_url/{s_url}")
def resolve_s_url(
    s_url: Annotated[str, Path(max_length=20)],
    session: Annotated[Session, Depends(get_session)],
):
    url = session.exec(select(URL).where(URL.s_url == s_url)).one_or_none()

    if url is None:
        raise NotFoundException

    resolution = Resolution(url_id=cast(int, url.id))

    session.add(resolution)
    session.commit()

    return RedirectResponse(url=url.url)


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
