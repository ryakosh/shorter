from typing import Annotated

from fastapi import FastAPI
from sqlalchemy import Engine
from sqlmodel import Field, SQLModel, create_engine

from .deps import get_settings


app = FastAPI()
settings = get_settings()
engine = create_engine(
    settings.shorter_sql_url, connect_args={"check_same_thread": False}
)


class URLBase(SQLModel):
    url: Annotated[str, Field(max_length=2083)]


class URL(URLBase, table=True):
    id: Annotated[int | None, Field(primary_key=True)] = None
    s_url: str


class URLCreate(URLBase):
    pass


def init_db(engine: Engine):
    SQLModel.metadata.create_all(engine)


@app.on_event("startup")  # TODO: Switch to Lifespans
async def on_startup():
    init_db(engine)
