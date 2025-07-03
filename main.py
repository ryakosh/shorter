import os
from typing import Annotated

from fastapi import FastAPI
from sqlmodel import Field, SQLModel, create_engine


class InvalidConfig(Exception):
    pass


app = FastAPI()
SQL_URL = os.getenv("SHORTENER_SQL_URL")

if SQL_URL is None:
    raise InvalidConfig("Please set 'SHORTENER_SQLITE_URL'")

SQL_ENGINE = create_engine(SQL_URL, connect_args={"check_same_thread": False})


class URLBase(SQLModel):
    url: Annotated[str, Field(max_length=2083)]


class URL(URLBase, table=True):
    id: Annotated[int | None, Field(primary_key=True)] = None
    s_url: str


class URLCreate(URLBase):
    pass


def init_db():
    SQLModel.metadata.create_all(SQL_ENGINE)


@app.on_event("startup")  # TODO: Switch to Lifespans
async def on_startup():
    init_db()
