from fastapi import FastAPI
from sqlalchemy import Engine
from sqlmodel import SQLModel, create_engine

from .models import URL
from .deps import get_settings


app = FastAPI()
settings = get_settings()
engine = create_engine(
    settings.shorter_sql_url, connect_args={"check_same_thread": False}
)


def init_db(engine: Engine):
    SQLModel.metadata.create_all(engine)


@app.on_event("startup")  # TODO: Switch to Lifespans
async def on_startup():
    init_db(engine)
