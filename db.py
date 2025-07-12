from functools import lru_cache

from sqlalchemy import Engine
from sqlmodel import create_engine

from .settings import get_settings


@lru_cache
def get_engine() -> Engine:
    """Get the database engine.

    Returns:
        Engine: The database engine.
    """

    settings = get_settings()

    return create_engine(settings.sql_url, connect_args={"check_same_thread": False})
