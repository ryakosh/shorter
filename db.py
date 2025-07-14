from collections.abc import Generator
from functools import lru_cache

from sqlmodel import Session, create_engine

from .settings import get_settings


engine = create_engine(
    get_settings().sql_url, connect_args={"check_same_thread": False}
)


@lru_cache
def get_session() -> Generator[Session, None]:
    """Get the database engine.

    Returns:
        Engine: The database engine.
    """

    with Session(engine) as session:
        yield session
