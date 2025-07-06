from typing import Annotated

from sqlmodel import Field, SQLModel


class URLBase(SQLModel):
    url: Annotated[str, Field(max_length=2083)]


class URL(URLBase, table=True):
    id: Annotated[int | None, Field(primary_key=True)] = None
    s_url: str


class URLCreate(URLBase):
    pass
