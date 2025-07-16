from datetime import datetime, timezone
from typing import Annotated

from pydantic import EmailStr, HttpUrl
from sqlmodel import Field, Relationship, SQLModel


def current_utc_time():
    return datetime.now(timezone.utc)


class URLBase(SQLModel):
    url: Annotated[str, Field(max_length=2083)]


class URL(URLBase, table=True):
    id: Annotated[int | None, Field(primary_key=True)] = None

    s_url: str | None = None

    user_id: Annotated[int, Field(foreign_key="user.id")]
    user: "User" = Relationship(back_populates="urls")
    resolutions: "Resolution" = Relationship(back_populates="url")


class URLCreate(SQLModel):
    url: HttpUrl


class URLRead(URLBase):
    id: int
    s_url: str
    user_id: int


class Resolution(SQLModel, table=True):
    id: Annotated[int | None, Field(primary_key=True)] = None
    timestamp: datetime = Field(default_factory=current_utc_time)

    url_id: Annotated[int, Field(foreign_key="url.id")]
    url: URL = Relationship(back_populates="resolutions")


class UserBase(SQLModel):
    email: EmailStr
    username: str


class User(UserBase, table=True):
    id: Annotated[int | None, Field(primary_key=True)] = None
    is_active: bool = False
    hashed_passwd: str

    urls: list[URL] | None = Relationship(back_populates="user")


class UserCreate(UserBase):
    passwd: Annotated[str, Field(min_length=8)]


class UserRead(UserBase):
    id: int
    is_active: bool
