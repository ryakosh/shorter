from typing import Annotated

from pydantic import EmailStr
from sqlmodel import Field, Relationship, SQLModel


class URLBase(SQLModel):
    url: Annotated[str, Field(max_length=2083)]


class URL(URLBase, table=True):
    id: Annotated[int | None, Field(primary_key=True)] = None

    s_url: str

    user_id: Annotated[int, Field(foreign_key="user.id")]
    user: "User" = Relationship(back_populates="urls")


class URLCreate(URLBase):
    pass


class UserBase(SQLModel):
    email: EmailStr
    username: str
    hashed_passwd: Annotated[str, Field(min_length=8)]


class User(UserBase, table=True):
    id: Annotated[int | None, Field(primary_key=True)] = None
    is_active: bool = False

    urls: list[URL] | None = Relationship(back_populates="user")


class UserCreate(UserBase):
    pass


class UserRead(SQLModel):
    id: int
    username: str
    email: str
    is_active: bool
