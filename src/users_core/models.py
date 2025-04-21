from datetime import datetime
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, computed_field

from users_core.hashers import password_hasher
from users_core.validators import (
    EmailStructValidator,
    PasswordLengthValidator,
    PasswordSymbolsValidator,
    UsernameLengthValidator,
    UsernameSymbolsValidator,
)

Username = Annotated[
    str,
    BeforeValidator(UsernameSymbolsValidator()),
    BeforeValidator(UsernameLengthValidator()),
]
Email = Annotated[
    str,
    BeforeValidator(EmailStructValidator()),
]
RawPassword = Annotated[
    str,
    BeforeValidator(PasswordSymbolsValidator()),
    BeforeValidator(PasswordLengthValidator()),
]


class User(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    username: Username
    email: Email

    model_config = ConfigDict(from_attributes=True)


class Password(BaseModel):
    user_id: UUID
    raw: RawPassword | None = None
    created_at: datetime = Field(default_factory=datetime.now)

    model_config = ConfigDict(from_attributes=True)

    @computed_field
    @property
    def hash(self) -> str | None:
        if self.raw:
            return password_hasher.make_hash(self.raw)
