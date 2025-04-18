from datetime import datetime
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from users_core.validators import (
    EmailStructValidator,
    PasswordHasher,
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
PasswordValue = Annotated[
    str,
    BeforeValidator(PasswordHasher()),
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
    value: PasswordValue
    created_at: datetime = Field(default_factory=datetime.now)

    model_config = ConfigDict(from_attributes=True)
