import uuid

import pytest

from users_core.hashers import password_hasher
from users_core.models import Password, User
from users_core.validators import (
    EmailInvalidStruct,
    PasswordInvalidLength,
    PasswordInvalidSymbol,
    UsernameIinvalidLength,
    UsernameInvalidSymbol,
)


def test_valid_user():
    user = User(username="username", email="name@host")
    assert user.id
    assert user.username == "username"
    assert user.email == "name@host"


def test_valid_password():
    password = Password(user_id=uuid.uuid4(), raw="Pass@12345")
    assert password.hash.startswith(password_hasher.prefix)


@pytest.mark.parametrize(
    argnames=("username", "email", "exc"),
    argvalues=(
        ("us", "name@host", UsernameIinvalidLength),
        ("user!", "name@host", UsernameInvalidSymbol),
        ("username", "name", EmailInvalidStruct),
        ("username", "name@", EmailInvalidStruct),
        ("username", "@host", EmailInvalidStruct),
    ),
)
def test_invalid_user(username, email, exc):
    with pytest.raises(exc):
        _ = User(username=username, email=email)

    user = User(username="username", email="user@host")
    with pytest.raises(exc):
        user.username = username
        user.email = email


@pytest.mark.parametrize(
    argnames=("value", "exc"),
    argvalues=(
        ("pass", PasswordInvalidLength),
        ("PassWord1", PasswordInvalidSymbol),
        ("PassWord@", PasswordInvalidSymbol),
        ("password@1", PasswordInvalidSymbol),
        ("PASSWORD@1", PasswordInvalidSymbol),
    ),
)
def test_invalid_password(value, exc):
    with pytest.raises(exc):
        _ = Password(user_id=uuid.uuid4(), raw=value)
