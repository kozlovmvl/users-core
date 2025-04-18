import hashlib
import string
from typing import Protocol, runtime_checkable


class UsernameIinvalidLength(Exception): ...


class UsernameInvalidSymbol(Exception): ...


class EmailInvalidStruct(Exception): ...


class PasswordInvalidLength(Exception): ...


class PasswordInvalidSymbol(Exception): ...


@runtime_checkable
class BaseValidator[T](Protocol):
    def __call__(self, value: T) -> T:
        return self.validate(value)

    def validate(self, value: T) -> T:
        raise NotImplementedError


@runtime_checkable
class BasePasswordHasher(Protocol):
    algorithms: list[str]

    @property
    def prefix(self) -> str:
        return ",".join(self.algorithms) + ";"

    def make_hash(self, value: str) -> str:
        raise NotImplementedError


class UsernameLengthValidator(BaseValidator):
    min_length = 3

    def validate(self, value: str) -> str:
        if len(value) < self.min_length:
            raise UsernameIinvalidLength
        return value


class UsernameSymbolsValidator(BaseValidator):
    valid_symbols = string.digits + string.ascii_letters

    def validate(self, value: str) -> str:
        if any([c not in self.valid_symbols for c in value]):
            raise UsernameInvalidSymbol
        return value


class EmailStructValidator(BaseValidator):
    def validate(self, value: str) -> str:
        parts = value.split("@")
        if len(parts) != 2 or parts[0] == "" or parts[1] == "":
            raise EmailInvalidStruct
        return value


class PasswordLengthValidator(BaseValidator):
    min_length = 8

    def validate(self, value: str) -> str:
        if len(value) < self.min_length:
            raise PasswordInvalidLength
        return value


class PasswordSymbolsValidator(BaseValidator):
    valid_ranges = [
        string.digits,
        string.ascii_uppercase,
        string.ascii_lowercase,
        string.punctuation,
    ]

    def validate(self, value: str) -> str:
        for valid_range in self.valid_ranges:
            if not any([c in valid_range for c in value]):
                raise PasswordInvalidSymbol
        return value


class PasswordHasher(BaseValidator, BasePasswordHasher):
    algorithms: list[str] = ["sha256"]

    def validate(self, value: str) -> str:
        return self.make_hash(value)

    def make_hash(self, value: str) -> str:
        result = value
        for alg in self.algorithms:
            hasher = hashlib.new(alg)
            hasher.update(result.encode())
            result = hasher.hexdigest()
        return self.prefix + result
