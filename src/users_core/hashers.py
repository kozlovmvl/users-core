import hashlib
from typing import Protocol, runtime_checkable


@runtime_checkable
class BasePasswordHasher(Protocol):
    algorithms: list[str]

    @property
    def prefix(self) -> str:
        return ",".join(self.algorithms) + ";"

    def make_hash(self, value: str) -> str:
        raise NotImplementedError


class PasswordHasher(BasePasswordHasher):
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


password_hasher = PasswordHasher()
