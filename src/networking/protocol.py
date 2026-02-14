from typing import TypeGuard

type MACaddr = str


def _valid_MAC(MAC: str | MACaddr) -> TypeGuard[MACaddr]:
    return isinstance(MAC, str) and len(MAC) == 2
