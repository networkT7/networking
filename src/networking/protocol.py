from typing import TypeIs, TypedDict


class NodeConfig(TypedDict):
    MAC: str
    IP: int
    port: int


MACaddr = str


def _valid_MAC(MAC: str) -> TypeIs[MACaddr]:
    return isinstance(MAC, str) and len(MAC) == 2
