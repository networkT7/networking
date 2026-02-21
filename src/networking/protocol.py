from typing import TypeIs, TypedDict


class NodeConfig(TypedDict):
    MAC: str
    IP: int
    wire: str


HOSTNAME = "127.0.0.1"
MACaddr = str


def _valid_MAC(MAC: str) -> TypeIs[MACaddr]:
    return isinstance(MAC, str) and len(MAC) == 2
