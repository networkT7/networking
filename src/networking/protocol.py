from typing import TypedDict


class NodeConfig(TypedDict):
    MAC: str
    IP: int
    port: int


MACaddr = str


def _valid_MAC(MAC: str) -> bool:
    return isinstance(MAC, str) and len(MAC) == 2
