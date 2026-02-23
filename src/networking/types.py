from enum import IntEnum
from typing import TypeIs, TypedDict

MACaddr = str
IPaddr = int


class IPProtocol(IntEnum):
    PING = 1
    ARP = 2


class NodeConfig(TypedDict):
    MAC: MACaddr
    IP: IPaddr
    wire: str


class Config(TypedDict):
    HOSTNAME: str
    LOGGING_LEVEL: str
    RECEIVE_SIZE: int
    SOCKET_TIMEOUT: float


class MasterConfig(TypedDict):
    config: Config
    nodes: NodeConfig
    wires: dict[str, int]


def valid_MAC(MAC: str) -> TypeIs[MACaddr]:
    return isinstance(MAC, str) and len(MAC) == 2


def valid_IP(IP: int) -> TypeIs[IPaddr]:
    return isinstance(IP, int) and IP > 0 and IP < 256
