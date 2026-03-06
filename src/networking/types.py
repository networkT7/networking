from enum import IntEnum
from typing import TypedDict, TypeGuard

MACaddr = str
IPaddr = int


class IPProtocol(IntEnum):
    DATA = 0
    PING = 1
    ARP = 2


class MetaConf(TypedDict):
    HOSTNAME: str
    LOGGING_LEVEL: str
    RECEIVE_SIZE: int
    SOCKET_TIMEOUT: float


class NodeConfig(TypedDict):
    MAC: MACaddr
    IP: IPaddr
    wire: str


class WireConfig(TypedDict):
    port: int
    subnet: int
    subnetMask: int


RouterInterfaceConfig = NodeConfig


class RouterConfig(TypedDict):
    interfaces: dict[str, RouterInterfaceConfig]
    routing_table: dict[str, str]


class Config(TypedDict):
    config: MetaConf
    nodes: dict[str, NodeConfig]
    wires: dict[str, WireConfig]
    routers: dict[str, RouterConfig]


def valid_MAC(MAC: str) -> TypeGuard[MACaddr]:
    return isinstance(MAC, str) and len(MAC) == 2


def valid_IP(IP: int) -> TypeGuard[IPaddr]:
    return isinstance(IP, int) and IP > 0 and IP < 256
