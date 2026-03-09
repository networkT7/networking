from enum import IntEnum
from typing import TypedDict, TypeGuard, NotRequired

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
    firewall: NotRequired[bool]


class WireConfig(TypedDict):
    port: int
    subnet: int
    subnetMask: int


class RouterConfig(TypedDict):
    interfaces: dict[str, NodeConfig]
    routing_table: dict[int, str]


class Config(TypedDict):
    config: MetaConf
    nodes: dict[str, NodeConfig]
    wires: dict[str, WireConfig]
    routers: RouterConfig


def valid_MAC(MAC: str) -> TypeGuard[MACaddr]:
    return len(MAC) == 2


def valid_IP(IP: int) -> TypeGuard[IPaddr]:
    return IP > 0 and IP < 256
