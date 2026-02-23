from enum import IntEnum
from typing import TypeIs, TypedDict

HOSTNAME = "127.0.0.1"
BROADCAST_MAC = "\xff\xff"
BROADCAST_IP = 0xFF
BYTE_ENCODING_TYPE = "iso-8859-1"
MACaddr = str
IPaddr = int


class IPProtocol(IntEnum):
    PING = 1
    ARP = 2


class NodeConfig(TypedDict):
    MAC: MACaddr
    IP: IPaddr
    wire: str


def valid_MAC(MAC: str) -> TypeIs[MACaddr]:
    return isinstance(MAC, str) and len(MAC) == 2


def valid_IP(IP: int) -> TypeIs[IPaddr]:
    return isinstance(IP, int) and IP > 0 and IP < 256
