from __future__ import annotations
from dataclasses import dataclass
from typing import override

from networking.protocol import MACaddr, IPaddr, _valid_MAC, _valid_IP, IPProtocol


class DeserializationException(Exception):
    def __init__(self, msg: str):
        super().__init__(msg)


@dataclass
class MACFrame:
    """
    The class describing the MAC frame sent and received
    This class includes convenience methods for serde
    of MAC_frames sent between nodes
    """
    __src: MACaddr
    __dst: MACaddr
    __length: int
    __data: str

    def from_bytes(byte_arr: bytes) -> MACFrame:
        """
        Deserialises a MAC frame from bytes
        """
        length = len(byte_arr)
        if length < 5 or length > 261:
            raise DeserializationException("data is not a valid MAC frame")

        arr = byte_arr.decode()
        data = arr[5:]
        data_len = ord(arr[4])
        actual_len = len(data)
        if data_len != actual_len:
            raise DeserializationException(f"data size {data_len} doesn't match with actual size {actual_len}")  # noqa

        return MACFrame(arr[:2], arr[2:4], data)

    @property
    def data(self) -> str:
        """
        Returns the encapsulated data
        """
        return self.__data

    @property
    def source(self) -> MACaddr:
        """
        Returns the source of the frame
        """
        return self.__src

    @property
    def destination(self) -> MACaddr:
        """
        Returns the encapsulated data
        """
        return self.__dst

    @override
    def __init__(self, src: MACaddr, dst: MACaddr, data: str):
        assert _valid_MAC(src), "not a valid src MAC"
        assert _valid_MAC(dst), "not a valid dst MAC"

        length = len(data)
        assert length <= 256, "data is too large for frame"

        self.__src = src
        self.__dst = dst
        self.__length = length
        self.__data = data

    def __len__(self):
        return self.__length

    def __bytes__(self):
        return f"{self.__src}{self.__dst}{chr(self.__length)}{self.__data}".encode()  # noqa


@dataclass
class IPFrame:
    """
    The class describing the IP frame sent and received
    This class includes convenience methods for serde
    of IP_frames sent between nodes
    """
    __src: IPaddr
    __dst: IPaddr
    __protocol: IPProtocol
    __length: int
    __data: str

    def from_bytes(byte_arr: bytes) -> IPFrame:
        """
        Deserialises an IP frame from bytes
        """
        length = len(byte_arr)
        if length < 4 or length > 260:
            raise DeserializationException("data is not a valid IP frame")

        arr = byte_arr.decode()
        try:
            protocol = IPProtocol(ord(arr[2]))
        except ValueError:
            raise DeserializationException("not a valid IP protocol")

        data = arr[4:]
        data_len = ord(arr[3])
        actual_len = len(data)
        if data_len != actual_len:
            raise DeserializationException(f"data size {data_len} doesn't match with actual size {actual_len}")  # noqa

        return IPFrame(ord(arr[0]), ord(arr[1]), protocol, data)

    @property
    def data(self) -> str:
        """
        Returns the encapsulated data
        """
        return self.__data

    @property
    def source(self) -> IPaddr:
        """
        Returns the source of the frame
        """
        return self.__src

    @property
    def destination(self) -> IPaddr:
        """
        Returns the encapsulated data
        """
        return self.__dst

    @property
    def protocol(self) -> IPProtocol:
        """
        Returns the encapsulated data
        """
        return self.__protocol

    @override
    def __init__(self, src: IPaddr, dst: IPaddr, protocol: IPProtocol, data: str):  # noqa
        assert _valid_IP(src), "not a valid src IP"
        assert _valid_IP(dst), "not a valid dst IP"
        assert protocol in IPProtocol, "not a valid protocol"

        length = len(data)
        assert length <= 252, "data is too large for frame"

        self.__src = src
        self.__dst = dst
        self.__protocol = protocol
        self.__length = length
        self.__data = data

    def __len__(self):
        return self.__length

    def __bytes__(self):
        return f"{chr(self.__src)}{chr(self.__dst)}{chr(self.__protocol.value)}{chr(self.__length)}{self.__data}".encode()  # noqa
