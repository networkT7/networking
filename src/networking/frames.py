from __future__ import annotations
from dataclasses import dataclass
from typing import override

from networking.protocol import MACaddr, _valid_MAC


@dataclass
class MAC_frame:
    """
    The class describing the MAC frame sent and received
    This class includes convenience methods for serde
    of MAC_frames sent between nodes
    """
    __src: MACaddr
    __dst: MACaddr
    __length: int
    __data: str

    def from_bytes(byte_arr: bytes) -> MAC_frame:
        """
        Deserialises a MAC frame from bytes
        """
        length = len(byte_arr)
        assert length >= 5 and length <= 261, "data is not a valid MAC frame"

        arr = byte_arr.decode()
        data = arr[5:]
        data_len = ord(arr[4])
        actual_len = len(data)
        assert data_len == actual_len, f"data size {data_len} doesn't match with actual size {actual_len}"

        return MAC_frame(arr[:2], arr[2:4], data)

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
    def __init__(self, src: str | MACaddr, dst: str | MACaddr, data: str):
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
        return f"{self.__src}{self.__dst}{chr(self.__length)}{self.__data}".encode()
