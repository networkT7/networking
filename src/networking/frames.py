from __future__ import annotations
from collections.abc import Iterable
from dataclasses import dataclass
import random
from typing import override

from networking.constants import BYTE_ENCODING_TYPE
from networking.types import (
    MACaddr,
    IPaddr,
    valid_MAC,
    valid_IP,
    IPProtocol,
)


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
    __data: bytes

    @staticmethod
    def from_bytes(arr: bytes) -> MACFrame:
        """
        Deserialises a MAC frame from bytes
        """
        length = len(arr)
        if length < 5 or length > 261:
            raise DeserializationException("data is not a valid MAC frame")

        data = arr[5:]
        data_len = arr[4]
        actual_len = len(data)
        if data_len != actual_len:
            raise DeserializationException(
                f"data size {data_len} doesn't match with actual size {actual_len}"
            )

        return MACFrame(
            arr[:2].decode(BYTE_ENCODING_TYPE),
            arr[2:4].decode(BYTE_ENCODING_TYPE),
            data,
        )

    @property
    def data(self) -> bytes:
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
        Returns the destination of the frame
        """
        return self.__dst

    @override
    def __init__(self, src: str, dst: str, data: bytes):
        assert valid_MAC(src), "not a valid src MAC"
        assert valid_MAC(dst), "not a valid dst MAC"

        length = len(data)
        assert length <= 256, "data is too large for frame"

        self.__src = src
        self.__dst = dst
        self.__length = length
        self.__data = data

    def __len__(self):
        return self.__length

    def __bytes__(self):
        return (
            f"{self.__src}{self.__dst}{chr(self.__length)}".encode(BYTE_ENCODING_TYPE)
            + self.__data
        )


FRAGMENT_THRESHOLD = 251
FRAGMENT_INDICATOR_MASK = 1 << 7
FRAGMENT_OFFSET_MASK = 1 << 6
FRAGMENT_ID_MASK = (1 << 6) - 1


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
    __fragment_info: int
    """
    bit 0: indicates if the packet was fragmented
    bit 1: fragment ordering (either 0 or 1)
    bit 2-7: fragment ID
    """
    __data: bytes

    @staticmethod
    def from_bytes(arr: bytes) -> IPFrame:
        """
        Deserialises an IP frame from bytes
        """
        length = len(arr)
        if length < 5 or length > 260:
            raise DeserializationException("data is not a valid IP frame")

        try:
            protocol = IPProtocol(arr[2])
        except ValueError:
            raise DeserializationException("not a valid IP protocol")

        data = arr[5:]
        data_len = arr[3]
        fragment_info = arr[4]
        actual_len = len(data)
        if data_len != actual_len:
            raise DeserializationException(
                f"data size {data_len} doesn't match with actual size {actual_len}"
            )

        return IPFrame(arr[0], arr[1], protocol, data, fragment_info=fragment_info)

    def fragment_frame(self) -> Iterable[IPFrame]:
        data = self.data
        if len(data) <= FRAGMENT_THRESHOLD:
            return [self]
        id = random.randint(1, FRAGMENT_ID_MASK)

        return [
            IPFrame(
                self.source,
                self.destination,
                self.protocol,
                data[d * FRAGMENT_THRESHOLD : (d + 1) * FRAGMENT_THRESHOLD],
                fragment_info=FRAGMENT_INDICATOR_MASK | (d << 6) | id,
            )
            for d in range(2)
        ]

    @staticmethod
    def defragment_frame(frames: list[IPFrame]) -> IPFrame:
        """
        Converts the fragmented frames to a single IP frame
        """
        if len(frames) < 2:
            raise DeserializationException("not enough frames to deserialize")

        if any([not f.is_fragmented for f in frames]):
            raise DeserializationException("fragment bit not set for all frames")

        for attr in ["fragment_id", "source", "destination", "protocol"]:
            first = getattr(frames[0], attr)
            if any(first != getattr(f, attr) for f in frames):
                raise DeserializationException(f"{attr} not same for all frames")

        sorted_frames = sorted(frames, key=lambda f: f.fragment_offset)
        data = b"".join([f.data for f in sorted_frames])
        f = sorted_frames[0]
        return IPFrame(f.source, f.destination, f.protocol, data)

    @property
    def data(self) -> bytes:
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
        Returns the destination of the frame
        """
        return self.__dst

    @property
    def protocol(self) -> IPProtocol:
        """
        Returns the protocol used for the IP packet
        """
        return self.__protocol

    @property
    def is_fragmented(self) -> bool:
        """
        Returns if the frame was fragmented
        """
        return bool(self.__fragment_info & FRAGMENT_INDICATOR_MASK)

    @property
    def fragment_offset(self) -> int:
        """
        Returns the offset of the frame fragment
        """
        return self.__fragment_info & FRAGMENT_OFFSET_MASK

    @property
    def fragment_id(self) -> int:
        """
        Returns the fragment id used for the IP packet
        """
        return self.__fragment_info & FRAGMENT_ID_MASK

    @override
    def __init__(
        self,
        src: int,
        dst: int,
        protocol: IPProtocol,
        data: bytes = b"",
        fragment_info: int = 0,
    ):
        assert valid_IP(src), "not a valid src IP"
        assert valid_IP(dst), "not a valid dst IP"
        assert protocol in IPProtocol, "not a valid protocol"

        length = len(data)
        assert length <= 256, "data is too large for frame"

        self.__src = src
        self.__dst = dst
        self.__protocol = protocol
        self.__fragment_info = fragment_info
        self.__length = length
        self.__data = data

    def __len__(self):
        return self.__length

    def __bytes__(self):
        return (
            f"{chr(self.__src)}{chr(self.__dst)}{chr(self.__protocol.value)}{chr(self.__length)}{chr(self.__fragment_info)}".encode(
                BYTE_ENCODING_TYPE
            )
            + self.__data
        )
