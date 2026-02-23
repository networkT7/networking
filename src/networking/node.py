from dataclasses import dataclass
from logging import Logger
import socket
from threading import Thread
from typing import override

from networking.collections.ts_dict import TSDict
from networking.frames import MACFrame, IPFrame, DeserializationException
from networking.log_format import create_logger
from networking.protocol import (
    BYTE_ENCODING_TYPE,
    MACaddr,
    IPaddr,
    IPProtocol,
    NodeConfig,
    HOSTNAME,
    BROADCAST_MAC,
)


@dataclass
class Node:
    Mac: MACaddr
    Ip: IPaddr
    __logger: Logger
    __socket: socket.SocketType
    __ip_mapping: TSDict[IPaddr, MACaddr] = TSDict()

    # receiving
    def rcv_MAC_frame(self) -> MACFrame:
        while True:
            data = self.__socket.recv(1000)
            frame = MACFrame.from_bytes(data)

            match frame:
                case MACFrame(src, dst, _, bites) if dst in [self.Mac, BROADCAST_MAC]:
                    self.__logger.info(f"rcving {bites} from {src} to {dst}")
                    self.rcv_IP_frame(bites, src)
                case _:
                    pass

    def rcv_IP_frame(self, byte_arr: bytes, src_mac: MACaddr) -> IPFrame | None:
        try:
            ip_frame = IPFrame.from_bytes(byte_arr)
        except DeserializationException as e:
            self.__logger.warning(str(e))
            return None

        self.__logger.info(
            f"rcving {ip_frame.data} from 0x{ip_frame.source:02x} to 0x{
                ip_frame.destination:02x} with protocol {
                IPProtocol(ip_frame.protocol).name
            }"
        )
        match ip_frame:
            case IPFrame(src, self.Ip, IPProtocol.ARP, _, b"res"):
                self.save_IP_mapping(src, src_mac)
                return ip_frame
            case IPFrame(src, self.Ip, IPProtocol.ARP, _, b"req"):
                self.send_ARP_response(src_mac, src)
                return ip_frame
            case _:
                return None

    # sending
    def send_MAC_frame(self, dst: MACaddr, data: bytes):
        self.__logger.info(f"sending {data} from {self.Mac} to {dst}")
        self.__socket.send(bytes(MACFrame(self.Mac, dst, data)))

    def send_IP_frame(self, dst: IPaddr, protocol: IPProtocol, data: bytes):
        self.__logger.info(f"sending {data} from 0x{self.Ip:02x} to 0x{dst:02x}")
        resolved_mac = self.resolve_IP(dst)
        self.send_MAC_frame(resolved_mac, bytes(IPFrame(self.Ip, dst, protocol, data)))

    # address resolution
    def save_IP_mapping(self, ip: IPaddr, mac: MACaddr):
        self.__ip_mapping[ip] = mac

    def send_ARP_request(self, dst: IPaddr):
        self.send_MAC_frame(
            BROADCAST_MAC,
            bytes(IPFrame(self.Ip, dst, IPProtocol.ARP, b"req")),
        )

    def send_ARP_response(self, dst: MACaddr, ip: IPaddr):
        self.send_MAC_frame(dst, bytes(IPFrame(self.Ip, ip, IPProtocol.ARP, b"res")))

    def resolve_IP(self, dst: IPaddr) -> MACaddr:
        self.__logger.debug(f"resolving ip 0x{dst:02x}")
        if dst not in self.__ip_mapping:
            self.__logger.debug("mapping not saved, requesting")
            self.send_ARP_request(dst)
        mac = self.__ip_mapping.block_until(dst)
        self.__logger.debug(f"resolved, mac is {mac}")
        return mac

    # object methods
    def input(self):
        while True:
            data = input("Format: MAC {dst} msg OR IP {dst} [PING|] msg: ")
            match data.split():
                case ["MAC", dst, *data]:
                    self.send_MAC_frame(dst, " ".join(data).encode(BYTE_ENCODING_TYPE))
                case ["IP", dst, protocol, *data]:
                    self.send_IP_frame(
                        int(dst, base=16),
                        IPProtocol[protocol],
                        " ".join(data).encode(BYTE_ENCODING_TYPE),
                    )
                case _:
                    pass

    @override
    def __init__(self, node_config: NodeConfig, wire_port: int):
        self.Mac = node_config["MAC"]
        self.Ip = node_config["IP"]
        self.__logger = create_logger(self.Mac)
        self.__socket = socket.create_connection((HOSTNAME, wire_port))
        self.__logger.info("connected to wire")

        Thread(target=self.rcv_MAC_frame).start()

    def __del__(self):
        self.__socket.close()
        self.__logger.info("closing node")
