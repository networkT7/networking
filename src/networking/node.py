from dataclasses import dataclass
from logging import Logger
import socket
from threading import Thread
from typing import override, Union

from networking.frames import MACFrame, IPFrame, DeserializationException
from networking.log_format import create_logger
from networking.protocol import MACaddr, IPaddr, IPProtocol, NodeConfig, HOSTNAME


@dataclass
class Node:
    MAC: MACaddr
    IP: IPaddr
    __logger: Logger
    __socket: socket.SocketType

    def rcv_MAC_frame(self) -> MACFrame:
        while True:
            data = self.__socket.recv(1000)
            frame = MACFrame.from_bytes(data)
            if frame.destination != self.MAC:
                continue

            match frame:
                case MACFrame(src, dst, _, bites):
                    self.__logger.info(f"rcving {bites} from {src} to {dst}")
                    self.rcv_IP_frame(bites)

    def rcv_IP_frame(self, byte_arr: bytes) -> Union[IPFrame | None]:
        try:
            ip_frame = IPFrame.from_bytes(byte_arr)
        except DeserializationException as e:
            self.__logger.error(str(e))
            return None
        if ip_frame.destination != self.IP:
            return None
        match ip_frame:
            case IPFrame(src, dst, protocol, _, data):
                self.__logger.info(f"rcving {data} from 0x{src:02x} to 0x{
                                   dst:02x} with protocol {IPProtocol(protocol).name}")
                return ip_frame

    def send_MAC_frame(self, dst: MACaddr, data: bytes):
        self.__logger.info(f"sending {data} from {self.MAC} to {dst}")
        self.__socket.send(bytes(MACFrame(self.MAC, dst, data)))

    def send_IP_frame(self, dst: IPaddr, protocol: IPProtocol, data: bytes):
        self.__logger.info(f"sending {data} from 0x{
                           self.IP:02x} to 0x{dst:02x}")
        # TODO: ARP mapping to send IP frame to correct MAC
        self.send_MAC_frame("N2", bytes(
            IPFrame(self.IP, dst, protocol, data)))

    def input(self):
        while True:
            data = input("Format: MAC {dst} msg OR IP {dst} [PING|] msg: ")
            match data.split():
                case ["MAC", dst, *data]:
                    self.send_MAC_frame(dst, " ".join(data).encode())
                case ["IP", dst, protocol, *data]:
                    self.send_IP_frame(
                        int(dst, base=16), IPProtocol[protocol], " ".join(data).encode())

    @override
    def __init__(self, node_config: NodeConfig, wire_port: int):
        self.MAC = node_config["MAC"]
        self.IP = node_config["IP"]
        self.__logger = create_logger(self.MAC)
        self.__socket = socket.create_connection((HOSTNAME, wire_port))
        self.__logger.info("connected to wire")

        Thread(target=self.rcv_MAC_frame).start()

    def __del__(self):
        self.__socket.close()
        self.__logger.info("closing node")
