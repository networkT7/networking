from dataclasses import dataclass
from logging import Logger
import socket
from threading import Thread
from typing import override

from networking.frames import MAC_frame
from networking.log_format import create_logger
from networking.protocol import MACaddr, NodeConfig, HOSTNAME


@dataclass
class Node:
    MAC: MACaddr
    IP: int
    __logger: Logger
    __socket: socket.SocketType

    def rcv_MAC_frame(self) -> MAC_frame:
        while True:
            data = self.__socket.recv(1000)
            frame = MAC_frame.from_bytes(data)
            if frame.destination != self.MAC:
                continue

            print(end="\r")
            self.__logger.info(f"rcving {frame.data} from {frame.source} to {frame.destination}")  # noqa
            print("\nEnter your message: ", end="")

    def send_MAC_frame(self, dst: MACaddr, data: str):
        self.__logger.info(f"sending {data} from {self.MAC} to {dst}")
        self.__socket.send(bytes(MAC_frame(self.MAC, dst, data)))

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
