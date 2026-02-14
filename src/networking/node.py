from dataclasses import dataclass
from typing import override

from networking.log_format import create_logger
from networking.frames import MAC_frame
from networking.protocol import MACaddr

logger = create_logger(__name__)


@dataclass
class Node:
    MAC: MACaddr
    IP: int

    def rcv_MAC_frame(self) -> MAC_frame:
        frame = MAC_frame(self.MAC, "bo", "hello")
        logger.info(f"rcving {frame.data} from {
                    frame.destination} to {frame.source}")
        return frame

    def send_MAC_frame(self, dst: MACaddr, data: str):
        logger.info(f"sending {data} from {self.MAC} to {dst}")
        MAC_frame(self.MAC, dst, data)
        pass

    @override
    def __init__(self, MAC: MACaddr, IP: int):
        self.MAC = MAC
        self.IP = IP

    def __del__(self):
        logger.info("closing node")
