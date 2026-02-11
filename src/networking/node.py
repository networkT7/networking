from networking.log_format import create_logger
from networking.frames import MAC_frame

logger = create_logger(__name__)


class Node:
    MAC: str
    IP: str

    def rcv_MAC_frame(self) -> MAC_frame:
        pass

    def send_MAC_frame(self, dst: str, data: str):
        return MAC_frame(self.MAC, dst, data)

    def __init__(self, MAC: str, IP: str):
        self.MAC = MAC
        self.IP = IP

    def __del__(self):
        logger.info("closing node")
