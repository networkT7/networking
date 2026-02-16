import socket

from networking.log_format import create_logger
from networking.protocol import NodeConfig

logger = create_logger(__name__)


class Wire:
    __map: dict[str, socket.SocketType]

    def _broadcast(self, msg: bytes):
        for sock in self.__map.values():
            sock.send(msg)

    def forward(self):
        for sock in self.__map.values():
            sock.settimeout(1)

        while True:
            for sock in self.__map.values():
                try:
                    msg = sock.recv(1000)
                    self._broadcast(msg)
                except TimeoutError:
                    pass

    def __init__(self, connected_nodes: list[str],
                 nodes: dict[str, NodeConfig]):
        self.__map = {node: socket.create_connection(
            ("127.0.0.1", nodes[node]["port"])) for node in connected_nodes}

    def __del__(self):
        logger.info("closing sockets")
        for v in self.__map.values():
            v.close()
