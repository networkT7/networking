import socket

from networking.log_format import create_logger
from networking.protocol import NodeConfig

logger = create_logger(__name__)


class Wire:
    __targets: list[socket.SocketType]

    def _broadcast(self, msg: bytes):
        for sock in self.__targets:
            sock.send(msg)

    def forward(self):
        for sock in self.__targets:
            sock.settimeout(1)

        while True:
            for sock in self.__targets:
                try:
                    msg = sock.recv(1000)
                    logger.info(f"sending message {msg}")
                    self._broadcast(msg)
                except TimeoutError:
                    pass

    def __init__(self, connected_nodes: list[str],
                 nodes: dict[str, NodeConfig]):
        self.__targets = [socket.create_connection(
            ("127.0.0.1", nodes[node]["port"])) for node in connected_nodes]

    def __del__(self):
        logger.info("closing sockets")
        for v in self.__targets:
            v.close()
