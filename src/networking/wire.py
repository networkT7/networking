import socket

from networking.frames import MAC_frame
from networking.log_format import create_logger
from networking.protocol import NodeConfig

logger = create_logger(__name__)


class Wire:
    __map: dict[str, socket.SocketType]

    def __init__(self, connected_nodes: list[str],
                 nodes: dict[str, NodeConfig]):
        self.__map = {node: socket.create_connection(
            ("127.0.0.1", nodes[node]["port"])) for node in connected_nodes}
        self.__map["N1"].send(bytes(MAC_frame("hi", "by", "hello")))

    def __del__(self):
        logger.info("closing sockets")
        for v in self.__map.values():
            v.close()
