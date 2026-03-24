from queue import SimpleQueue
import socket
from threading import Thread

from networking.config import HOSTNAME, RECEIVE_SIZE, SOCKET_TIMEOUT
from networking.log_format import create_logger

logger = create_logger(__name__)


class Wire:
    __server: socket.socket
    __targets: SimpleQueue[socket.SocketType]

    def _broadcast(self, msg: bytes):
        targets = []
        while not self.__targets.empty():
            targets.append(self.__targets.get_nowait())
        
        logger.info(f"sending {msg} to {len(targets)} targets")
        for sock in targets:
            try:
                sock.send(msg)
                self.__targets.put(sock) 
            except (BrokenPipeError, OSError):
                logger.warning("dropping dead connection") 

    def forward(self):
        while True:
            sock = self.__targets.get()
            try:
                msg = sock.recv(RECEIVE_SIZE)
                if msg:
                    self.__targets.put(sock)
                    self._broadcast(msg)
                else:
                    logger.warning("connection closed, removing socket")
            except TimeoutError:
                self.__targets.put(sock)
            except (BrokenPipeError, OSError):
                logger.warning("dropping dead connection in forward")

    def accept(self):
        while True:
            try:
                conn = self.__server.accept()[0]
                conn.settimeout(SOCKET_TIMEOUT)
                self.__targets.put(conn)
            except TimeoutError:
                pass

    def __init__(self, port: int):
        self.__targets = SimpleQueue()
        Thread(target=self.forward, daemon=True).start()
        self.__server = socket.create_server((HOSTNAME, port))
        self.__server.settimeout(SOCKET_TIMEOUT)

    def __del__(self):
        logger.debug("closing sockets")
        while not self.__targets.empty():
            self.__targets.get_nowait().close()
