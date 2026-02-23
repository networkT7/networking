from queue import SimpleQueue
import socket
from threading import Thread

from networking.log_format import create_logger
from networking.protocol import HOSTNAME

logger = create_logger(__name__)


class Wire:
    __targets: SimpleQueue[socket.SocketType] = SimpleQueue()

    def _broadcast(self, msg: bytes):
        logger.info(f"sending {msg} to {self.__targets.qsize()} targets")
        for _ in range(self.__targets.qsize()):
            sock = self.__targets.get()
            sock.send(msg)
            self.__targets.put(sock)

    def forward(self):
        while True:
            sock = self.__targets.get()
            try:
                msg = sock.recv(1000)
                self._broadcast(msg)
            except TimeoutError:
                pass
            finally:
                self.__targets.put(sock)

    def accept(self):
        while True:
            try:
                conn, _ = self.__server.accept()
                conn.settimeout(1)
                self.__targets.put(conn)
            except TimeoutError:
                pass

    def __init__(self, port: int):
        Thread(target=self.forward).start()
        self.__server = socket.create_server((HOSTNAME, port))
        self.__server.settimeout(1)

    def __del__(self):
        logger.info("closing sockets")
        while not self.__targets.empty():
            self.__targets.get_nowait().close()
