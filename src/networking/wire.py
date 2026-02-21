from queue import SimpleQueue
import socket
from threading import Thread

from networking.log_format import create_logger
from networking.protocol import HOSTNAME

logger = create_logger(__name__)


class Wire:
    __targets = SimpleQueue()
    __size = 0

    def _broadcast(self, msg: bytes):
        logger.info(f"sending messages to {self.__size} targets")
        for _ in range(self.__size):
            print("Loop")
            sock = self.__targets.get_nowait()
            sock.send(msg)
            self.__targets.put_nowait(sock)

    def forward(self):
        while True:
            sock = self.__targets.get()
            try:
                msg = sock.recv(1000)
                logger.info(f"sending message {msg}")
                self._broadcast(msg)
            except TimeoutError:
                pass
            finally:
                self.__targets.put_nowait(sock)

    def accept(self):
        while True:
            # logger.info("waiting for connection")
            try:
                conn, _ = self.__server.accept()
                self.__size += 1
                conn.settimeout(1)
                self.__targets.put_nowait(conn)
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
