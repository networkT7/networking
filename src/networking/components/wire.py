import socket
from threading import Thread, Lock

from networking.config import HOSTNAME, LOGGING_LEVEL, RECEIVE_SIZE, SOCKET_TIMEOUT
from networking.log_format import create_logger

logger = create_logger(__name__, level=LOGGING_LEVEL)


class Wire:
    __server: socket.socket
    __targets: list[socket.socket]
    __lock: Lock  # guards __targets during broadcast

    def _broadcast(self, msg: bytes, sender: socket.socket):
        """Send msg to every connected socket except the sender."""
        with self.__lock:
            targets = list(self.__targets)
        logger.info(f"broadcasting {len(msg)} bytes to {len(targets) - 1} peer(s)")
        for sock in targets:
            if sock is sender:
                continue
            try:
                sock.sendall(msg)
            except OSError as e:
                logger.warning(f"broadcast send failed: {e}")

    def _handle(self, conn: socket.socket):
        """
        Dedicated blocking receive loop for one connected node.
        No timeout — blocks until a full frame arrives.
        One thread per connection means frames are never interleaved.
        """
        conn.settimeout(None)  # must be blocking for recv_framed
        try:
            while True:
                msg = conn.recv(RECEIVE_SIZE)
                if not msg:
                    logger.info("connection closed by peer")
                    break
                logger.debug(f"[WIRE RECV] {len(msg)} bytes: {msg.hex()}")
                self._broadcast(msg, sender=conn)
        except OSError as e:
            logger.warning(f"connection error: {e}")
        finally:
            with self.__lock:
                if conn in self.__targets:
                    self.__targets.remove(conn)
            conn.close()

    def accept(self):
        while True:
            try:
                conn = self.__server.accept()[0]
                logger.info("new connection accepted")
                with self.__lock:
                    self.__targets.append(conn)
                Thread(target=self._handle, args=(conn,), daemon=True).start()
            except TimeoutError:
                pass

    def __init__(self, port: int):
        self.__targets = []
        self.__lock = Lock()
        self.__server = socket.create_server((HOSTNAME, port))
        self.__server.settimeout(SOCKET_TIMEOUT)

    def __del__(self):
        logger.debug("closing sockets")
        with self.__lock:
            for sock in self.__targets:
                sock.close()
