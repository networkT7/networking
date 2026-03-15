from queue import SimpleQueue
import socket
from threading import Thread, Lock

from networking.config import HOSTNAME, RECEIVE_SIZE, SOCKET_TIMEOUT
from networking.log_format import create_logger

logger = create_logger(__name__)


# ---------------------------------------------------------------------------
# Framing helpers — 2-byte big-endian length prefix on every frame.
# Used by both Wire and Node so TCP coalescing never merges frames.
# ---------------------------------------------------------------------------

def send_framed(sock: socket.socket, data: bytes) -> None:
    """Prepend a 2-byte length header and send atomically."""
    sock.sendall(len(data).to_bytes(2, "big") + data)


def recv_framed(sock: socket.socket) -> bytes:
    """
    Read exactly one framed message.
    The socket must have NO timeout (blocking) — Wire sets this automatically.
    Returns b"" when the connection is closed.
    """
    header = _recv_exact(sock, 2)
    if not header:
        return b""
    length = int.from_bytes(header, "big")
    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes, looping across multiple recv() calls."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf.extend(chunk)
    return bytes(buf)


class Wire:
    __server: socket.socket
    __targets: list[socket.socket]
    __lock: Lock                        # guards __targets during broadcast

    def _broadcast(self, msg: bytes, sender: socket.socket):
        """Send msg to every connected socket except the sender."""
        with self.__lock:
            targets = list(self.__targets)
        logger.info(f"broadcasting {len(msg)} bytes to {len(targets) - 1} peer(s)")
        for sock in targets:
            if sock is sender:
                continue
            try:
                send_framed(sock, msg)
            except OSError as e:
                logger.warning(f"broadcast send failed: {e}")

    def _handle(self, conn: socket.socket):
        """
        Dedicated blocking receive loop for one connected node.
        No timeout — blocks until a full frame arrives.
        One thread per connection means frames are never interleaved.
        """
        conn.settimeout(None)           # must be blocking for recv_framed
        try:
            while True:
                msg = recv_framed(conn)
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