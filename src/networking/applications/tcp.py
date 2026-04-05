from logging import Logger
from threading import Lock
import time
from typing import Literal, TypedDict, override
from networking.components.node import Application, FrameHandler, Node
from networking.frames import IPFrame
from networking.types import BytesEnum, IPProtocol, IPaddr, MACaddr


class TCPState(BytesEnum):
    SYN = b"SYN"
    SYNACK = b"SYN-ACK"
    RST = b"RST"
    FIN = b"FIN"
    KEEPALIVE = b"KEEPALIVE"


class TCPHandler(FrameHandler):
    application: TCPApplication

    def __init__(self, application: TCPApplication):
        self.application = application
        super().__init__(
            lambda node, f: f.protocol == IPProtocol.TCP and node.Ip == f.destination,
            self.on_request,
        )

    def on_request(self, node: Node, frame: IPFrame, _: MACaddr):
        app = self.application

        with app.conn_lock:
            app.cleanup_stale_connections()
            src = frame.source
            table_has_src = src in app.conn_table

            now = time.monotonic()
            reply = None  # ← [CONNECT] will be set to SYN-ACK or RST for SYN frames
            try:
                payload = frame.data
                match TCPState(payload):
                    case TCPState.SYN:
                        if table_has_src:
                            app.conn_table[src]["last_activity"] = now
                            app.logger.info(
                                f"[TCP] Duplicate SYN from 0x{src:02x}, refreshed"
                            )
                            reply = b"SYN-ACK"  #  re-acknowledge existing connection
                        elif len(app.conn_table) >= app.max_connections:
                            app.logger.warning(
                                f"[TCP] Connection limit reached ({app.max_connections}), "
                                + f"dropping SYN from 0x{src:02x}"
                            )
                            reply = b"RST"  #  table full — tell sender to back off
                        else:
                            app.conn_table[src] = {
                                "state": "HALF_OPEN",
                                "last_activity": now,
                            }
                            count = len(app.conn_table)
                            app.logger.info(
                                f"[TCP] Connection {count}/{app.max_connections} "
                                + f"from 0x{src:02x} (HALF_OPEN)"
                            )
                            reply = b"SYN-ACK"  # ← [CONNECT] connection accepted

                    case TCPState.KEEPALIVE:
                        if table_has_src:
                            app.conn_table[src]["last_activity"] = now
                            app.logger.debug(f"[TCP] Keepalive from 0x{src:02x}")
                        else:
                            app.logger.debug(
                                f"[TCP] Keepalive from 0x{src:02x} with no connection, ignored"
                            )
                    case TCPState.FIN:
                        if table_has_src:
                            del app.conn_table[src]
                            app.logger.info(
                                f"[TCP] Connection from 0x{src:02x} closed (FIN)"
                            )
                    case TCPState.SYNACK:
                        app.logger.info(f"[TCP] CONNECT to 0x{src:02x} ACCEPTED")
                    case TCPState.RST:
                        app.logger.info(
                            f"[TCP] CONNECT to 0x{src:02x} REFUSED — table full"
                        )
                # ← [CONNECT] send reply outside the lock to avoid holding it during ARP resolution
                if reply:
                    try:
                        node.send_IP_frame(src, IPProtocol.TCP, reply)
                    except TimeoutError:
                        app.logger.warning(
                            f"[TCP] Could not send {reply!r} to 0x{src:02x} (ARP timeout)"
                        )
            except ValueError:
                pass


class TCPConnection(TypedDict):
    last_activity: float
    state: Literal["HALF_OPEN"]


class TCPApplication(Application):
    conn_table: dict[IPaddr, TCPConnection]
    conn_lock: Lock
    max_connections: int
    conn_timeout: float
    logger: Logger

    def __init__(self, node: Node) -> None:
        self.conn_table = {}
        self.conn_lock = Lock()
        self.max_connections = 10
        self.conn_timeout = 10.0
        self.logger = node.logger

        _ = node.add_handler(TCPHandler(self))
        super().__init__()

    @override
    def handle_command(self, node: Node, *args: str):
        match args:
            case ("stats",):
                self.stats()
            case (dst,):
                node.send_IP_frame(int(dst, base=16), IPProtocol.TCP, TCPState.SYN)
            case _:
                pass

    def stats(self):
        print("\n=== TRAFFIC STATS ===")
        with self.conn_lock:
            self.cleanup_stale_connections()
            total = len(self.conn_table)
            half_open = sum(
                1 for v in self.conn_table.values() if v["state"] == "HALF_OPEN"
            )
            established = total - half_open
            print(
                f"Connections: {total}/{self.max_connections} used "
                + f"({half_open} HALF_OPEN, {established} ESTABLISHED)"
            )
            now = time.monotonic()
            for ip, info in self.conn_table.items():
                age = now - info["last_activity"]
                print(f"  0x{ip:02x}: {info['state']}  (last activity: {age:.1f}s ago)")

    def cleanup_stale_connections(self):
        """Remove connections that have timed out. Must be called with _conn_lock held."""
        now = time.monotonic()
        stale = [
            ip
            for ip, info in self.conn_table.items()
            if now - info["last_activity"] > self.conn_timeout
        ]
        for ip in stale:
            del self.conn_table[ip]
            self.logger.debug(f"[TCP] Connection from 0x{ip:02x} timed out")
