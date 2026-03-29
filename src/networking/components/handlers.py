import time

from networking.components.node import FrameHandlerClass, Node
from networking.constants import BYTE_ENCODING_TYPE
from networking.frames import IPFrame
from networking.types import IPProtocol, MACaddr


class ARPRequestHandler(FrameHandlerClass):
    def __init__(self):
        super().__init__(
            lambda node, f: (
                f.protocol == IPProtocol.ARP
                and f.data == b"req"
                and node.Ip == f.destination
            ),
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, src_mac: MACaddr):
        src = frame.source
        node._logger.debug(f"ARP request received from 0x{src:02x}")
        node.save_IP_mapping(src, src_mac)
        node.send_ARP_response(src_mac, node.Ip, src)
        return True


class ARPResponseHandler(FrameHandlerClass):
    def __init__(self):
        super().__init__(
            lambda node, f: (
                f.protocol == IPProtocol.ARP
                and f.data == b"res"
                and node.Ip == f.destination
            ),
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, src_mac: MACaddr):
        src = frame.source
        node._logger.debug(f"ARP response received from 0x{src:02x}")
        node.save_IP_mapping(src, src_mac)
        return True

class PingRequestHandler(FrameHandlerClass):
    def __init__(self):
        super().__init__(
            lambda node, f: (
                f.protocol == IPProtocol.PING
                and f.data == b"req"
                and node.Ip == f.destination
            ),
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, _: MACaddr):
        src = frame.source
        node._logger.info(f"Ping request received from 0x{src:02x}")
        node.send_IP_frame(src, IPProtocol.PING, b"res")
        return True


class PingResponseHandler(FrameHandlerClass):
    def __init__(self):
        super().__init__(
            lambda node, f: (
                f.protocol == IPProtocol.PING
                and f.data == b"res"
                and node.Ip == f.destination
            ),
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, _: MACaddr):
        node._logger.info(f"Ping reply received from 0x{frame.source:02x}")
        return True


class TCPConnectionHandler(FrameHandlerClass):
    def __init__(self):
        super().__init__(
            lambda node, f: f.protocol == IPProtocol.TCP and node.Ip == f.destination,
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, _: MACaddr) -> bool:
        src = frame.source
        payload = frame.data
        now = time.monotonic()
        reply = None  # ← [CONNECT] will be set to SYN-ACK or RST for SYN frames

        with node._conn_lock:
            node._cleanup_stale_connections()

            if payload == b"SYN":
                if src in node._conn_table:
                    node._conn_table[src]["last_activity"] = now
                    node._logger.info(
                        f"[TCP] Duplicate SYN from 0x{src:02x}, refreshed"
                    )
                    reply = b"SYN-ACK"  # ← [CONNECT] re-acknowledge existing connection
                elif len(node._conn_table) >= node._max_connections:
                    node._logger.warning(
                        f"[TCP] Connection limit reached ({node._max_connections}), "
                        f"dropping SYN from 0x{src:02x}"
                    )
                    reply = b"RST"  # ← [CONNECT] table full — tell sender to back off
                else:
                    node._conn_table[src] = {
                        "state": "HALF_OPEN",
                        "last_activity": now,
                    }
                    count = len(node._conn_table)
                    node._logger.info(
                        f"[TCP] Connection {count}/{node._max_connections} "
                        f"from 0x{src:02x} (HALF_OPEN)"
                    )
                    reply = b"SYN-ACK"  # ← [CONNECT] connection accepted

            elif payload == b"KEEPALIVE":
                if src in node._conn_table:
                    node._conn_table[src]["last_activity"] = now
                    node._logger.debug(
                        f"[TCP] Keepalive from 0x{src:02x}"
                    )
                else:
                    node._logger.debug(
                        f"[TCP] Keepalive from 0x{src:02x} with no connection, ignored"
                    )

            elif payload == b"FIN":
                if src in node._conn_table:
                    del node._conn_table[src]
                    node._logger.info(
                        f"[TCP] Connection from 0x{src:02x} closed (FIN)"
                    )

        # ← [CONNECT] send reply outside the lock to avoid holding it during ARP resolution
        if reply is not None:
            try:
                node.send_IP_frame(src, IPProtocol.TCP, reply)
            except TimeoutError:
                node._logger.warning(
                    f"[TCP] Could not send {reply!r} to 0x{src:02x} (ARP timeout)"
                )

        return True


# ← [CONNECT] handles SYN-ACK / RST replies on the connecting node's side
class TCPConnectResponseHandler(FrameHandlerClass):
    def __init__(self):
        super().__init__(
            lambda node, f: (
                f.protocol == IPProtocol.TCP
                and node.Ip == f.destination
                and f.data in (b"SYN-ACK", b"RST")
            ),
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, _: MACaddr) -> bool:
        src = frame.source
        if frame.data == b"SYN-ACK":
            node._logger.info(f"[TCP] CONNECT to 0x{src:02x} ACCEPTED")
        else:
            node._logger.info(f"[TCP] CONNECT to 0x{src:02x} REFUSED — table full")
        return True


class DataHandler(FrameHandlerClass):
    def __init__(self):
        super().__init__(
            lambda node, f: f.protocol == IPProtocol.DATA and node.Ip == f.destination,
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, _: MACaddr):
        node._logger.info(
            f"[DATA] Message from 0x{frame.source:02x}: {frame.data.decode(BYTE_ENCODING_TYPE)}"
        )
        return True
