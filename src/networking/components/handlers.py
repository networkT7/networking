import time

from networking.components.node import FrameHandlerClass, Node
from networking.constants import BYTE_ENCODING_TYPE
from networking.frames import IPFrame
from networking.types import FragmentId, IPProtocol, IPaddr, MACaddr


class IPFragmentHandler(FrameHandlerClass):
    fragments: dict[tuple[FragmentId, IPaddr, IPaddr, IPProtocol], IPFrame]

    def __init__(self):
        self.fragments = {}
        super().__init__(lambda _, frame: frame.is_fragmented, self.on_request)

    def on_request(self, _node: Node, frame: IPFrame, _mac: MACaddr):
        key = (frame.fragment_id, frame.source, frame.destination, frame.protocol)
        frag = self.fragments.pop(key, None)
        if frag:
            return IPFrame.defragment_frame([frag, frame])
        else:
            self.fragments[key] = frame


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
        node.logger.debug(f"ARP request received from 0x{src:02x}")
        node.save_IP_mapping(src, src_mac)
        node.send_ARP_response(src_mac, node.Ip, src)


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
        node.logger.debug(f"ARP response received from 0x{src:02x}")
        node.save_IP_mapping(src, src_mac)


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
        node.logger.info(f"Ping request received from 0x{src:02x}")
        node.send_IP_frame(src, IPProtocol.PING, b"res")


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
        node.logger.info(f"Ping reply received from 0x{frame.source:02x}")


class TCPConnectionHandler(FrameHandlerClass):
    def __init__(self):
        super().__init__(
            lambda node, f: f.protocol == IPProtocol.TCP and node.Ip == f.destination,
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, _: MACaddr):
        src = frame.source
        payload = frame.data
        now = time.monotonic()
        reply = None  # ← [CONNECT] will be set to SYN-ACK or RST for SYN frames

        with node._conn_lock:
            node._cleanup_stale_connections()

            if payload == b"SYN":
                if src in node._conn_table:
                    node._conn_table[src]["last_activity"] = now
                    node.logger.info(f"[TCP] Duplicate SYN from 0x{src:02x}, refreshed")
                    reply = b"SYN-ACK"  # ← [CONNECT] re-acknowledge existing connection
                elif len(node._conn_table) >= node._max_connections:
                    node.logger.warning(
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
                    node.logger.info(
                        f"[TCP] Connection {count}/{node._max_connections} "
                        f"from 0x{src:02x} (HALF_OPEN)"
                    )
                    reply = b"SYN-ACK"  # ← [CONNECT] connection accepted

            elif payload == b"KEEPALIVE":
                if src in node._conn_table:
                    node._conn_table[src]["last_activity"] = now
                    node.logger.debug(f"[TCP] Keepalive from 0x{src:02x}")
                else:
                    node.logger.debug(
                        f"[TCP] Keepalive from 0x{src:02x} with no connection, ignored"
                    )

            elif payload == b"FIN":
                if src in node._conn_table:
                    del node._conn_table[src]
                    node.logger.info(f"[TCP] Connection from 0x{src:02x} closed (FIN)")

        # ← [CONNECT] send reply outside the lock to avoid holding it during ARP resolution
        if reply is not None:
            try:
                node.send_IP_frame(src, IPProtocol.TCP, reply)
            except TimeoutError:
                node.logger.warning(
                    f"[TCP] Could not send {reply!r} to 0x{src:02x} (ARP timeout)"
                )


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
    def on_request(node: Node, frame: IPFrame, _: MACaddr):
        src = frame.source
        if frame.data == b"SYN-ACK":
            node.logger.info(f"[TCP] CONNECT to 0x{src:02x} ACCEPTED")
        else:
            node.logger.info(f"[TCP] CONNECT to 0x{src:02x} REFUSED — table full")


class DataHandler(FrameHandlerClass):
    def __init__(self):
        super().__init__(
            lambda node, f: f.protocol == IPProtocol.DATA and node.Ip == f.destination,
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, _: MACaddr):
        node.logger.info(
            f"[DATA] Message from 0x{frame.source:02x}: {frame.data.decode(BYTE_ENCODING_TYPE)}"
        )
