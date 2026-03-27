import time
from collections import defaultdict
from threading import Thread, Lock
from logging import Logger

from networking.components.handlers import (
    ARPRequestHandler,
    ARPResponseHandler,
    PingRequestHandler,
)
from networking.components.node import FrameHandlerClass, Node
from networking.config import LOGGING_LEVEL
from networking.frames import IPFrame
from networking.log_format import create_logger
from networking.types import MACaddr, IPProtocol, RouterConfig, WireConfig

# --- Tunable thresholds (mirror ids.py) ---
RATE_WINDOW = 2.0       # seconds
RATE_THRESHOLD = 50     # packets per window from a single src_ip


class Router:
    logger: Logger = create_logger(__name__, level=LOGGING_LEVEL)
    routing_table: dict[int, Node]

    def __init__(self, config: RouterConfig, wires: dict[str, WireConfig]):
        # Spoofing detection: src_ip → first-seen MAC
        self._ip_mac_table: dict[int, MACaddr] = {}
        self._ip_mac_lock = Lock()

        # DDoS detection: src_ip → list of packet timestamps
        self._pkt_times: dict[int, list[float]] = defaultdict(list)
        self._pkt_lock = Lock()

        interfaces: dict[str, Node] = {}
        forward_handler = FrameHandlerClass(
            lambda _, f: f.protocol != IPProtocol.ARP, self.forward
        )
        ids_handler = FrameHandlerClass(
            lambda _, f: True, self._ids_inspect 
        )
        for k, v in config["interfaces"].items():
            wire_conf = wires[v["wire"]]
            n = (
                Node(v, wire_conf)
                .add_handler(ARPRequestHandler())
                .add_handler(ARPResponseHandler())
                .add_handler(PingRequestHandler())
                .add_handler(ids_handler)
                .add_handler(forward_handler)
            )
            self.logger.info(f"{k} connected to wire")
            interfaces[k] = n

        self.routing_table = {
            k: interfaces[v] for k, v in config["routing_table"].items()
        }

    def _ids_inspect(self, _n: Node, ip_frame: IPFrame, src_mac: MACaddr) -> bool:
        src_ip = ip_frame.source

        # --- IP Spoofing (DAI) ---
        with self._ip_mac_lock:
            known_mac = self._ip_mac_table.get(src_ip)
            if known_mac is None:
                self._ip_mac_table[src_ip] = src_mac
                self.logger.debug(
                    f"[ROUTER IDS] Learned: 0x{src_ip:02x} → '{src_mac}'"
                )
            elif known_mac != src_mac:
                self.logger.critical(
                    f"[ROUTER IDS] ⚠ IP SPOOFING DETECTED: "
                    f"IP 0x{src_ip:02x} known from MAC '{known_mac}', "
                    f"arrived from '{src_mac}' — packet DROPPED before forwarding"
                )
                return True  # drop — never reaches forward()

        # --- DDoS: sliding window rate check ---
        now = time.monotonic()
        with self._pkt_lock:
            times = self._pkt_times[src_ip]
            self._pkt_times[src_ip] = [t for t in times if now - t < RATE_WINDOW]
            self._pkt_times[src_ip].append(now)
            count = len(self._pkt_times[src_ip])

        if count >= RATE_THRESHOLD:
            self.logger.critical(
                f"[ROUTER IDS] ⚠ DDoS DETECTED: "
                f"0x{src_ip:02x} sent {count} packets in {RATE_WINDOW}s — packet DROPPED"
            )
            return True  # drop flood packets

        return False  # clean — pass to forward()

    def forward(self, _n: Node, ip_frame: IPFrame, _mac: MACaddr) -> bool:
        dst_ip = ip_frame.destination

        if dst_ip not in self.routing_table:
            self.logger.warning(f"No route for 0x{dst_ip:02x}")
            return False

        n = self.routing_table[dst_ip]
        n.send_MAC_frame(n.resolve_IP(dst_ip), bytes(ip_frame))
        self.logger.info(f"Forwarded packet to 0x{dst_ip:02x} via {n.Mac}")
        return True