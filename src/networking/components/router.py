import time
from collections import defaultdict
from threading import Thread, Lock
from logging import Logger

from networking.components.handlers import (
    ARPHandler,
    PingHandler,
)
from networking.components.node import FrameHandler, Node
from networking.config import LOGGING_LEVEL
from networking.frames import IPFrame
from networking.log_format import create_logger
from networking.types import MACaddr, IPProtocol, RouterConfig, WireConfig

# --- Tunable thresholds (mirror ids.py) ---
RATE_WINDOW = 2.0  # seconds
RATE_THRESHOLD = 15  # packets per window from a single src_ip


class Router:
    logger: Logger = create_logger(__name__, level=LOGGING_LEVEL)
    routing_table: dict[int, Node]

    def __init__(self, config: RouterConfig, wires: dict[str, WireConfig]):
        self.ids_enabled = True

        # Spoofing detection: src_ip → first-seen MAC
        self._ip_mac_table: dict[int, MACaddr] = {}
        self._ip_mac_lock = Lock()

        # DDoS detection: src_ip → list of packet timestamps
        self._pkt_times: dict[int, list[float]] = defaultdict(list)
        self._pkt_lock = Lock()

        interfaces: dict[str, Node] = {}
        forward_handler = FrameHandler(
            lambda _, f: f.protocol != IPProtocol.ARP, self.forward
        )
        ids_handler = FrameHandler(lambda _, f: True, self._ids_inspect)
        for k, v in config["interfaces"].items():
            wire_conf = wires[v["wire"]]
            n = (
                Node(v, wire_conf)
                .add_handler(ARPHandler())
                .add_handler(PingHandler())
                .add_handler(ids_handler)
                .add_handler(forward_handler)
            )
            self.logger.info(f"{k} connected to wire")
            interfaces[k] = n

        self.routing_table = {
            k: interfaces[v] for k, v in config["routing_table"].items()
        }

        Thread(target=self._control_loop, daemon=True).start()

    def _ids_inspect(
        self, _n: Node, ip_frame: IPFrame, src_mac: MACaddr
    ) -> IPFrame | None:
        if not self.ids_enabled:
            return ip_frame

        src_ip = ip_frame.source

        # --- IP Spoofing (DAI) ---
        with self._ip_mac_lock:
            known_mac = self._ip_mac_table.get(src_ip)
            if known_mac is None:
                self._ip_mac_table[src_ip] = src_mac
                self.logger.debug(f"[ROUTER IDS] Learned: 0x{src_ip:02x} → '{src_mac}'")
            elif known_mac != src_mac:
                self.logger.critical(
                    f"[ROUTER IDS] ⚠ IP SPOOFING DETECTED: "
                    f"IP 0x{src_ip:02x} known from MAC '{known_mac}', "
                    f"arrived from '{src_mac}' — packet DROPPED before forwarding"
                )
                return  # drop — never reaches forward()

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
            return  # drop flood packets

        return ip_frame  # clean — pass to forward()

    def forward(self, _n: Node, ip_frame: IPFrame, _mac: MACaddr) -> IPFrame | None:
        dst_ip = ip_frame.destination

        if dst_ip not in self.routing_table:
            self.logger.warning(f"No route for 0x{dst_ip:02x}")
            return

        n = self.routing_table[dst_ip]
        try:
            n.send_MAC_frame(n.resolve_IP(dst_ip), bytes(ip_frame))
        except TimeoutError:
            self.logger.warning(
                f"ARP timeout resolving 0x{dst_ip:02x} — dropping packet"
            )
            return
        self.logger.info(f"Forwarded packet to 0x{dst_ip:02x} via {n.Mac}")

    def _control_loop(self):
        while True:
            try:
                cmd = input("[ROUTER] ").strip().upper()

                if cmd == "IDS OFF":
                    self.ids_enabled = False
                    print("[ROUTER] IDS disabled")

                elif cmd == "IDS ON":
                    self.ids_enabled = True
                    print("[ROUTER] IDS enabled")

                else:
                    print("Commands: IDS ON / IDS OFF")

            except Exception as e:
                print(f"[ROUTER] Error: {e}")
