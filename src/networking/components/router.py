from threading import Thread
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


class Router:
    logger: Logger = create_logger(__name__, level=LOGGING_LEVEL)
    routing_table: dict[int, Node]

    def __init__(self, config: RouterConfig, wires: dict[str, WireConfig]):
        """
        config: full config["nodes"]
        wires: config["wires"]
        """

        interfaces: dict[str, Node] = {}
        handler = FrameHandlerClass(
            lambda _, f: f.protocol != IPProtocol.ARP, self.forward
        )

        # Create interface sockets
        for k, v in config["interfaces"].items():
            wire_conf = wires[v["wire"]]
            n = (
                Node(v, wire_conf)
                .add_handler(ARPRequestHandler())
                .add_handler(ARPResponseHandler())
                .add_handler(PingRequestHandler())
                .add_handler(handler)
            )
            self.logger.info(f"{k} connected to wire")
            interfaces[k] = n

            # Start listener threads
            Thread(target=n.rcv_MAC_frame, daemon=True).start()

        # Fixed routing table (IP → interface name)
        self.routing_table = {
            k: interfaces[v] for k, v in config["routing_table"].items()
        }

    def forward(self, _n: Node, ip_frame: IPFrame, _mac: MACaddr) -> bool:
        dst_ip = ip_frame.destination

        if dst_ip not in self.routing_table:
            self.logger.warning(f"No route for 0x{dst_ip:02x}")
            return False

        n = self.routing_table[dst_ip]
        n.send_MAC_frame(n.resolve_IP(dst_ip), bytes(ip_frame))
        self.logger.info(f"Forwarded packet to 0x{dst_ip:02x} via {n.Mac}")
        return True
