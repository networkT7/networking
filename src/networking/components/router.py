import socket
from threading import Thread
from logging import Logger
from typing import TypedDict

from networking.collections.ts_dict import TSDict
from networking.config import HOSTNAME, LOGGING_LEVEL, RECEIVE_SIZE
from networking.constants import BROADCAST_MAC
from networking.frames import DeserializationException, MACFrame, IPFrame
from networking.log_format import create_logger
from networking.types import IPaddr, MACaddr, IPProtocol, RouterConfig, WireConfig


class InterfaceDict(TypedDict):
    socket: socket.SocketType
    MAC: MACaddr
    IP: IPaddr


class Router:
    arp_table: TSDict[IPaddr, MACaddr] = TSDict()
    interfaces: dict[str, InterfaceDict] = {}
    logger: Logger = create_logger("ROUTER", level=LOGGING_LEVEL)
    routing_table: dict[int, str]

    def __init__(self, config: RouterConfig, wires: dict[str, WireConfig]):
        """
        config: full config["nodes"]
        wires: config["wires"]
        """

        # Fixed routing table (IP → interface name)
        self.routing_table = {
            int(k, base=16): v for k, v in config["routing_table"].items()
        }

        # Create interface sockets
        for k, v in config["interfaces"].items():
            wire_conf = wires[v["wire"]]
            sock = socket.create_connection((HOSTNAME, wire_conf["port"]))
            self.logger.info(f"{k} connected to wire")
            conf: InterfaceDict = {
                "socket": sock,
                "MAC": config[k]["MAC"],
                "IP": config[k]["IP"],
            }
            self.interfaces[k] = conf

            # Start listener threads
            Thread(target=self.listen, args=(conf), daemon=True).start()

    def process_ip_frame(self, ip_frame: IPFrame, conf: InterfaceDict):
        iface_ip = conf["IP"]
        if ip_frame.protocol == IPProtocol.ARP:
            if ip_frame.destination == iface_ip and ip_frame.data == b"req":
                reply = IPFrame(
                    iface_ip,
                    ip_frame.source,
                    ip_frame.protocol,
                    b"res",
                )

                response = MACFrame(
                    iface_mac,
                    frame.source,
                    bytes(reply),
                )

                sock.send(bytes(response))
                self.logger.info(f"{iface_mac} replied to ARP")

            return
        # ------------------------
        # Normal IP forwarding
        # ------------------------
        self.logger.info(f"{receiving_mac} received IP packet")
        self.forward(ip_frame)

    def listen(self, conf: InterfaceDict):
        sock = conf["socket"]
        iface_mac = conf["MAC"]

        while True:
            data = sock.recv(RECEIVE_SIZE)
            frame = MACFrame.from_bytes(data)

            match frame:
                case MACFrame(src, dst, _, msg) if dst in [iface_mac, BROADCAST_MAC]:
                    self.logger.info(f"rcving {msg} from {src} to {dst}")
                    try:
                        ip_frame = IPFrame.from_bytes(frame.data)
                        self.save_arp_entry(ip_frame.source, frame.source)
                        self.process_ip_frame(ip_frame, conf)
                    except DeserializationException:
                        continue
                case _:
                    pass

    def forward(self, ip_frame: IPFrame):
        dst_ip = ip_frame.destination

        if dst_ip not in self.routing_table:
            self.logger.warning(f"No route for 0x{dst_ip:02x}")
            return

        out_iface_name = self.routing_table[dst_ip]
        out_iface = self.interfaces[out_iface_name]

        dst_mac = self.resolve_mac(dst_ip)

        new_mac_frame = MACFrame(out_iface["MAC"], dst_mac, bytes(ip_frame))

        out_iface["socket"].send(bytes(new_mac_frame))

        self.logger.info(f"Forwarded packet to 0x{dst_ip:02x} via {out_iface_name}")

    def save_arp_entry(self, ip: IPaddr, mac: MACaddr):
        self.arp_table[ip] = mac

    def send_arp_response(self, ip):
        pass

    def send_MAC_frame(self, dst: MACaddr, data: bytes):
        self.logger.debug(f"sending {data} from {self.Mac} to {dst}")
        self.socket.send(bytes(MACFrame(self.Mac, dst, data)))

    def send_IP_frame(self, dst: IPaddr, protocol: IPProtocol, data: bytes):
        self.logger.debug(f"sending {data} from 0x{self.Ip:02x} to 0x{dst:02x}")
        self.__manual_send_IP_frame(self.Ip, dst, protocol, data)

    def resolve_mac(self, ip: IPaddr) -> MACaddr:
        if ip in self.arp_table:
            return self.arp_table[ip]

        # If not known yet, send ARP request out correct interface
        out_iface_name = self.routing_table[ip]
        out_iface = self.interfaces[out_iface_name]

        arp_request = IPFrame(
            out_iface["IP"],
            ip,
            IPProtocol.ARP,
            b"req",
        )

        broadcast = MACFrame(
            out_iface["MAC"],
            BROADCAST_MAC,
            bytes(arp_request),
        )

        out_iface["socket"].send(bytes(broadcast))

        # wait until learned
        return self.arp_table.block_until(ip)
