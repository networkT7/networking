import socket
from threading import Thread
from logging import Logger

from networking.config import HOSTNAME, LOGGING_LEVEL, RECEIVE_SIZE
from networking.frames import MACFrame, IPFrame
from networking.log_format import create_logger
from networking.types import IPaddr, MACaddr, IPProtocol
from networking.constants import BYTE_ENCODING_TYPE
from networking.types import valid_IP


class Router:

    def __init__(self, config, wires):
        """
        config: full config["nodes"]
        wires: config["wires"]
        """

        self.logger: Logger = create_logger("ROUTER", level=LOGGING_LEVEL)
        self.arp_table = {}

        # Create interface sockets
        self.interfaces = {}
        for name in ["R1", "R2", "R3"]:
            port = wires[config[name]["wire"]]
            sock = socket.create_connection((HOSTNAME, port))
            self.interfaces[name] = {
                "socket": sock,
                "MAC": config[name]["MAC"],
                "IP": config[name]["IP"],
            }
            self.logger.info(f"{name} connected to wire")

        # Fixed routing table (IP → interface name)
        self.routing_table = {
            0x12: "R1",
            0x13: "R1",
            0x22: "R2",
            0x32: "R3",
        }

        # Start listener threads
        for name in self.interfaces:
            Thread(target=self.listen, args=(name,), daemon=True).start()

    def listen(self, iface_name):
        sock = self.interfaces[iface_name]["socket"]
        iface_mac = self.interfaces[iface_name]["MAC"]
        iface_ip = self.interfaces[iface_name]["IP"]

        while True:
            data = sock.recv(RECEIVE_SIZE)
            frame = MACFrame.from_bytes(data)

            # Accept frames sent to this interface OR broadcast
            if frame.destination not in [iface_mac, "\xff\xff"]:
                continue

            try:
                ip_frame = IPFrame.from_bytes(frame.data)
            except:
                continue


            if ip_frame.protocol.name == "ARP":
                self.arp_table[ip_frame.source] = frame.source
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
                    self.logger.info(f"{iface_name} replied to ARP")

                continue

            # ------------------------
            # Normal IP forwarding
            # ------------------------
            self.logger.info(f"{iface_name} received IP packet")
            self.forward(bytes(ip_frame))

    def forward(self, ip_bytes: bytes):

        ip_frame = IPFrame.from_bytes(ip_bytes)
        dst_ip: IPaddr = ip_frame.destination

        if dst_ip not in self.routing_table:
            self.logger.warning(f"No route for 0x{dst_ip:02x}")
            return

        out_iface_name = self.routing_table[dst_ip]
        out_iface = self.interfaces[out_iface_name]

        dst_mac = self.resolve_mac(dst_ip)

        new_mac_frame = MACFrame(
            out_iface["MAC"],
            dst_mac,
            bytes(ip_frame)
        )

        out_iface["socket"].send(bytes(new_mac_frame))

        self.logger.info(
            f"Forwarded packet to 0x{dst_ip:02x} via {out_iface_name}"
        )

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
            "\xff\xff",
            bytes(arp_request),
        )

        out_iface["socket"].send(bytes(broadcast))

        # wait until learned
        while ip not in self.arp_table:
            pass

        return self.arp_table[ip]