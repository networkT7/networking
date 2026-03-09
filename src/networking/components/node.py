from logging import Logger
import socket
from threading import Thread
from typing import Callable, override

from networking.collections.ts_dict import TSDict
from networking.config import HOSTNAME, LOGGING_LEVEL, RECEIVE_SIZE
from networking.constants import BYTE_ENCODING_TYPE, BROADCAST_MAC
from networking.frames import MACFrame, IPFrame, DeserializationException
from networking.log_format import create_logger
from networking.types import (
    MACaddr,
    IPaddr,
    IPProtocol,
    NodeConfig,
    WireConfig,
)

IPFramePredicate = Callable[["Node", IPFrame], bool]
""" check if the current IP frame should be handled by the handler """

IPFrameHandler = Callable[["Node", IPFrame, MACaddr], bool]
"""
runs on the IP frame to be handled
the return value determines if the handling chain should be stopped
"""


class FrameHandlerClass:
    predicate: IPFramePredicate
    handler: IPFrameHandler

    def __init__(self, predicate: IPFramePredicate, handler: IPFrameHandler):
        self.predicate = predicate
        self.handler = handler

    def try_handle(self, node: "Node", ip_frame: IPFrame, src_mac: MACaddr) -> bool:
        return self.predicate(node, ip_frame) and self.handler(node, ip_frame, src_mac)


HELP = """
SEND <IP> <message>
PING <IP>
SPOOF <spoofed IP> <IP> <message>
SNIFF {{on|off}}
"""


class Node:
    Mac: MACaddr
    Ip: IPaddr
    subnet: IPaddr
    subnet_mask: IPaddr
    logger: Logger
    socket: socket.SocketType
    sniffing: bool
    ip_mapping: TSDict[IPaddr, MACaddr]
    ip_handlers: list[FrameHandlerClass]

    # receiving
    def rcv_MAC_frame(self) -> MACFrame:
        while True:
            data = self.socket.recv(RECEIVE_SIZE)
            try:
                frame = MACFrame.from_bytes(data)
            except DeserializationException:
                continue

            match frame:
                case MACFrame(src, dst, _, bites) if dst in [self.Mac, BROADCAST_MAC]:
                    self.logger.info(f"rcving {bites} from {src} to {dst}")
                    self.rcv_IP_frame(bites, src)
                case MACFrame(src, dst, _, data) if self.sniffing:
                    try:
                        ip = IPFrame.from_bytes(frame.data)
                        self.logger.warning(
                            f"[SNIFF] src={src} dst={dst} | "
                            + f"IP src=0x{ip.source:02x} dst=0x{ip.destination:02x} "
                            + f"proto={ip.protocol.name} data={ip.data}"
                        )
                    except DeserializationException:
                        self.logger.warning(
                            f"[SNIFF] raw frame: src={src} dst={dst} data={data}"
                        )
                case _:
                    pass

    def rcv_IP_frame(self, byte_arr: bytes, src_mac: MACaddr):
        try:
            ip_frame = IPFrame.from_bytes(byte_arr)
        except DeserializationException as e:
            self.logger.warning(str(e))
            return

        self.logger.info(
            f"rcving {ip_frame.data} from 0x{ip_frame.source:02x} to 0x{
                ip_frame.destination:02x} with protocol {
                IPProtocol(ip_frame.protocol).name
            }"
        )

        for handler in self.ip_handlers:
            if handler.try_handle(self, ip_frame, src_mac):
                return

    def add_handler(self, handler_class: FrameHandlerClass):
        self.ip_handlers.append(handler_class)
        return self

    # sending
    def send_MAC_frame(self, dst: MACaddr, data: bytes):
        self.logger.debug(f"sending {data} from {self.Mac} to {dst}")
        self.socket.send(bytes(MACFrame(self.Mac, dst, data)))

    def send_IP_frame(self, dst: IPaddr, protocol: IPProtocol, data: bytes):
        self.logger.debug(f"sending {data} from 0x{self.Ip:02x} to 0x{dst:02x}")
        self.send_spoofed_IP_frame(self.Ip, dst, protocol, data)

    def send_spoofed_IP_frame(
        self, spoof_src: IPaddr, dst: IPaddr, protocol: IPProtocol, data: bytes
    ):
        if self.Ip != spoof_src:
            self.logger.warning(f"[SPOOF] sending as 0x{spoof_src:02x} to 0x{dst:02x}")
        resolved_mac = self.resolve_IP(dst)

        self.send_MAC_frame(
            resolved_mac,
            bytes(IPFrame(spoof_src, dst, protocol, data)),
        )

    # address resolution
    def save_IP_mapping(self, ip: IPaddr, mac: MACaddr):
        self.ip_mapping[ip] = mac

    def send_ARP_request(self, dst: IPaddr):
        self.send_MAC_frame(
            BROADCAST_MAC,
            bytes(IPFrame(self.Ip, dst, IPProtocol.ARP, b"req")),
        )

    def send_ARP_response(self, dst: MACaddr, ip: IPaddr):
        self.send_MAC_frame(dst, bytes(IPFrame(self.Ip, ip, IPProtocol.ARP, b"res")))

    def resolve_IP(self, dst: IPaddr) -> MACaddr:
        # Determine next hop (basic subnet logic)
        # Same LAN → send directly
        # Different LAN → send to router interface
        next_hop_ip = (
            dst if dst & self.subnet_mask == self.subnet else self.subnet | 0x01
        )

        self.logger.debug(f"resolving ip 0x{next_hop_ip:02x}")
        if next_hop_ip not in self.ip_mapping:
            self.send_ARP_request(next_hop_ip)
        mac = self.ip_mapping.block_until(next_hop_ip)
        self.logger.debug(f"resolved, mac is {mac}")
        return mac

    # object methods
    def input(self):
        print("Type help to get all possible commands")
        while True:
            data = input("> ")
            match data.split():
                case ["SEND", dst, *msg]:
                    self.send_IP_frame(
                        int(dst, base=16),
                        IPProtocol.DATA,
                        " ".join(msg).encode(BYTE_ENCODING_TYPE),
                    )
                case ["PING", dst]:
                    self.send_IP_frame(int(dst, base=16), IPProtocol.PING, b"req")
                case ["SPOOF", fake_src, dst, *msg]:
                    self.send_spoofed_IP_frame(
                        int(fake_src, base=16),
                        int(dst, base=16),
                        IPProtocol.DATA,
                        " ".join(msg).encode(BYTE_ENCODING_TYPE),
                    )
                case ["SNIFF", mode] if mode.lower() in ["on", "off"]:
                    self.sniffing = True if mode.lower() == "on" else False
                    print(f"[*] Sniffing {'enabled' if self.sniffing else 'disabled'}")
                case _:
                    print(HELP)

    @override
    def __init__(self, node_config: NodeConfig, wire_config: WireConfig):
        self.Mac = node_config["MAC"]
        self.Ip = node_config["IP"]
        self.logger = create_logger(self.Mac, level=LOGGING_LEVEL)
        self.subnet = wire_config["subnet"]
        self.subnet_mask = wire_config["subnetMask"]
        self.socket = socket.create_connection((HOSTNAME, wire_config["port"]))
        self.sniffing = False
        self.ip_mapping = TSDict()
        self.ip_handlers = []
        self.logger.info("connected to wire")

        Thread(target=self.rcv_MAC_frame, daemon=True).start()

    def __del__(self):
        self.socket.close()
        self.logger.debug("closing node")
