from dataclasses import dataclass
from logging import Logger
import socket
from threading import Thread
from typing import override

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


@dataclass
class Node:
    Mac: MACaddr
    Ip: IPaddr
    subnet: IPaddr
    subnet_mask: IPaddr
    logger: Logger
    socket: socket.SocketType
    sniffing: bool = False
    ip_mapping: TSDict[IPaddr, MACaddr] = TSDict()

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
                            f"IP src=0x{ip.source:02x} dst=0x{ip.destination:02x} "
                            f"proto={ip.protocol.name} data={ip.data}"
                        )
                    except DeserializationException:
                        self.logger.warning(
                            f"[SNIFF] raw frame: src={src} dst={dst} data={data}"
                        )
                case _:
                    pass

    def rcv_IP_frame(self, byte_arr: bytes, src_mac: MACaddr) -> IPFrame | None:
        try:
            ip_frame = IPFrame.from_bytes(byte_arr)
        except DeserializationException as e:
            self.logger.warning(str(e))
            return None

        self.logger.info(
            f"rcving {ip_frame.data} from 0x{ip_frame.source:02x} to 0x{
                ip_frame.destination:02x} with protocol {
                IPProtocol(ip_frame.protocol).name
            }"
        )
        match ip_frame:
            case IPFrame(src, self.Ip, IPProtocol.ARP, _, b"res"):
                self.logger.debug(f"ARP response received from 0x{src:02x}")
                self.save_IP_mapping(src, src_mac)

            case IPFrame(src, self.Ip, IPProtocol.ARP, _, b"req"):
                self.logger.debug(f"ARP request received from 0x{src:02x}")
                self.save_IP_mapping(src, src_mac)
                self.send_ARP_response(src_mac, src)

            case IPFrame(src, self.Ip, IPProtocol.PING, _, b"req"):
                self.logger.info(f"Ping request received from 0x{src:02x}")
                self.send_IP_frame(src, IPProtocol.PING, b"res")

            case IPFrame(src, self.Ip, IPProtocol.PING, _, b"res"):
                self.logger.info(f"Ping reply received from 0x{src:02x}")

            case IPFrame(src, self.Ip, IPProtocol.DATA, _, data):
                self.logger.info(
                    f"[DATA] Message from 0x{src:02x}: {data.decode(BYTE_ENCODING_TYPE)}"
                )

            case _:
                pass

        return ip_frame

    # sending
    def send_MAC_frame(self, dst: MACaddr, data: bytes):
        self.logger.debug(f"sending {data} from {self.Mac} to {dst}")
        self.socket.send(bytes(MACFrame(self.Mac, dst, data)))

    def send_IP_frame(self, dst: IPaddr, protocol: IPProtocol, data: bytes):
        self.logger.debug(f"sending {data} from 0x{self.Ip:02x} to 0x{dst:02x}")
        self.__manual_send_IP_frame(self.Ip, dst, protocol, data)

    def send_spoofed_IP_frame(
        self, spoof_src: IPaddr, dst: IPaddr, protocol: IPProtocol, data: bytes
    ):
        self.logger.warning(f"[SPOOF] sending as 0x{spoof_src:02x} to 0x{dst:02x}")
        self.__manual_send_IP_frame(spoof_src, dst, protocol, data)

    def __manual_send_IP_frame(
        self, src: IPaddr, dst: IPaddr, protocol: IPProtocol, data: bytes
    ):
        resolved_mac = self.resolve_IP(dst)

        self.send_MAC_frame(
            resolved_mac,
            bytes(IPFrame(src, dst, protocol, data)),
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
        while True:
            data = input(
                f"Format: MAC {{dst}} msg OR IP {{dst}} [{'|'.join([i.name for i in IPProtocol])}]: "
            )
            match data.split():
                case ["MAC", dst, *data]:
                    self.send_MAC_frame(dst, " ".join(data).encode(BYTE_ENCODING_TYPE))
                case ["IP", dst, protocol, *msg]:
                    self.send_IP_frame(
                        int(dst, base=16),
                        IPProtocol[protocol],
                        " ".join(msg).encode(BYTE_ENCODING_TYPE),
                    )
                case ["SPOOF", fake_src, dst, *msg]:
                    self.send_spoofed_IP_frame(
                        int(fake_src, base=16),
                        int(dst, base=16),
                        IPProtocol.DATA,
                        " ".join(msg).encode(BYTE_ENCODING_TYPE),
                    )
                case ["SNIFF", "on"]:
                    self.sniffing = True
                    print("[*] Sniffing enabled")
                case ["SNIFF", "off"]:
                    self.sniffing = False
                    print("[*] Sniffing disabled")
                case _:
                    pass

    @override
    def __init__(self, node_config: NodeConfig, wire_config: WireConfig):
        self.Mac = node_config["MAC"]
        self.Ip = node_config["IP"]
        self.logger = create_logger(self.Mac, level=LOGGING_LEVEL)
        self.subnet = wire_config["subnet"]
        self.subnet_mask = wire_config["subnetMask"]
        self.socket = socket.create_connection((HOSTNAME, wire_config["port"]))
        self.logger.info("connected to wire")

        Thread(target=self.rcv_MAC_frame, daemon=True).start()

    def __del__(self):
        self.socket.close()
        self.logger.debug("closing node")
