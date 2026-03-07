from dataclasses import dataclass
from logging import Logger
import socket
from threading import Thread
from typing import override
from networking.firewall import Firewall, FirewallRule, FirewallAction
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
)


@dataclass
class Node:
    Mac: MACaddr
    Ip: IPaddr
    _logger: Logger
    _socket: socket.SocketType
    ip_mapping: TSDict[IPaddr, MACaddr] = TSDict()

    # receiving
    def rcv_MAC_frame(self) -> MACFrame:
        while True:
            data = self._socket.recv(RECEIVE_SIZE)
            frame = MACFrame.from_bytes(data)

            match frame:
                case MACFrame(src, dst, _, bites) if dst in (
                    self.Mac,
                    BROADCAST_MAC,
                ):
                    self._logger.info(f"receiving [MAC] src={src} dst={dst} len={len(bites)} data={bites.hex()}")
                    self.rcv_IP_frame(bites, src)
                case _:
                    pass

    def rcv_IP_frame(
        self, byte_arr: bytes, src_mac: MACaddr
    ) -> IPFrame | None:
        try:
            ip_frame = IPFrame.from_bytes(byte_arr)
        except DeserializationException as e:
            self._logger.warning(str(e))
            return None

        # Firewall check
        if self.firewall is not None and not self.firewall.check(ip_frame):
            self._logger.warning(
                f"Firewall dropped packet from 0x{ip_frame.source:02x} to 0x{ip_frame.destination:02x} "
            )
            return None

        self._logger.info(
            f"rcving {ip_frame.data} from 0x{ip_frame.source:02x} to 0x{
                ip_frame.destination:02x} with protocol {
                IPProtocol(ip_frame.protocol).name
            }"
        )
        match ip_frame:
            case IPFrame(src, self.Ip, IPProtocol.ARP, _, b"res"):
                self.save_IP_mapping(src, src_mac)
                return ip_frame

            case IPFrame(src, self.Ip, IPProtocol.ARP, _, b"req"):
                self.save_IP_mapping(src, src_mac)
                self.send_ARP_response(src_mac, src)
                return ip_frame

            case IPFrame(src, self.Ip, IPProtocol.PING, _, b"req"):
                self._logger.info(f"Ping request received from 0x{src:02x}")
                self.send_IP_frame(src, IPProtocol.PING, b"res")
                return ip_frame

            case IPFrame(src, self.Ip, IPProtocol.PING, _, b"res"):
                self._logger.info(f"Ping reply received from 0x{src:02x}")
                return ip_frame

            case _:
                return None

    # sending
    def send_MAC_frame(self, dst: MACaddr, data: bytes):
        self._logger.info(f"sending [MAC] src={self.Mac} dst={dst} len={len(data)} data={data.hex()}")
        self._socket.sendall(bytes(MACFrame(self.Mac, dst, data)))

    def send_IP_frame(self, dst: IPaddr, protocol: IPProtocol, data: bytes):
        self._logger.info(f"sending {data} from 0x{self.Ip:02x} to 0x{dst:02x}")

        # Determine next hop (basic subnet logic)
        if (self.Ip & 0xF0) == (dst & 0xF0):
            # Same LAN → send directly
            next_hop_ip = dst
        else:
            # Different LAN → send to router interface
            if (self.Ip & 0xF0) == 0x10:
                next_hop_ip = 0x11  # R1
            elif (self.Ip & 0xF0) == 0x20:
                next_hop_ip = 0x21  # R2
            elif (self.Ip & 0xF0) == 0x30:
                next_hop_ip = 0x31  # R3
            else:
                raise Exception("Unknown subnet")

        resolved_mac = self.resolve_IP(next_hop_ip)

        self.send_MAC_frame(
            resolved_mac,
            bytes(IPFrame(self.Ip, dst, protocol, data)),
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
        self._logger.debug(f"resolving ip 0x{dst:02x}")
        if dst not in self.ip_mapping:
            self.send_ARP_request(dst)
        mac = self.ip_mapping.block_until(dst)
        self._logger.debug(f"resolved, mac is {mac}")
        return mac

    # object methods
    def input(self):
        while True:
            data = input("Format: MAC {dst} msg OR IP {dst} [PING|] msg: ")
            match data.split():
                case ["MAC", dst, *data]:
                    self.send_MAC_frame(dst, " ".join(data).encode(BYTE_ENCODING_TYPE))
                case ["IP", dst, protocol]:
                    self.send_IP_frame(
                        int(dst, base=16),
                        IPProtocol[protocol],
                        b"req",
                    )
                # Firewall commands
                case ["FW", "ADD", action_str, src_ip_hex] if self.firewall is not None:
                    try:
                        action = FirewallAction(action_str.upper())
                        src_ip = int(src_ip_hex, base=16)
                        rule = FirewallRule(src_ip=src_ip, protocol=None, action=action)
                        index = self.firewall.add_rule(rule)
                        print(f"Added firewall rule #{index}: {rule}")
                    except (ValueError, KeyError) as e:
                        print(f"Invalid firewall rule: {e}")

                case ["FW", "REMOVE", index_str] if self.firewall is not None:
                    try:
                        index = int(index_str)
                        if self.firewall.remove_rule(index):
                            print(f"Removed firewall rule #{index}")
                        else:
                            print(f"Failed to remove firewall rule #{index}: Invalid index")
                    except ValueError:
                        print(f"Invalid firewall rule index: {index_str}")

                case ["FW", "LIST"] if self.firewall is not None:
                    for i in self.firewall.list_rules():
                        print(i)

                case ["FW", "DEFAULT", policy_str] if self.firewall is not None:
                    try:
                        policy = FirewallAction(policy_str.upper())
                        self.firewall.set_default_policy(policy)
                        print(f"Set default firewall policy to {policy.value}")
                    except KeyError:
                        print("Invalid policy. Policy must be 'accept' or 'drop'")

                case ["FW", *_]:
                    if self.firewall is None:
                        print("Firewall is not enabled on this node.")
                    else:
                        print("Usage: FW ADD <drop|accept> <src_ip_hex>")
                        print("       FW REMOVE <rule_index>")
                        print("       FW LIST")
                        print("       FW DEFAULT <accept|drop>")

                case _:
                    pass

    @override
    def __init__(self, node_config: NodeConfig, wire_port: int):
        self.Mac = node_config["MAC"]
        self.Ip = node_config["IP"]
        self._logger = create_logger(self.Mac, level=LOGGING_LEVEL)
        self._socket = socket.create_connection((HOSTNAME, wire_port))
        self._logger.info("connected to wire")
        if node_config.get("firewall", False):
            self.firewall: Firewall | None = Firewall(self._logger, default_policy=FirewallAction.ACCEPT)
            self._logger.info("Firewall enabled")
        else:
            self.firewall = None
        Thread(target=self.rcv_MAC_frame).start()

    def __del__(self):
        self._socket.close()
        self._logger.debug("closing node")
