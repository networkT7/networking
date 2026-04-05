from __future__ import annotations
from abc import ABC, abstractmethod
from logging import Logger
import socket
from threading import Thread
from typing import Callable, SupportsBytes, TypedDict, Unpack, override
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
    PayloadType,
    WireConfig,
)

IPFramePredicate = Callable[["Node", IPFrame], bool]
""" check if the current IP frame should be handled by the handler """

IPFrameHandler = Callable[["Node", IPFrame, MACaddr], IPFrame | None]
"""
runs on the IP frame to be handled
the return value determines if the handling chain should be stopped
"""


class FrameHandler:
    predicate: IPFramePredicate
    handler: IPFrameHandler

    def __init__(self, predicate: IPFramePredicate, handler: IPFrameHandler):
        self.predicate = predicate
        self.handler = handler

    def try_handle(
        self, node: Node, ip_frame: IPFrame, src_mac: MACaddr
    ) -> IPFrame | None:
        return (
            self.handler(node, ip_frame, src_mac)
            if self.predicate(node, ip_frame)
            else ip_frame
        )


class Application(ABC):
    @abstractmethod
    def handle_command(self, _node: Node, *_args: str):
        pass


HELP = """
SEND <IP> <message>
PING <IP>
CONNECT <IP>           - attempt TCP connection, shows ACCEPTED or REFUSED  ← [CONNECT]
SPOOF <spoofed IP> <IP> <message>
SNIFF on|off
DDOS <IP>              - volumetric flood with random source IPs
DDOS STOP
SLOWLORIS <IP>         - low-and-slow connection exhaustion
SLOWLORIS STOP
RDDOS <IP>             - rotating source distributed flood
RDDOS STOP
STATS                  - show connection table & active attacks
FW ADD ACCEPT|DROP <IP>
FW REMOVE <rule_id>
FW LIST
FW DEFAULT ACCEPT|DROP
"""


class SendMACKWargs(TypedDict, total=False):
    spoofed_mac: MACaddr


class Node:
    Mac: MACaddr
    Ip: IPaddr
    subnet: IPaddr
    subnet_mask: IPaddr
    logger: Logger
    _socket: socket.socket
    sniffing: bool
    ip_mapping: TSDict[IPaddr, MACaddr]
    ip_handlers: list[FrameHandler]
    applications: dict[str, Application]

    # receiving
    def rcv_MAC_frame(self) -> None:
        while True:
            try:
                data = self._socket.recv(RECEIVE_SIZE)
                if not data:
                    self.logger.warning("Socket closed, stopping receiver.")
                    return
                frame = MACFrame.from_bytes(data)

            except DeserializationException as e:
                self.logger.warning(f"Dropping malformed frame: {e}")
                continue

            except OSError as e:
                self.logger.warning(f"Socket error: {e}")
                return

            match frame:
                case MACFrame(src, dst, _, bites) if dst in (self.Mac, BROADCAST_MAC):
                    self.logger.debug(
                        f"receiving [MAC] src={src} dst={dst} len={len(bites)} data={bites.hex()}"
                    )
                    self.rcv_IP_frame(bites, src)

                case MACFrame(src, dst, _, data) if self.sniffing:
                    try:
                        self.logger.warning("[SNIFF] ...")
                        ip = IPFrame.from_bytes(frame.data)
                        self.handle_ip_frame(ip, src)
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

        # Firewall check
        if self.firewall is not None and not self.firewall.check(ip_frame):
            self.logger.warning(
                f"Firewall dropped packet from 0x{ip_frame.source:02x} to 0x{ip_frame.destination:02x} "
            )
            return

        self.logger.debug(
            f"rcving {ip_frame.data} from 0x{ip_frame.source:02x} to 0x{ip_frame.destination:02x} with protocol {IPProtocol(ip_frame.protocol).name}")

        self.handle_ip_frame(ip_frame, src_mac)

    def handle_ip_frame(self, ip_frame: IPFrame, src_mac: MACaddr):
        frame: IPFrame | None = ip_frame
        for handler in self.ip_handlers:
            frame = handler.try_handle(self, frame, src_mac)
            if not frame:
                return

    def add_handler(self, handler_class: FrameHandler):
        self.ip_handlers.append(handler_class)
        return self

    def add_application(self, name: str, application: Application):
        self.applications[name] = application
        return self

    # sending
    def send_MAC_frame(
        self, dst: MACaddr, data: bytes, **kwargs: Unpack[SendMACKWargs]
    ):
        spoofed_mac = kwargs.get("spoofed_mac") or self.Mac
        self.logger.debug(
            f"sending [MAC] src={spoofed_mac} dst={dst} len={len(data)} data={data.hex()}"
        )
        self._socket.sendall(bytes(MACFrame(spoofed_mac, dst, data)))

    def send_IP_frame(
        self,
        dst: IPaddr,
        protocol: IPProtocol,
        data: SupportsBytes,
        spoof_src: IPaddr | None = None,
        **kwargs: Unpack[SendMACKWargs],
    ):
        if spoof_src:
            self.logger.warning(f"[SPOOF] sending as 0x{spoof_src:02x} to 0x{dst:02x}")
        else:
            spoof_src = self.Ip

        self.logger.debug(f"sending {data} from 0x{self.Ip:02x} to 0x{dst:02x}")

        resolved_mac = self.resolve_IP(dst)

        for f in IPFrame(spoof_src, dst, protocol, data).fragment_frame():
            self.send_MAC_frame(resolved_mac, bytes(f), **kwargs)

    # address resolution
    def save_IP_mapping(self, ip: IPaddr, mac: MACaddr):
        self.ip_mapping[ip] = mac

    def send_ARP_request(self, dst: IPaddr):
        self.send_MAC_frame(
            BROADCAST_MAC,
            bytes(IPFrame(self.Ip, dst, IPProtocol.ARP, PayloadType.REQ)),
        )

    def send_ARP_response(self, dst_mac: MACaddr, claimed_ip: IPaddr, dst_ip: IPaddr):
        self.send_MAC_frame(
            dst_mac,
            bytes(IPFrame(claimed_ip, dst_ip, IPProtocol.ARP, PayloadType.RES)),
        )

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
                    msg = " ".join(msg)
                    if not msg:
                        print("Message cannot be empty")

                    self.send_IP_frame(
                        int(dst, base=16),
                        IPProtocol.DATA,
                        msg.encode(BYTE_ENCODING_TYPE),
                    )

                case ["PING", dst]:
                    self.send_IP_frame(
                        int(dst, base=16), IPProtocol.PING, PayloadType.REQ
                    )

                case [
                    "CONNECT",
                    dst,
                ]:  # ← [CONNECT] sends SYN; reply logged by TCPConnectResponseHandler
                    self.applications["tcp"].handle_command(self, dst)

                case ["SPOOF", fake_src, dst, *msg]:
                    self.send_IP_frame(
                        int(dst, base=16),
                        IPProtocol.DATA,
                        " ".join(msg).encode(BYTE_ENCODING_TYPE),
                        spoof_src=int(fake_src, base=16),
                    )

                case ["SNIFF", mode] if mode.lower() in ["on", "off"]:
                    self.sniffing = True if mode.lower() == "on" else False
                    print(f"[*] Sniffing {'enabled' if self.sniffing else 'disabled'}")

                case ["MITM", *args]:
                    self.applications["mitm"].handle_command(self, *args)

                case [ddos_attack, action] if ddos_attack in (
                    "DDOS",
                    "SLOWLORIS",
                    "RDDOS",
                ):
                    self.applications["ddos"].handle_command(self, ddos_attack, action)

                case ["STATS"]:
                    print("\n=== TRAFFIC STATS ===")
                    self.applications["tcp"].handle_command(self, "STATS")
                    self.applications["ddos"].handle_command(self, "STATS")
                    print("====================\n")

                case ["ARP"]:
                    print("\n=== ARP TABLE ===")
                    for ip, mac in dict(self.ip_mapping).items():
                        label = ""
                        if ip == self.Ip:
                            label = "(self)"
                        print(f"IP 0x{ip:02x} -> MAC {mac} {label}")
                    print("=================\n")
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
                            print(
                                f"Failed to remove firewall rule #{index}: Invalid index"
                            )
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

                # to remove
                case ["THREADS"]:
                    import threading

                    for t in threading.enumerate():
                        print(
                            f"  [{t.ident}] {t.name} | daemon={t.daemon} | alive={t.is_alive()}"
                        )
                    print(f"  TOTAL: {threading.active_count()}")

                case ["HELP"] | ["?"]:
                    print(HELP)
                case _:
                    pass

    @override
    def __init__(self, node_config: NodeConfig, wire_config: WireConfig):
        self.Mac = node_config["MAC"]
        self.Ip = node_config["IP"]
        self.logger = create_logger(self.Mac, level=LOGGING_LEVEL)
        self.subnet = wire_config["subnet"]
        self.subnet_mask = wire_config["subnetMask"]
        self._socket = socket.create_connection((HOSTNAME, wire_config["port"]))
        self.sniffing = False
        self.ip_mapping = TSDict()
        self.ip_mapping[self.Ip] = self.Mac
        self.ip_handlers = []
        self.applications = {}

        self.logger.info("connected to wire")

        if node_config.get("firewall", False):
            self.firewall: Firewall | None = Firewall(
                self.logger, default_policy=FirewallAction.ACCEPT
            )
            self.logger.info("Firewall enabled")
        else:
            self.firewall = None

        def watched():
            try:
                self.rcv_MAC_frame()
            except Exception as e:
                self.logger.error(f"Receiver thread crashed: {e}")
            finally:
                self.logger.warning("Receiver thread exited.")

        Thread(target=watched, daemon=True).start()
        Thread(target=lambda: self.send_ARP_request(self.Ip), daemon=True).start()

    def __del__(self):
        self._socket.close()
        self.logger.debug("closing node")
