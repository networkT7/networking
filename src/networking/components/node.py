from logging import Logger
import socket
from threading import Thread
from typing import Callable, override
from random import randint
from threading import Event
from networking.firewall import Firewall, FirewallRule, FirewallAction
from networking.collections.ts_dict import TSDict
from networking.config import HOSTNAME, LOGGING_LEVEL
from networking.constants import BYTE_ENCODING_TYPE, BROADCAST_MAC
from networking.frames import MACFrame, IPFrame, DeserializationException
from networking.components.wire import send_framed, recv_framed
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
SNIFF on|off
FW
FW ADD ACCEPT|DROP <IP>
FW REMOVE <rule_id>
FW LIST
FW DEFAULT ACCEPT|DROP
"""

class MITMHandler(FrameHandlerClass):
    """
    Intercepts packets destined for `router_ip` that were sent by `victim_ip`,
    logs them, then forwards them to the real router.
    """
    victim_ip: IPaddr
    router_ip: IPaddr

    def __init__(self, victim_ip: IPaddr, router_ip: IPaddr):
        self.victim_ip = victim_ip
        self.router_ip = router_ip

        def predicate(node: "Node", ip_frame: IPFrame) -> bool:
            # Only intercept frames originating from the victim
            return ip_frame.source == victim_ip

        def handler(node: "Node", ip_frame: IPFrame, src_mac: MACaddr) -> bool:
            node._logger.warning(
                f"[MITM] Intercepted packet: "
                f"src=0x{ip_frame.source:02x} dst=0x{ip_frame.destination:02x} "
                f"proto={IPProtocol(ip_frame.protocol).name} data={ip_frame.data}"
            )
            # Forward the original frame onwards to the real destination
            node.send_IP_frame(ip_frame.destination, IPProtocol(ip_frame.protocol), ip_frame.data)
            return True  # stop handler chain — we've dealt with it

        super().__init__(predicate, handler)

class Node:
    Mac: MACaddr
    Ip: IPaddr
    subnet: IPaddr
    subnet_mask: IPaddr
    _logger: Logger
    _socket: socket.socket
    sniffing: bool
    ip_mapping: TSDict[IPaddr, MACaddr]
    ip_handlers: list[FrameHandlerClass]

    # receiving
    def rcv_MAC_frame(self) -> None:
        while True:
            try:
                data = recv_framed(self._socket)
                if not data:                          # socket closed gracefully
                    self._logger.warning("Socket closed, stopping receiver.")
                    return
                frame = MACFrame.from_bytes(data)
            except DeserializationException as e:
                self._logger.warning(f"Dropping malformed frame: {e}")
                continue                              # skip bad frame, keep looping
            except OSError as e:
                self._logger.warning(f"Socket error: {e}")
                return

            match frame:
                case MACFrame(src, dst, _, bites) if dst in (
                    self.Mac,
                    BROADCAST_MAC,
                ):
                    self._logger.info(
                        f"receiving [MAC] src={src} dst={dst} len={len(bites)} data={bites.hex()}"
                    )
                    self.rcv_IP_frame(bites, src)
                case MACFrame(src, dst, _, data) if self.sniffing:
                    try:
                        ip = IPFrame.from_bytes(frame.data)
                        self._logger.warning(
                            f"[SNIFF] src={src} dst={dst} | "
                            + f"IP src=0x{ip.source:02x} dst=0x{ip.destination:02x} "
                            + f"proto={ip.protocol.name} data={ip.data}"
                        )
                    except DeserializationException:
                        self._logger.warning(
                            f"[SNIFF] raw frame: src={src} dst={dst} data={data}"
                        )
                case _:
                    pass

    def rcv_IP_frame(self, byte_arr: bytes, src_mac: MACaddr):
        try:
            ip_frame = IPFrame.from_bytes(byte_arr)
        except DeserializationException as e:
            self._logger.warning(str(e))
            return

        # Firewall check
        if self.firewall is not None and not self.firewall.check(ip_frame):
            self._logger.warning(
                f"Firewall dropped packet from 0x{ip_frame.source:02x} to 0x{ip_frame.destination:02x} "
            )
            return

        self._logger.info(
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

    def ddos(self, target_ip: IPaddr, count: int = 200):
        self._logger.warning(f"[DDOS] Starting DDoS on 0x{target_ip:02x}")
        self._ddos_stop = Event()
        sent = 0
        while not self._ddos_stop.is_set() and sent < count:
            fake_src = randint(0x01, 0xFE)        # random spoofed source IP
            self.send_spoofed_IP_frame(
                fake_src,
                target_ip,
                IPProtocol.DATA,
                b"flood",
            )
            sent += 1
        self._logger.warning(f"[DDOS] Finished — sent {sent} packets to 0x{target_ip:02x}")
        
    # sending
    def send_MAC_frame(self, dst: MACaddr, data: bytes):
        self._logger.info(
            f"sending [MAC] src={self.Mac} dst={dst} len={len(data)} data={data.hex()}"
        )
        send_framed(self._socket, bytes(MACFrame(self.Mac, dst, data)))

    def send_IP_frame(self, dst: IPaddr, protocol: IPProtocol, data: bytes):
        self._logger.info(f"sending {data} from 0x{self.Ip:02x} to 0x{dst:02x}")
        self.send_spoofed_IP_frame(self.Ip, dst, protocol, data)

    def send_spoofed_IP_frame(
        self, spoof_src: IPaddr, dst: IPaddr, protocol: IPProtocol, data: bytes
    ):
        if self.Ip != spoof_src:
            self._logger.warning(f"[SPOOF] sending as 0x{spoof_src:02x} to 0x{dst:02x}")
        resolved_mac = self.resolve_IP(dst)

        self.send_MAC_frame(
            resolved_mac,
            bytes(IPFrame(spoof_src, dst, protocol, data)),
        )

    # address resolution
    def save_IP_mapping(self, ip: IPaddr, mac: MACaddr):
        self._logger.debug(f"IP {ip:02x} saved as MAC {mac}")
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

        self._logger.debug(f"resolving ip 0x{next_hop_ip:02x}")
        if next_hop_ip not in self.ip_mapping:
            self.send_ARP_request(next_hop_ip)
        mac = self.ip_mapping.block_until(next_hop_ip)
        self._logger.debug(f"resolved, mac is {mac}")
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
                case ["MITM", victim_ip_hex, router_ip_hex]:
                    victim_ip = int(victim_ip_hex, base=16)
                    router_ip = int(router_ip_hex, base=16)

                    # Poison the victim's ARP cache:
                    # Tell the victim that router_ip is at *our* MAC address
                    self.send_ARP_response(
                        self.resolve_IP(victim_ip),   # send to victim's MAC
                        router_ip,                    # "I am the owner of router_ip"
                    )
                    self._logger.warning(
                        f"[MITM] ARP poison sent to 0x{victim_ip:02x} — "
                        f"claiming router 0x{router_ip:02x} is at {self.Mac}"
                    )

                    # Install the intercept+forward handler if not already present
                    if not any(isinstance(h, MITMHandler) for h in self.ip_handlers):
                        self.add_handler(MITMHandler(victim_ip, router_ip))
                        self._logger.warning(f"[MITM] Intercept handler installed for victim 0x{victim_ip:02x}")
                    else:
                        print("[MITM] Handler already active.")
                case ["DDOS", target_ip_hex]:
                    target_ip = int(target_ip_hex, base=16)
                    Thread(target=self.ddos, args=(target_ip,), daemon=True).start()

                case ["DDOS", "STOP"]:
                    if self._ddos_stop is not None:
                        self._ddos_stop.set()
                        print("[DDOS] Stopping attack...")
                    else:
                        print("[DDOS] No active DDoS attack.")
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

                case _:
                    print(HELP)

    @override
    def __init__(self, node_config: NodeConfig, wire_config: WireConfig):
        self.Mac = node_config["MAC"]
        self.Ip = node_config["IP"]
        self._logger = create_logger(self.Mac, level=LOGGING_LEVEL)
        self.subnet = wire_config["subnet"]
        self.subnet_mask = wire_config["subnetMask"]
        self._socket = socket.create_connection((HOSTNAME, wire_config["port"]))
        self.sniffing = False
        self.ip_mapping = TSDict()
        self.ip_handlers = []
        self._ddos_stop: Event | None = None  
        self._logger.info("connected to wire")

        if node_config.get("firewall", False):
            self.firewall: Firewall | None = Firewall(
                self._logger, default_policy=FirewallAction.ACCEPT
            )
            self._logger.info("Firewall enabled")
        else:
            self.firewall = None

        self._start_receiver()  

    def _start_receiver(self):
        def watched():
            try:
                self.rcv_MAC_frame()
            except Exception as e:
                self._logger.error(f"Receiver thread crashed: {e}")
            finally:
                self._logger.warning("Receiver thread exited.")

        Thread(target=watched, daemon=True).start()

    def __del__(self):
        self._socket.close()
        self._logger.debug("closing node")