from logging import Logger
import socket, time
from threading import Thread, Lock
from typing import Callable, TypedDict, Unpack, override
from random import randint
from threading import Event
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


class MITMHandler(FrameHandlerClass):
    """
    Intercepts packets from victim ONLY when MITM is active,
    logs them, then forwards them to the real destination.
    """

    victim_ip: IPaddr
    router_ip: IPaddr

    def __init__(self, victim_ip: IPaddr, router_ip: IPaddr):
        self.victim_ip = victim_ip
        self.router_ip = router_ip

        def predicate(node: "Node", ip_frame: IPFrame) -> bool:

            if not getattr(node, "_mitm_active", False):
                return False

            return ip_frame.source == victim_ip

        def handler(node: "Node", ip_frame: IPFrame, src_mac: MACaddr) -> bool:

            if not getattr(node, "_mitm_active", False):
                return False

            original_data = ip_frame.data

            node._logger.warning(
                f"[MITM] Intercepted packet: "
                f"src=0x{ip_frame.source:02x} dst=0x{ip_frame.destination:02x} "
                f"proto={IPProtocol(ip_frame.protocol).name} data={original_data}"
            )

            # =========================
            # 🔥 ACTIVE MODE (USER INPUT)
            # =========================
            if getattr(node, "_mitm_mode", "passive") == "active":
                try:
                    decoded = original_data.decode("utf-8")
                except:
                    decoded = str(original_data)

                print("\n=== MITM INTERCEPT ===")
                print(f"Original message: {decoded}")
                print("Options:")
                print("  [1] Forward unchanged")
                print("  [2] Modify message")
                print("  [3] Drop packet")
                print("\n⚠️  Press ENTER before typing your choice", flush=True)
                choice = input("Select option: ").strip()

                if choice == "2":
                    print("\n⚠️  Press ENTER before typing modified message", flush=True)
                    new_msg = input("Enter modified message: ")
                    modified = new_msg.encode("utf-8")

                elif choice == "3":
                    print("[MITM] Packet dropped.")
                    return True

                else:
                    modified = original_data

            else:
                # =========================
                # 💤 PASSIVE MODE
                # =========================
                modified = original_data

            # 🔥 Build new frame
            new_frame = IPFrame(
                ip_frame.source, ip_frame.destination, ip_frame.protocol, modified
            )

            real_mac = node.resolve_IP(ip_frame.destination)
            node.send_MAC_frame(real_mac, bytes(new_frame))

            node._logger.warning(f"[MITM] Forwarded → {modified}")

            return True

        super().__init__(predicate, handler)


class MITMARPInterceptHandler(FrameHandlerClass):
    """
    When sniffed: if victim sends ARP req for router,
    N2 responds immediately so victim never hears from real router.
    """

    node: Node
    victim_ip: IPaddr
    router_ip: IPaddr

    def __init__(self, node: Node, victim_ip: IPaddr, router_ip: IPaddr):
        self.victim_ip = victim_ip
        self.router_ip = router_ip
        self.node = node

        def predicate(node: "Node", f: IPFrame) -> bool:
            return (
                f.protocol == IPProtocol.ARP
                and f.data == b"req"
                and f.source == victim_ip
                and f.destination == router_ip
            )

        def handler(node: "Node", f: IPFrame, src_mac: MACaddr) -> bool:
            node._logger.warning(
                f"[MITM] Intercepted ARP req from 0x{f.source:02x} for 0x{f.destination:02x} — spoofing response"
            )
            # Reply to victim claiming we are the router
            node.send_ARP_response(src_mac, router_ip, dst_ip=victim_ip)
            return True

        super().__init__(predicate, handler)

    def __del__(self):
        self.node._logger.warning("Removing ARP intercept handler")
        victim_mac = self.node.resolve_IP(self.victim_ip)
        router_mac = self.node.resolve_IP(self.router_ip)
        self.node.send_spoofed_IP_frame(
            self.victim_ip,
            self.router_ip,
            IPProtocol.ARP,
            b"res",
            spoofed_mac=victim_mac,
        )
        self.node.send_spoofed_IP_frame(
            self.router_ip,
            self.victim_ip,
            IPProtocol.ARP,
            b"res",
            spoofed_mac=router_mac,
        )


class SendMACKWargs(TypedDict, total=False):
    spoofed_mac: MACaddr | None


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
                data = self._socket.recv(RECEIVE_SIZE)
                if not data:
                    self._logger.warning("Socket closed, stopping receiver.")
                    return
                frame = MACFrame.from_bytes(data)

            except DeserializationException as e:
                self._logger.warning(f"Dropping malformed frame: {e}")
                continue

            except OSError as e:
                self._logger.warning(f"Socket error: {e}")
                return

            match frame:
                case MACFrame(src, dst, _, bites) if dst in (self.Mac, BROADCAST_MAC):
                    self._logger.info(
                        f"receiving [MAC] src={src} dst={dst} len={len(bites)} data={bites.hex()}"
                    )
                    self.rcv_IP_frame(bites, src)

                case MACFrame(src, dst, _, data) if self.sniffing:
                    try:
                        ip = IPFrame.from_bytes(frame.data)
                        self._logger.warning("[SNIFF] ...")
                        for handler in self.ip_handlers:
                            if handler.try_handle(self, ip, src):
                                break
                    except DeserializationException:
                        self._logger.warning(
                            f"[SNIFF] raw frame: src={src} dst={dst} data={data}"
                        )

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

    def ddos(self, target_ip: IPaddr):
        self._logger.warning(f"[DDOS] Starting DDoS on 0x{target_ip:02x}")

        if self._ddos_stop is None:
            self._ddos_stop = Event()
        else:
            self._ddos_stop.clear()

        total_sent = 0
        while True:
            if self._ddos_stop.is_set():
                print(
                    f"\r[DDOS] Stopped. Total packets sent: {total_sent:<8}", flush=True
                )
                self._logger.warning("[DDOS] Stopped.")
                break

            fake_src = randint(0x01, 0xFE)

            self.send_spoofed_IP_frame(
                fake_src,
                target_ip,
                IPProtocol.DATA,
                b"flood",
            )

            total_sent += 1
            print(
                f"\r[DDOS] Flooding 0x{target_ip:02x} | pkts: {total_sent:<6} | src: 0x{fake_src:02x} (random)",
                end="",
                flush=True,
            )
            time.sleep(0.01)  # controls speed (don’t remove)

    def _cleanup_stale_connections(self):
        """Remove connections that have timed out. Must be called with _conn_lock held."""
        now = time.monotonic()
        stale = [
            ip
            for ip, info in self._conn_table.items()
            if now - info["last_activity"] > self._conn_timeout
        ]
        for ip in stale:
            del self._conn_table[ip]
            self._logger.debug(f"[TCP] Connection from 0x{ip:02x} timed out")

    def slowloris(self, target_ip: IPaddr):
        self._logger.warning(f"[SLOWLORIS] Starting Slowloris on 0x{target_ip:02x}")

        if self._slowloris_stop is None:
            self._slowloris_stop = Event()
        else:
            self._slowloris_stop.clear()

        # Phase 1: Open connections with spoofed IPs
        # 12 IPs > max_connections (10), so last 2 get dropped — demonstrates exhaustion
        # Pool is offset by node IP so concurrent attackers don't share spoofed IPs
        # (shared IPs trigger the router's DAI and get dropped)
        base = (self.Ip & 0x0F) * 12
        pool = [(0x80 + base + i) & 0xFF for i in range(12)]  # 12 spoofed source IPs
        self._logger.warning(f"[SLOWLORIS] Phase 1: Opening {len(pool)} connections...")

        for i, spoofed_ip in enumerate(pool):
            if self._slowloris_stop.is_set():
                self._logger.warning("[SLOWLORIS] Stopped during Phase 1.")
                return

            self.send_spoofed_IP_frame(spoofed_ip, target_ip, IPProtocol.TCP, b"SYN")
            self._logger.warning(f"[SLOWLORIS] Phase 1: SYN sent ({i + 1}/{len(pool)})")
            time.sleep(0.2)

        # Phase 2: Hold connections open with keepalives
        # Cycle must complete within _conn_timeout (10s).
        # 12 IPs x 0.5s = 6s per cycle — safely under 10s timeout.
        keepalive_sleep = 0.5
        cycle_time = len(pool) * keepalive_sleep
        self._logger.warning(
            f"[SLOWLORIS] Phase 2: Holding connections, "
            f"cycle every {cycle_time:.0f}s, ~{1 / keepalive_sleep:.0f} pps"
        )

        cycle_count = 0
        while not self._slowloris_stop.is_set():
            for spoofed_ip in pool:
                if self._slowloris_stop.is_set():
                    break
                self.send_spoofed_IP_frame(
                    spoofed_ip, target_ip, IPProtocol.TCP, b"KEEPALIVE"
                )
                time.sleep(keepalive_sleep)

            cycle_count += 1
            self._logger.warning(
                f"[SLOWLORIS] Status: keepalive cycle {cycle_count} complete "
                f"({len(pool)} connections maintained)"
            )

        self._logger.warning("[SLOWLORIS] Stopped.")

    def rddos(self, target_ip: IPaddr):
        self._logger.warning(
            f"[RDDOS] Starting rotating source DDoS on 0x{target_ip:02x}"
        )

        if self._rddos_stop is None:
            self._rddos_stop = Event()
        else:
            self._rddos_stop.clear()

        pool = list(range(0xC0, 0xD4))  # 20 spoofed source IPs
        self._logger.warning(
            f"[RDDOS] Using {len(pool)} rotating sources, "
            f"~{1000 / 5:.0f} pps aggregate, "
            f"~{1000 / (5 * len(pool)):.0f} pps per source"
        )

        total_sent = 0
        idx = 0

        while not self._rddos_stop.is_set():
            spoofed_ip = pool[idx % len(pool)]
            self.send_spoofed_IP_frame(spoofed_ip, target_ip, IPProtocol.DATA, b"flood")
            total_sent += 1
            idx += 1

            bar_filled = idx % len(pool)
            bar = "#" * bar_filled + "." * (len(pool) - bar_filled)
            print(
                f"\r[RDDOS] [{bar}] pkts: {total_sent:<6} | src: 0x{spoofed_ip:02x} | ~200 pps",
                end="",
                flush=True,
            )

            time.sleep(0.005)

        print(f"\r[RDDOS] Stopped. Total packets sent: {total_sent:<8}", flush=True)
        self._logger.warning(f"[RDDOS] Stopped. Total packets sent: {total_sent}")

    # sending
    def send_MAC_frame(
        self, dst: MACaddr, data: bytes, **kwargs: Unpack[SendMACKWargs]
    ):
        spoofed_mac = kwargs.get("spoofed_mac") or self.Mac
        self._logger.info(
            f"sending [MAC] src={spoofed_mac} dst={dst} len={len(data)} data={data.hex()}"
        )
        self._socket.sendall(bytes(MACFrame(spoofed_mac, dst, data)))

    def send_IP_frame(self, dst: IPaddr, protocol: IPProtocol, data: bytes):
        self._logger.info(f"sending {data} from 0x{self.Ip:02x} to 0x{dst:02x}")
        self.send_spoofed_IP_frame(self.Ip, dst, protocol, data)

    def send_spoofed_IP_frame(
        self,
        spoof_src: IPaddr,
        dst: IPaddr,
        protocol: IPProtocol,
        data: bytes,
        **kwargs: Unpack[SendMACKWargs],
    ):
        if self.Ip != spoof_src:
            self._logger.warning(f"[SPOOF] sending as 0x{spoof_src:02x} to 0x{dst:02x}")
        resolved_mac = self.resolve_IP(dst)

        self.send_MAC_frame(
            resolved_mac, bytes(IPFrame(spoof_src, dst, protocol, data)), **kwargs
        )

    # address resolution
    def save_IP_mapping(self, ip, mac):
        self.ip_mapping[ip] = mac

    def send_ARP_request(self, dst: IPaddr):
        self.send_MAC_frame(
            BROADCAST_MAC,
            bytes(IPFrame(self.Ip, dst, IPProtocol.ARP, b"req")),
        )

    def send_ARP_response(self, dst_mac: MACaddr, claimed_ip: IPaddr, dst_ip: IPaddr):
        self.send_MAC_frame(
            dst_mac,
            bytes(IPFrame(claimed_ip, dst_ip, IPProtocol.ARP, b"res")),
        )

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

                case [
                    "CONNECT",
                    dst,
                ]:  # ← [CONNECT] sends SYN; reply logged by TCPConnectResponseHandler
                    self.send_IP_frame(int(dst, base=16), IPProtocol.TCP, b"SYN")

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

                case ["MITM", "STOP"]:
                    self._mitm_active = False
                    self.sniffing = False
                    self.ip_handlers = [
                        h
                        for h in self.ip_handlers
                        if h.__class__.__name__
                        not in ["MITMHandler", "MITMARPInterceptHandler"]
                    ]

                case ["MITM", "MODE", mode]:
                    if mode.lower() in ["active", "passive"]:
                        self._mitm_mode = mode.lower()
                        print(f"[MITM] Mode set to {self._mitm_mode.upper()}")
                    else:
                        print("Usage: MITM MODE active|passive")

                case ["MITM", victim_ip_hex, router_ip_hex]:
                    victim_ip = int(victim_ip_hex, base=16)
                    router_ip = int(router_ip_hex, base=16)

                    self._mitm_active = True

                    victim_mac = self.resolve_IP(victim_ip)
                    router_mac = self.resolve_IP(router_ip)

                    self.sniffing = True

                    if not any(
                        h.__class__.__name__ == "MITMARPInterceptHandler"
                        for h in self.ip_handlers
                    ):
                        self.add_handler(
                            MITMARPInterceptHandler(self, victim_ip, router_ip)
                        )

                    if not any(
                        h.__class__.__name__ == "MITMHandler" for h in self.ip_handlers
                    ):
                        self.add_handler(MITMHandler(victim_ip, router_ip))

                    def poison_loop():
                        while getattr(self, "_mitm_active", False):
                            self.send_ARP_response(victim_mac, router_ip, victim_ip)
                            self.send_ARP_response(router_mac, victim_ip, router_ip)
                            time.sleep(2)

                    Thread(target=poison_loop, daemon=True).start()

                    self._logger.warning(
                        f"[MITM] Attack started against 0x{victim_ip:02x}"
                    )

                case ["DDOS", "STOP"]:
                    if self._ddos_stop is not None and not self._ddos_stop.is_set():
                        self._ddos_stop.set()
                        print("[DDOS] Stopping attack...")
                    else:
                        print("[DDOS] No active DDoS attack.")
                case ["DDOS", target_ip_hex]:
                    target_ip = int(target_ip_hex, base=16)
                    Thread(target=self.ddos, args=(target_ip,), daemon=True).start()

                case ["SLOWLORIS", "STOP"]:
                    if (
                        self._slowloris_stop is not None
                        and not self._slowloris_stop.is_set()
                    ):
                        self._slowloris_stop.set()
                        print("[SLOWLORIS] Stopping attack...")
                    else:
                        print("[SLOWLORIS] No active Slowloris attack.")
                case ["SLOWLORIS", target_ip_hex]:
                    target_ip = int(target_ip_hex, base=16)
                    Thread(
                        target=self.slowloris, args=(target_ip,), daemon=True
                    ).start()

                case ["RDDOS", "STOP"]:
                    if self._rddos_stop is not None and not self._rddos_stop.is_set():
                        self._rddos_stop.set()
                        print("[RDDOS] Stopping attack...")
                    else:
                        print("[RDDOS] No active rotating DDoS attack.")
                case ["RDDOS", target_ip_hex]:
                    target_ip = int(target_ip_hex, base=16)
                    Thread(target=self.rddos, args=(target_ip,), daemon=True).start()

                case ["STATS"]:
                    print("\n=== TRAFFIC STATS ===")
                    with self._conn_lock:
                        self._cleanup_stale_connections()
                        total = len(self._conn_table)
                        half_open = sum(
                            1
                            for v in self._conn_table.values()
                            if v["state"] == "HALF_OPEN"
                        )
                        established = total - half_open
                        print(
                            f"Connections: {total}/{self._max_connections} used "
                            f"({half_open} HALF_OPEN, {established} ESTABLISHED)"
                        )
                        now = time.monotonic()
                        for ip, info in self._conn_table.items():
                            age = now - info["last_activity"]
                            print(
                                f"  0x{ip:02x}: {info['state']}  (last activity: {age:.1f}s ago)"
                            )
                    attacks = []
                    if self._ddos_stop is not None and not self._ddos_stop.is_set():
                        attacks.append("DDOS")
                    if (
                        self._slowloris_stop is not None
                        and not self._slowloris_stop.is_set()
                    ):
                        attacks.append("SLOWLORIS")
                    if self._rddos_stop is not None and not self._rddos_stop.is_set():
                        attacks.append("RDDOS")
                    print(
                        f"Active attacks: {', '.join(attacks) if attacks else 'none'}"
                    )
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
        self.ip_mapping[self.Ip] = self.Mac
        self.ip_handlers = []
        self._ddos_stop: Event | None = None
        self._mitm_mode = "passive"
        self._mitm_active = False
        self._slowloris_stop: Event | None = None
        self._rddos_stop: Event | None = None

        # Connection tracking (target for Slowloris)
        self._conn_table: dict[int, dict] = {}
        self._conn_lock = Lock()
        self._max_connections = 10
        self._conn_timeout = 10.0

        self._logger.info("connected to wire")

        if node_config.get("firewall", False):
            self.firewall: Firewall | None = Firewall(
                self._logger, default_policy=FirewallAction.ACCEPT
            )
            self._logger.info("Firewall enabled")
        else:
            self.firewall = None

        self._start_receiver()
        Thread(target=lambda: self.send_ARP_request(self.Ip), daemon=True).start()

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
