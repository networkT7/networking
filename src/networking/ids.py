import time
from collections import defaultdict
from threading import Lock
from logging import Logger

from networking.components.node import FrameHandler, Node
from networking.firewall import Firewall, FirewallRule, FirewallAction
from networking.frames import IPFrame
from networking.types import IPaddr, MACaddr, IPProtocol


# --- Tunable thresholds ---
RATE_WINDOW = 2.0  # seconds — sliding window for rate measurement
RATE_THRESHOLD = 15  # packets per window from a single src_ip → DDoS alert


class IDS:
    """
    Intrusion Detection System.

    Plug into any Node via .add_handler(ids.handler) in main.py.
    Detects:
      - DDoS:       a single src_ip sends >= RATE_THRESHOLD packets within RATE_WINDOW seconds
      - ARP Spoof:  a known ip→MAC mapping suddenly changes (MITM indicator)
      - IP Spoofing: DATA/PING frame src_ip arrives from a different MAC than first seen

    On detection, logs a CRITICAL alert. If the node has a firewall enabled,
    automatically inserts a DROP rule for the offending src_ip.
    """

    def __init__(self, logger: Logger, trusted_macs: set[MACaddr] | None = None):
        self._logger = logger
        self._pkt_times: dict[IPaddr, list[float]] = defaultdict(list)
        self._pkt_lock = Lock()
        self._arp_table: dict[IPaddr, MACaddr] = {}
        self._arp_lock = Lock()
        self._blocked: set[IPaddr] = set()
        self._blocked_lock = Lock()
        self._spoof_counts: dict[IPaddr, int] = defaultdict(int)
        self._spoof_lock = Lock()
        self._trusted_macs: set[MACaddr] = trusted_macs or set()
        self.handler = FrameHandler(
            lambda _node, _frame: True,
            self._inspect,
        )

    # ------------------------------------------------------------------
    # Main inspection entry point
    # ------------------------------------------------------------------

    def _inspect(self, node: Node, ip_frame: IPFrame, src_mac: MACaddr):
        self._logger.debug(
            f"[IDS] _inspect called: src_ip=0x{ip_frame.source:02x} src_mac={src_mac}"
        )  # ← temp
        self._check_arp_spoof(node, ip_frame, src_mac)
        self._check_ip_mac_consistency(node, ip_frame, src_mac)
        self._check_ddos(node, ip_frame)
        return ip_frame  # never consume — always pass to next handler

    # ------------------------------------------------------------------
    # Detection: DDoS
    # ------------------------------------------------------------------

    def _check_ddos(self, node: Node, ip_frame: IPFrame):
        """
        Sliding-window rate check.
        ARP traffic is excluded — only DATA and PING are counted.
        """
        if ip_frame.protocol == IPProtocol.ARP:
            return

        src = ip_frame.source
        now = time.monotonic()

        with self._pkt_lock:
            times = self._pkt_times[src]
            self._pkt_times[src] = [t for t in times if now - t < RATE_WINDOW]
            self._pkt_times[src].append(now)
            count = len(self._pkt_times[src])

        if count >= RATE_THRESHOLD:
            self._alert_ddos(node, src, count)

    def _alert_ddos(self, node: Node, src: IPaddr, count: int):
        self._logger.critical(
            f"[IDS] ⚠ DDoS DETECTED: src=0x{src:02x} sent {count} packets "
            f"in {RATE_WINDOW}s window on node {node.Mac}"
        )
        self._block(node, src, reason="DDoS")

    # ------------------------------------------------------------------
    # Detection: ARP Spoofing / MITM
    # ------------------------------------------------------------------

    def _check_arp_spoof(self, node: Node, ip_frame: IPFrame, src_mac: MACaddr):
        """
        ARP-specific spoof detection.
        First ARP from a src_ip seeds the trust table.
        Any subsequent ARP from the same src_ip with a different MAC is flagged.
        """
        if ip_frame.protocol != IPProtocol.ARP:
            return

        src_ip = ip_frame.source

        with self._arp_lock:
            known_mac = self._arp_table.get(src_ip)
            if known_mac is None:
                self._arp_table[src_ip] = src_mac
                self._logger.debug(f"[IDS] Learned ARP: 0x{src_ip:02x} → '{src_mac}'")
                return

            if known_mac != src_mac:
                with self._spoof_lock:
                    self._spoof_counts[src_ip] += 1
                    count = self._spoof_counts[src_ip]

                if count == 1 or count % 5 == 0:
                    self._logger.critical(
                        f"[IDS] ⚠ ARP SPOOF / MITM DETECTED on node {node.Mac}: "
                        f"IP 0x{src_ip:02x} was at MAC '{known_mac}', "
                        f"now claiming to be at MAC '{src_mac}' — possible MITM!"
                        + (f" (x{count})" if count > 1 else "")
                    )
                # self._block(node, src_ip, reason="ARP spoof")

    # ------------------------------------------------------------------
    # Detection: IP Spoofing (DATA / PING frames)
    # ------------------------------------------------------------------

    def _check_ip_mac_consistency(
        self, node: Node, ip_frame: IPFrame, src_mac: MACaddr
    ):
        """
        Detects forged src_ip in DATA/PING frames.
        First packet from a src_ip seeds the trust table.
        Later packets from the same src_ip but a different MAC are flagged.
        Crucially: does NOT update the table after a spoof — keeps the original
        trusted MAC so repeated spoofed packets keep triggering alerts.
        """
        if ip_frame.protocol == IPProtocol.ARP:
            return
        if src_mac in self._trusted_macs:
            return
        src_ip = ip_frame.source

        with self._arp_lock:
            known_mac = self._arp_table.get(src_ip)
            if known_mac is None:
                self._arp_table[src_ip] = src_mac
                self._logger.debug(
                    f"[IDS] Learned DATA/PING: 0x{src_ip:02x} → '{src_mac}'"
                )
                return

            if known_mac != src_mac:
                self._logger.critical(
                    f"[IDS] ⚠ IP SPOOFING DETECTED on node {node.Mac}: "
                    f"IP 0x{src_ip:02x} known from MAC '{known_mac}', "
                    f"but packet arrived from MAC '{src_mac}' — possible MITM/spoof!"
                )
                self._block(node, src_ip, reason="IP spoofing")

    # ------------------------------------------------------------------
    # Response: auto-block via firewall if available
    # ------------------------------------------------------------------

    def _block(self, node: Node, src: IPaddr, reason: str):
        """
        Insert a DROP rule for the offending src_ip. Fires once per src_ip.
        """
        with self._blocked_lock:
            if src in self._blocked:
                return
            self._blocked.add(src)

        if node.firewall is not None:
            rule = FirewallRule(
                src_ip=src,
                protocol=None,
                action=FirewallAction.DROP,
            )
            index = node.firewall.add_rule(rule)
            self._logger.critical(
                f"[IDS] 🛡 Auto-blocked 0x{src:02x} via firewall rule #{index} "
                f"(reason: {reason})"
            )

    def seed(self, ip: IPaddr, mac: MACaddr):
        """Pre-seed a trusted IP→MAC mapping (e.g. own address on startup)."""
        with self._arp_lock:
            if ip not in self._arp_table:
                self._arp_table[ip] = mac
                self._logger.debug(f"[IDS] Pre-seeded: 0x{ip:02x} → '{mac}'")
