from threading import Thread
import time
from typing import override
from networking.components.node import Application, FrameHandler, Node
from networking.constants import BYTE_ENCODING_TYPE
from networking.frames import IPFrame
from networking.types import IPProtocol, IPaddr, MACaddr, PayloadType


class MITMHandler(FrameHandler):
    """
    Intercepts packets from victim ONLY when MITM is active,
    logs them, then forwards them to the real destination.
    """

    app: MITMApplication

    def __init__(self, app: MITMApplication):
        self.app = app

        def predicate(_node: Node, _ip_frame: IPFrame) -> bool:
            if _ip_frame.protocol == IPProtocol.ARP:
                return False

            if not app.victim_router_pair:
                return False

            condition = any(
                ip in app.victim_router_pair
                for ip in (_ip_frame.source, _ip_frame.destination)
            )
            return condition

        def handler(node: Node, ip_frame: IPFrame, _: MACaddr):
            original_data = ip_frame.data

            node.logger.warning(
                "[MITM] Intercepted packet: "
                + f"src=0x{ip_frame.source:02x} dst=0x{ip_frame.destination:02x} "
                + f"proto={IPProtocol(ip_frame.protocol).name} data={original_data}"
            )

            decoded = original_data.decode(BYTE_ENCODING_TYPE)

            print("\n=== MITM INTERCEPT ===")
            print(f"Original message: {decoded}")
            print("Options:")
            print("  [1] Forward unchanged")
            print("  [2] Modify message")
            print("  [3] Drop packet")
            print("\n⚠️  Press ENTER before typing your choice", flush=True)
            choice = input("Select option: ").strip()

            match choice:
                case "2":
                    print("\n⚠️  Press ENTER before typing modified message", flush=True)
                    new_msg = input("Enter modified message: ")
                    modified = new_msg.encode("utf-8")

                case "3":
                    print("[MITM] Packet dropped.")
                    return

                case _:
                    modified = original_data

            node.send_IP_frame(
                ip_frame.destination,
                ip_frame.protocol,
                modified,
                spoof_src=ip_frame.source,
            )

            node.logger.warning(f"[MITM] Forwarded → {modified}")

        super().__init__(predicate, handler)


class MITMApplication(Application):
    victim_router_pair: tuple[IPaddr, IPaddr] | None

    def __init__(self, node: Node) -> None:
        self.victim_router_pair = None
        _ = node.add_handler(MITMHandler(self))

    @override
    def handle_command(self, node: Node, *args: str):
        match args:
            case ("stop",):
                if not self.victim_router_pair:
                    return
                victim_ip, router_ip = self.victim_router_pair
                self.victim_router_pair = None

                victim_mac = node.resolve_IP(victim_ip)
                router_mac = node.resolve_IP(router_ip)

                node.send_IP_frame(
                    router_ip,
                    IPProtocol.ARP,
                    PayloadType.RES,
                    spoofed_mac=victim_mac,
                    spoof_src=victim_ip,
                )
                node.send_IP_frame(
                    victim_ip,
                    IPProtocol.ARP,
                    PayloadType.RES,
                    spoofed_mac=router_mac,
                    spoof_src=router_ip,
                )
            case (victim_ip_hex, router_ip_hex):
                victim_ip = int(victim_ip_hex, base=16)
                router_ip = int(router_ip_hex, base=16)

                self.victim_router_pair = (victim_ip, router_ip)
                Thread(target=self.poison_loop, args=(node,), daemon=True).start()
                node.logger.warning(f"[MITM] Attack started against 0x{victim_ip:02x}")
            case _:
                pass

    def poison_loop(self, node: Node):
        if not self.victim_router_pair:
            return
        victim_ip, router_ip = self.victim_router_pair
        victim_mac = node.resolve_IP(victim_ip)
        router_mac = node.resolve_IP(router_ip)

        while self.victim_router_pair:
            node.send_ARP_response(victim_mac, router_ip, victim_ip)
            node.send_ARP_response(router_mac, victim_ip, router_ip)
            time.sleep(2)
