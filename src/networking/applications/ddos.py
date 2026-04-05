from logging import Logger
from random import randint
from threading import Event, Thread
import time
from typing import Callable, Literal, override
from networking.components.node import Application, Node
from networking.types import IPProtocol, IPaddr

type AttackLiteral = Literal["DDOS", "SLOWLORIS", "RDDOS"]
_ATTACKS: list[AttackLiteral] = ["DDOS", "SLOWLORIS", "RDDOS"]


class DDOSApplication(Application):
    logger: Logger
    attack_events: dict[AttackLiteral, Event]
    attack_func: dict[AttackLiteral, Callable[[Node, int], None]]

    def __init__(self, node: Node) -> None:
        self.logger = node.logger
        self.attack_events = {k: Event() for k in _ATTACKS}
        self.attack_func = {
            "DDOS": self.ddos,
            "SLOWLORIS": self.slowloris,
            "RDDOS": self.rddos,
        }
        super().__init__()

    @override
    def handle_command(self, node: Node, *args: str):
        if args[0] == "stats":
            attacks = [k for (k, v) in self.attack_events.items() if not v.is_set()]
            print(f"Active attacks: {', '.join(attacks) if attacks else 'none'}")
            return

        attack, target = args
        if attack not in _ATTACKS:
            return

        e = self.attack_events[attack]
        if target == "STOP":
            if e.is_set():
                e.set()
                print(f"[{attack}] Stopping attack...")
            else:
                print(f"[{attack}] No active {attack} attack.")
        else:
            target_ip = int(target, base=16)
            f = self.attack_func[attack]
            Thread(target=f, args=(node, target_ip), daemon=True).start()

    def ddos(self, node: Node, target_ip: IPaddr):
        self.logger.warning(f"[DDOS] Starting DDoS on 0x{target_ip:02x}")

        e = self.attack_events["DDOS"]
        e.clear()

        total_sent = 0
        while True:
            if e.is_set():
                print(
                    f"\r[DDOS] Stopped. Total packets sent: {total_sent:<8}", flush=True
                )
                self.logger.warning("[DDOS] Stopped.")
                break

            fake_src = randint(0x01, 0xFE)

            node.send_IP_frame(
                target_ip,
                IPProtocol.DATA,
                b"flood",
                spoof_src=fake_src,
            )

            total_sent += 1
            print(
                f"\r[DDOS] Flooding 0x{target_ip:02x} | pkts: {total_sent:<6} | src: 0x{fake_src:02x} (random)",
                end="",
                flush=True,
            )
            time.sleep(0.01)  # controls speed (don’t remove)

    def slowloris(self, node: Node, target_ip: IPaddr):
        self.logger.warning(f"[SLOWLORIS] Starting Slowloris on 0x{target_ip:02x}")

        e = self.attack_events["SLOWLORIS"]
        e.clear()

        # Phase 1: Open connections with spoofed IPs
        # 12 IPs > max_connections (10), so last 2 get dropped — demonstrates exhaustion
        # Pool is offset by node IP so concurrent attackers don't share spoofed IPs
        # (shared IPs trigger the router's DAI and get dropped)
        base = (node.Ip & 0x0F) * 12
        pool = [(0x80 + base + i) & 0xFF for i in range(12)]  # 12 spoofed source IPs
        self.logger.warning(f"[SLOWLORIS] Phase 1: Opening {len(pool)} connections...")

        for i, spoofed_ip in enumerate(pool):
            if e.is_set():
                self.logger.warning("[SLOWLORIS] Stopped during Phase 1.")
                return

            node.send_IP_frame(target_ip, IPProtocol.TCP, b"SYN", spoof_src=spoofed_ip)
            self.logger.warning(f"[SLOWLORIS] Phase 1: SYN sent ({i + 1}/{len(pool)})")
            time.sleep(0.2)

        # Phase 2: Hold connections open with keepalives
        # Cycle must complete within _conn_timeout (10s).
        # 12 IPs x 0.5s = 6s per cycle — safely under 10s timeout.
        keepalive_sleep = 0.5
        cycle_time = len(pool) * keepalive_sleep
        self.logger.warning(
            "[SLOWLORIS] Phase 2: Holding connections, "
            + f"cycle every {cycle_time:.0f}s, ~{1 / keepalive_sleep:.0f} pps"
        )

        cycle_count = 0
        while not e.is_set():
            for spoofed_ip in pool:
                if e.is_set():
                    break
                node.send_IP_frame(
                    target_ip, IPProtocol.TCP, b"KEEPALIVE", spoof_src=spoofed_ip
                )
                time.sleep(keepalive_sleep)

            cycle_count += 1
            self.logger.warning(
                f"[SLOWLORIS] Status: keepalive cycle {cycle_count} complete "
                + f"({len(pool)} connections maintained)"
            )

        self.logger.warning("[SLOWLORIS] Stopped.")

    def rddos(self, node: Node, target_ip: IPaddr):
        self.logger.warning(
            f"[RDDOS] Starting rotating source DDoS on 0x{target_ip:02x}"
        )

        e = self.attack_events["SLOWLORIS"]
        e.clear()

        pool = list(range(0xC0, 0xD4))  # 20 spoofed source IPs
        self.logger.warning(
            f"[RDDOS] Using {len(pool)} rotating sources, "
            + f"~{1000 / 5:.0f} pps aggregate, "
            + f"~{1000 / (5 * len(pool)):.0f} pps per source"
        )

        total_sent = 0
        idx = 0

        while not e.is_set():
            spoofed_ip = pool[idx % len(pool)]
            node.send_IP_frame(
                target_ip, IPProtocol.DATA, b"flood", spoof_src=spoofed_ip
            )
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
        self.logger.warning(f"[RDDOS] Stopped. Total packets sent: {total_sent}")
