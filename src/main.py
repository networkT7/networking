from sys import argv, executable

from networking.applications.ddos import DDOSApplication
from networking.applications.mitm import MITMApplication
from networking.applications.tcp import TCPApplication
from networking.components.handlers import (
    ARPHandler,
    DataHandler,
    IPFragmentHandler,
    PingHandler,
)
from networking.config import config
from networking.components.node import Node
from networking.components.wire import Wire
from networking.components.router import Router


def usage():
    print("Usage:")
    print(f"  {executable} {argv[0]} wire <WIRE_NAME>")
    print(f"  {executable} {argv[0]} node <NODE_NAME>")
    print(f"  {executable} {argv[0]} router")
    exit(1)


if len(argv) < 2:
    usage()

match argv:
    case [_, "wire", wire_name]:
        if len(argv) != 3:
            usage()

        if wire_name not in config["wires"]:
            print(f"Unknown wire: {wire_name}")
            exit(1)

        port = int(config["wires"][wire_name]["port"])
        Wire(port).accept()

    case [_, "node", node_name]:
        if len(argv) != 3:
            usage()

        if node_name not in config["nodes"]:
            print(f"Unknown node: {node_name}")
            exit(1)

        c = config["nodes"][node_name]
        wire = config["wires"][c["wire"]]

        from networking.ids import IDS
        from networking.log_format import create_logger
        from networking.config import LOGGING_LEVEL
        router_macs = {
            iface["MAC"] for iface in config["routers"]["interfaces"].values()
        }

        ids = IDS(
            create_logger(f"IDS-{node_name}", level=LOGGING_LEVEL),
            trusted_macs=router_macs,
        )
        ids.seed(c["IP"], c["MAC"])

        n = Node(c, wire)
        (
            n.add_handler(ids.handler)
            .add_handler(IPFragmentHandler())
            .add_handler(ARPHandler())
            .add_handler(PingHandler())
            .add_handler(DataHandler())
            .add_application(MITMApplication(n))
            .add_application(TCPApplication(n))
            .add_application(DDOSApplication(n))
            .input()
        )

    case [_, "router"]:
        Router(config["routers"], config["wires"])
        
    case _:
        usage()
