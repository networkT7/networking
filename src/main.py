from sys import argv, executable

from networking.components.handlers import (
    ARPRequestHandler,
    ARPResponseHandler,
    DataHandler,
    PingRequestHandler,
    PingResponseHandler,
    TCPConnectionHandler,
    TCPConnectResponseHandler,  # ← [CONNECT]
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
        ids = IDS(create_logger(f"IDS-{node_name}", level=LOGGING_LEVEL))
        ids.seed(c["IP"], c["MAC"])

        (
            Node(c, wire)
            .add_handler(ids.handler)
            .add_handler(ARPRequestHandler())
            .add_handler(ARPResponseHandler())
            .add_handler(PingRequestHandler())
            .add_handler(PingResponseHandler())
            .add_handler(TCPConnectResponseHandler())  # ← [CONNECT] before TCPConnectionHandler so SYN-ACK/RST are caught first
            .add_handler(TCPConnectionHandler())
            .add_handler(DataHandler())
            .input()
        )

    case [_, "router"]:
        Router(config["routers"], config["wires"])
        input("Router running... Press Enter to exit.\n")

    case _:
        usage()
