from sys import argv, executable

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

        Node(c, wire).input()

    case [_, "router"]:
        Router(config["routers"], config["nodes"], config["wires"])
        input("Router running... Press Enter to exit.\n")

    case _:
        usage()
