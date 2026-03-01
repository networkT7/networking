from sys import argv, executable

from networking.config import config
from networking.components.node import Node
from networking.components.wire import Wire
from networking.components.router import Router
from networking.types import NodeConfig


def usage():
    print(f"Usage:")
    print(f"  {executable} {argv[0]} wire <WIRE_NAME>")
    print(f"  {executable} {argv[0]} node <NODE_NAME>")
    print(f"  {executable} {argv[0]} router")
    exit(1)


if len(argv) < 2:
    usage()

mode = argv[1]

if mode == "wire":
    if len(argv) != 3:
        usage()

    wire_name = argv[2]

    if wire_name not in config["wires"]:
        print(f"Unknown wire: {wire_name}")
        exit(1)

    port = int(config["wires"][wire_name])
    Wire(port).accept()

elif mode == "node":
    if len(argv) != 3:
        usage()

    node_name = argv[2]

    if node_name not in config["nodes"]:
        print(f"Unknown node: {node_name}")
        exit(1)

    c: NodeConfig = config["nodes"][node_name]
    port = int(config["wires"][c["wire"]])

    Node(c, port).input()

elif mode == "router":
    Router(config["nodes"], config["wires"])
    input("Router running... Press Enter to exit.\n")

else:
    usage()