from sys import argv, executable

from networking.config import config
from networking.components.node import Node
from networking.types import NodeConfig
from networking.components.wire import Wire


if len(argv) < 3:
    print(f"usage: {executable} {argv[0]} node|wire|router NAME")
    exit(1)

if argv[1] == "node":
    c: NodeConfig = config["nodes"][argv[2]]
    n = Node(c, int(config["wires"][c["wire"]])).input()

if argv[1] == "wire":
    Wire(int(config["wires"][argv[2]])).accept()
