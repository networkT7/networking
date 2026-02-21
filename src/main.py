from sys import argv, executable
from yaml import load, Loader

from networking.node import Node
from networking.protocol import NodeConfig
from networking.wire import Wire

with open("config.yaml") as f:
    config = load(f.read(), Loader)

if len(argv) < 3:
    print(f"usage: {executable} {argv[0]} node|wire|router NAME")
    exit(1)

if argv[1] == "node":
    c: NodeConfig = config["nodes"][argv[2]]
    n = Node(c, int(config["wires"][c["wire"]]))

    while True:
        data = input("Enter your message: ")
        idx = data.find(" ")
        n.send_MAC_frame(data[:idx], data[idx+1:])

if argv[1] == "wire":
    Wire(int(config["wires"][argv[2]])).accept()
