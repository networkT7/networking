from networking.node import Node

print(bytes(Node("hi", "1").send_MAC_frame("yo", "hello thereee")))
