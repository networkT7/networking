import socket

from networking.protocol import IPaddr


class Router:
    __routing_table: dict[IPaddr, socket.SocketType]
