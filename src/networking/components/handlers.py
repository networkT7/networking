from networking.components.node import FrameHandlerClass, Node
from networking.constants import BYTE_ENCODING_TYPE
from networking.frames import IPFrame
from networking.types import IPProtocol, MACaddr


class ARPRequestHandler(FrameHandlerClass):
    def __init__(self):
        super().__init__(
            lambda node, f: (
                f.protocol == IPProtocol.ARP
                and f.data == b"req"
                and node.Ip == f.destination
            ),
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, src_mac: MACaddr):
        src = frame.source
        node._logger.debug(f"ARP request received from 0x{src:02x}")
        node.save_IP_mapping(src, src_mac)
        node.send_ARP_response(src_mac, node.Ip, src)
        return True


class ARPResponseHandler(FrameHandlerClass):
    def __init__(self):
        super().__init__(
            lambda node, f: (
                f.protocol == IPProtocol.ARP
                and f.data == b"res"
                and node.Ip == f.destination
            ),
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, src_mac: MACaddr):
        src = frame.source
        node._logger.debug(f"ARP response received from 0x{src:02x}")
        node.save_IP_mapping(src, src_mac)
        return True

class PingRequestHandler(FrameHandlerClass):
    def __init__(self):
        super().__init__(
            lambda node, f: (
                f.protocol == IPProtocol.PING
                and f.data == b"req"
                and node.Ip == f.destination
            ),
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, _: MACaddr):
        src = frame.source
        node._logger.info(f"Ping request received from 0x{src:02x}")
        node.send_IP_frame(src, IPProtocol.PING, b"res")
        return True


class PingResponseHandler(FrameHandlerClass):
    def __init__(self):
        super().__init__(
            lambda node, f: (
                f.protocol == IPProtocol.PING
                and f.data == b"res"
                and node.Ip == f.destination
            ),
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, _: MACaddr):
        node._logger.info(f"Ping reply received from 0x{frame.source:02x}")
        return True


class DataHandler(FrameHandlerClass):
    def __init__(self):
        super().__init__(
            lambda node, f: f.protocol == IPProtocol.DATA and node.Ip == f.destination,
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, _: MACaddr):
        node._logger.info(
            f"[DATA] Message from 0x{frame.source:02x}: {frame.data.decode(BYTE_ENCODING_TYPE)}"
        )
        return True
