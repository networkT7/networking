from networking.components.node import FrameHandler, Node
from networking.constants import BYTE_ENCODING_TYPE
from networking.frames import IPFrame
from networking.types import FragmentId, IPProtocol, IPaddr, MACaddr, PayloadType


class IPFragmentHandler(FrameHandler):
    fragments: dict[tuple[FragmentId, IPaddr, IPaddr, IPProtocol], IPFrame]

    def __init__(self):
        self.fragments = {}
        super().__init__(lambda _, frame: frame.is_fragmented, self.on_request)

    def on_request(self, _node: Node, frame: IPFrame, _mac: MACaddr):
        key = (frame.fragment_id, frame.source, frame.destination, frame.protocol)
        frag = self.fragments.pop(key, None)
        if frag:
            return IPFrame.defragment_frame([frag, frame])
        else:
            self.fragments[key] = frame


class ARPHandler(FrameHandler):
    def __init__(self):
        super().__init__(
            lambda node, f: f.protocol == IPProtocol.ARP and node.Ip == f.destination,
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, src_mac: MACaddr):
        src = frame.source
        node.save_IP_mapping(src, src_mac)
        try:
            payload = PayloadType(frame.data)
            match payload:
                case PayloadType.REQ:
                    node.logger.debug(f"ARP request received from 0x{src:02x}")
                    node.send_ARP_response(src_mac, node.Ip, src)
                case PayloadType.RES:
                    node.logger.debug(f"ARP response received from 0x{src:02x}")
        except ValueError:
            pass


class PingHandler(FrameHandler):
    def __init__(self):
        super().__init__(
            lambda node, f: f.protocol == IPProtocol.PING and node.Ip == f.destination,
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, _: MACaddr):
        src = frame.source
        try:
            payload = PayloadType(frame.data)
            match payload:
                case PayloadType.REQ:
                    node.logger.info(f"Ping request received from 0x{src:02x}")
                    node.send_IP_frame(src, IPProtocol.PING, PayloadType.RES)
                case PayloadType.RES:
                    node.logger.info(f"Ping reply received from 0x{src:02x}")
        except ValueError:
            pass


class DataHandler(FrameHandler):
    def __init__(self):
        super().__init__(
            lambda node, f: f.protocol == IPProtocol.DATA and node.Ip == f.destination,
            self.on_request,
        )

    @staticmethod
    def on_request(node: Node, frame: IPFrame, _: MACaddr):
        node.logger.info(
            f"[DATA] Message from 0x{frame.source:02x}: {frame.data.decode(BYTE_ENCODING_TYPE)}"
        )
