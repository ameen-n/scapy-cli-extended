from scapy.all import Dot1Q, Ether, NoPayload
import sys
import logging

class MyFormatter(logging.Formatter):
    err_fmt = "%(asctime)s: %(levelname)s: %(message)s, at line %(lineno)d, in %(funcName)s()"
    crit_fmt = "%(asctime)s: %(levelname)s: %(message)s, at line %(lineno)d, in %(funcName)s()"
    info_fmt = "%(asctime)s: %(levelname)s: %(message)s"

    def __init__(self):
        super().__init__(fmt="%(levelno)d: %(msg)s", datefmt=None, style='%')

    def format(self, record):
        format_orig = self._style._fmt
        if record.levelno == logging.CRITICAL:
            self._style._fmt = MyFormatter.crit_fmt
        elif record.levelno == logging.INFO:
            self._style._fmt = MyFormatter.info_fmt
        elif record.levelno == logging.ERROR:
            self._style._fmt = MyFormatter.err_fmt
        result = logging.Formatter.format(self, record)
        self._style._fmt = format_orig
        return result

fmt = MyFormatter()
hdlr = logging.StreamHandler(sys.stdout)
hdlr.setFormatter(fmt)
logging.root.addHandler(hdlr)
logging.root.setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)

def requires(module):
    req_arr = {
        "ICMP": [
            "Source MAC (de:ad:be:ef:ca:fe)", "Destination MAC", "Source IP",
            "Destination IP", "TTL", "Tag (y/n)"
        ],
        "ARP": [
            "Source MAC (de:ad:be:ef:ca:fe)", "Destination MAC", "Sender MAC",
            "Sender IP", "Target MAC", "Target IP", "Tag (y/n)"
        ],
        "IGMP": [
            "Sender MAC (de:ad:be:ef:ca:fe)", "Sender IP", "Multicast Address",
            "Source Address", "Tag (y/n)"
        ],
        "PCAP": [
            "Source MAC (de:ad:be:ef:ca:fe)", "Destination MAC", "Source IP",
            "Destination IP"
        ],
        "MCAST": [
            "Source MAC (de:ad:be:ef:ca:fe)", "Source IP", "Destination IP",
            "UDP Source Port", "UDP Destination Port", "Tag (y/n)"
        ],
        "UDP": [
            "Source MAC (de:ad:be:ef:ca:fe)", "Destination MAC", "Source IP",
            "Destination IP", "UDP Source Port", "UDP Destination Port",
            "Tag (y/n)"
        ],
        "TCP": [
            "Source MAC (de:ad:be:ef:ca:fe)", "Destination MAC", "Source IP",
            "Destination IP", "TCP Source Port", "TCP Destination Port",
            "Tag (y/n)"
        ],
        "VXLAN": [
            "Outer Source MAC (de:ad:be:af:ca:fe)", "Outer Destination MAC",
            "Outer Source IP", "Outer Destination IP", "Outer UDP Source Port",
            "Outer UDP Destination Port (default 4789)", "VNI"
        ],
        "LLFC": [
            "Source MAC (de:ad:be:ef:ca:fe)", "Time in Quanta (0-65535)"
        ],
        "PFC": [
            "Source MAC (de:ad:be:ef:ca:fe)", "Enable Pause for Class (C0-C7)",
            "Time in Quanta for Class (0-65535)"
        ],
        "MPLS": [
            "Outer Source MAC (de:ad:be:af:ca:fe)", "Outer Destination MAC",
            "Labels in comma delimited form (Top to Bottom)", "Control Word (y/n)"
        ],
        "common": ["Count (c for continous)", "Source Interface"]
    }
    return req_arr[module], req_arr["common"]


def add_dot1q(vlan_list, cos_list, layer):
    if (len(vlan_list) == 1):
        dot1q = Dot1Q(vlan=vlan_list[0], prio=cos_list[0])
        vlan_list.pop(0)
        cos_list.pop(0)
        dot1q.add_payload(layer.payload)
        return dot1q
    else:
        dot1q = Dot1Q(vlan=vlan_list[0], prio=cos_list[0], type=33024)
        vlan_list.pop(0)
        cos_list.pop(0)
        dot1q.add_payload(add_dot1q(vlan_list, cos_list, layer))
        return dot1q


def add_vlan(packet, vlans, cos):
    layer = packet.firstlayer()
    while not isinstance(layer, NoPayload):
        if 'chksum' in layer.default_fields:
            del layer.chksum
        if (type(layer) is Ether):
            layer.type = 33024
            dot1q = add_dot1q(vlans, cos, layer)
            layer.remove_payload()
            layer.add_payload(dot1q)
            layer = dot1q
        layer = layer.payload
    return packet


def validate_cos(cos, vlans):
    if len(cos) > len(vlans):
        logger.critical("Mismatched CoS and vlans input")
        return None
    elif len(cos) <= len(vlans):
        if len(cos) == 1 and cos[0] == "":
            _ = cos.pop(0)
        cos.extend([0] * (len(vlans) - len(cos)))
        try:
            cos = [int(i) for i in cos]
        except ValueError:
            logger.critical("Invalid CoS id'{}' Expected integer".format(cos))
            logger.critical(ValueError, exc_info=True)
            return None
        if (any((i > 7) or (i < 0) for i in cos)):
            logger.critical(
                "Invalid CoS values'{}' Expected value between 0 and 7".format(cos))
            return None
        else:
            return cos
