from scapy.all import Ether, IP, ICMP, RandMAC, RandIP, get_if_hwaddr, get_if_addr
from os import urandom
from random import randint
import re

from .helpers import requires, add_vlan, validate_cos, logger


def icmp_packet(fuzzy, module, icmp_type, icmp_inputs):
    final_packet = None
    if icmp_type == 'req':
        pkt_type = 'echo-request'
    elif icmp_type == 'reply':
        pkt_type = 'echo-reply'
    else:
        logger.critical(
            "Invalid icmp_type: '{}' Expected value (req/reply)".format(
                icmp_type))
        return None
    if fuzzy == 'y':
        if module != None:
            if module == 'VXLAN' or module == 'MPLS':
                src_mac, dst_mac = RandMAC()._fix(), RandMAC()._fix()
                src_ip, dst_ip = RandIP("172.16.0.0/12")._fix(), RandIP("172.16.0.0/12")._fix()
                ttl = randint(10, 255)
            elif module == 'ICMP':
                src_mac, dst_mac = get_if_hwaddr(icmp_inputs[1]), RandMAC()._fix()
                src_ip, dst_ip = get_if_addr(icmp_inputs[1]), RandIP("172.16.0.0/12")._fix()
                ip_pattern = re.compile(r'^0\.0\.0\.0$')
                if ip_pattern.match(src_ip):
                    src_ip = RandIP("172.16.0.0/12")._fix()
                ttl = randint(10, 255)
            else:
                return None
        else:
            return None
    elif fuzzy == 'n':
        if module != None and len(icmp_inputs) != 0:
            if module == 'VXLAN' or module == 'MPLS':
                src_mac, dst_mac = icmp_inputs[0], icmp_inputs[1]
                src_ip, dst_ip = icmp_inputs[2], icmp_inputs[3]
                ttl = int(icmp_inputs[4])
            elif module == 'ICMP':
                dst_mac = icmp_inputs[1]
                dst_ip = icmp_inputs[3]
                mac_pattern = re.compile(
                    r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
                ip_pattern = re.compile(
                    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
                )
                ip_pattern_2 = re.compile(r'^0\.0\.0\.0$')
                if mac_pattern.match(icmp_inputs[0].strip()):
                    src_mac = icmp_inputs[0]
                else:
                    logger.error(
                        "Invalid source MAC provided. Extracting source MAC from source interface.",
                    )
                    src_mac = get_if_hwaddr(icmp_inputs[7])
                if not ip_pattern.match(icmp_inputs[2]):
                    logger.error(
                        "Invalid source IP provided. Extracting source IP from source interface.",
                    )
                    src_ip = get_if_addr(icmp_inputs[7])
                    if ip_pattern_2.match(src_ip):
                        logger.critical(
                            "Source interface does not have a valid IP address")
                        return None
                else:
                    src_ip = icmp_inputs[2]
                ttl = int(icmp_inputs[4])
        else:
            return None
    random_data = urandom(64)
    random_id = randint(1, 2000)
    final_packet = Ether(src=src_mac, dst=dst_mac) / IP(
        src=src_ip, dst=dst_ip, ttl=ttl) / ICMP(
            id=random_id, type=pkt_type) / Raw(load=random_data)
    return final_packet


def build_icmp():
    icmp_pkt = None
    input_param, common_param = requires("ICMP")
    fuzzy = (input("Random ICMP Packet? (y/n) > ").strip()).lower()
    if fuzzy == "y":
        icmp_type = (input("ICMP Type (req/reply) > ").strip()).lower()
        inputs = []
        for i in range(0, len(common_param)):
            inputs.insert(i, input("{} > ".format(common_param[i])))
        icmp_pkt = icmp_packet(fuzzy, 'ICMP', icmp_type, inputs)
        if icmp_pkt != None:
            logger.info("ICMP packet built")
            icmp_pkt.show()
            return icmp_pkt, inputs[0], inputs[1]
        else:
            return None
    elif fuzzy == "n":
        icmp_type = (input("ICMP Type (req/reply) > ").strip()).lower()
        inputs = []
        dot1q_prio = []
        for i in range(0, len(input_param)):
            temp_input = input("{} > ".format(input_param[i]))
            if "Tag" in input_param[i] and temp_input.lower() == "y":
                inputs.insert(i, input("VLAN Tag (x,y) > "))
                dot1q_prio.insert(0, input("CoS (x,y | default 0) > "))
            elif "Tag" in input_param[i] and temp_input.lower() == "n":
                inputs.insert(i, False)
            elif "Tag" not in input_param[i]:
                inputs.insert(i, temp_input)
            else:
                logger.critical(
                    "Invalid choice, got '{}' expected values (y/n)".format(
                        temp_input))
                return None
        for j in range(0, len(common_param)):
            i = i + 1
            inputs.insert(i, input("{} > ".format(common_param[j])))
        if not (inputs[5]):
            icmp_pkt = icmp_packet(fuzzy, 'ICMP', icmp_type, inputs)
        else:
            vlans = (inputs[5]).strip().split(",")
            cos = (dot1q_prio[0]).strip().split(",")
            try:
                vlans = [int(i) for i in vlans]
            except ValueError:
                logger.critical(
                    "Invalid vlan id'{}' Expected integer".format(vlans))
                logger.critical(ValueError, exc_info=True)
                return None
            icmp_pkt = icmp_packet(fuzzy, 'ICMP', icmp_type, inputs)
            cos = validate_cos(cos, vlans)
            if icmp_pkt != None and cos != None:
                icmp_pkt = add_vlan(icmp_pkt, vlans, cos)
            else:
                return None
        if icmp_pkt != None:
            logger.info("ICMP Packet built")
            icmp_pkt.show()
            return icmp_pkt, inputs[6], inputs[7]
        else:
            return None
    else:
        logger.critical(
            "Invalid input '{}' Expected string (y/n)".format(fuzzy))
        return None
