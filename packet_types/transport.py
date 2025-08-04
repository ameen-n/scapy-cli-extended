from os import urandom
from random import randint
import re

from scapy.all import (
    Ether,
    IP,
    UDP,
    TCP,
    RandMAC,
    RandIP,
    RandShort,
    get_if_hwaddr,
    get_if_addr,
    Raw,
)

from .helpers import convert_multicast_ip_to_mac, logger


def udp_packet(fuzzy, module, udp_inputs):
    final_packet = None
    if fuzzy == 'y':
        if module != None:
            if module == 'VXLAN' or module == 'MPLS':
                src_mac, dst_mac = RandMAC()._fix(), RandMAC()._fix()
                src_ip, dst_ip = RandIP("172.16.0.0/12")._fix(), RandIP("172.16.0.0/12")._fix()
                udp_dport = udp_sport = randint(49152, 65535)
            elif module == 'MCAST':
                src_mac, src_ip = get_if_hwaddr(udp_inputs[1]), get_if_addr(udp_inputs[1])
                ip_pattern = re.compile(r'^0\.0\.0\.0$')
                if ip_pattern.match(src_ip):
                    src_ip = RandIP("172.16.0.0/12")._fix()
                dst_ip = RandIP("239.0.0.0/8")._fix()
                dst_mac = convert_multicast_ip_to_mac(dst_ip)
                udp_dport = udp_sport = randint(49152, 65535)
        else:
            return None
    elif fuzzy == 'n':
        if module != None and len(udp_inputs) != 0:
            if module == 'VXLAN' or module == 'MPLS':
                src_mac, dst_mac = udp_inputs[0], udp_inputs[1]
                src_ip, dst_ip = udp_inputs[2], udp_inputs[3]
                udp_sport, udp_dport = int(udp_inputs[4]), int(udp_inputs[5])
            elif module == 'MCAST':
                mac_pattern = re.compile(
                    r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
                ip_pattern = re.compile(
                    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
                ip_pattern_2 = re.compile(r'^0\.0\.0\.0$')
                if mac_pattern.match(udp_inputs[0].strip()):
                    src_mac = udp_inputs[0]
                else:
                    src_mac = get_if_hwaddr(udp_inputs[7])
                if not ip_pattern.match(udp_inputs[1].strip()):
                    logger.error(
                        "Invalid source IP provided. Extracting source IP from source interface.")
                    src_ip = get_if_addr(udp_inputs[7])
                    if ip_pattern_2.match(src_ip):
                        logger.critical(
                            "Source interface does not have a valid IP address")
                        return None
                else:
                    src_ip = udp_inputs[1]
                if not ip_pattern.match(udp_inputs[2]):
                    logger.error("Invalid destination IP provided.")
                    return None
                else:
                    dst_ip = udp_inputs[2]
                dst_mac = convert_multicast_ip_to_mac(dst_ip)
                try:
                    if udp_inputs[4] and udp_inputs[3]:
                        udp_dport, udp_sport = int(udp_inputs[4]), int(udp_inputs[3])
                except ValueError:
                    logger.critical(
                        "Invalid udp_sport: '{}' and udp_dport: '{}' provided")
                    return None
        else:
            return None
    random_data = urandom(64)
    final_packet = Ether(src=src_mac, dst=dst_mac) / IP(
        src=src_ip, dst=dst_ip, ttl=randint(10, 255)) / UDP(
            sport=udp_sport, dport=udp_dport) / Raw(load=random_data)
    return final_packet


def tcp_packet(fuzzy, module, tcp_inputs):
    final_packet = None
    if fuzzy == 'y':
        if module != None:
            if module == 'VXLAN' or module == 'MPLS':
                src_mac, dst_mac = RandMAC()._fix(), RandMAC()._fix()
                src_ip, dst_ip = RandIP("172.16.0.0/12")._fix(), RandIP("172.16.0.0/12")._fix()
                tcp_sport, tcp_dport = RandShort()._fix(), RandShort()
        else:
            return None
    elif fuzzy == 'n':
        if module != None and len(tcp_inputs) != 0:
            if module == 'VXLAN' or module == 'MPLS':
                src_mac, dst_mac = tcp_inputs[0], tcp_inputs[1]
                src_ip, dst_ip = tcp_inputs[2], tcp_inputs[3]
                tcp_sport, tcp_dport = int(tcp_inputs[4]), int(tcp_inputs[5])
        else:
            return None
    final_packet = Ether(src=src_mac, dst=dst_mac) / IP(
        src=src_ip, dst=dst_ip, ttl=randint(10, 255)) / TCP(
            sport=tcp_sport, dport=tcp_dport, flags='S')
    return final_packet

