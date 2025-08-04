import re
from random import randint

from scapy.all import Ether, IP, UDP, VXLAN, RandMAC, RandIP, get_if_hwaddr

from .helpers import requires, logger
from .icmp import icmp_packet
from .arp import arp_packet
from .transport import udp_packet, tcp_packet


def vxlan_packet(fuzzy, inner_pkt, vxlan_inputs):
    final_pkt = None
    if fuzzy == 'y':
        if inner_pkt != None and len(vxlan_inputs) != 0:
            outer_dst_mac, outer_src_mac = RandMAC()._fix(), get_if_hwaddr(vxlan_inputs[1])
            outer_src_ip, outer_dst_ip = RandIP("192.168.0.0/12")._fix(), RandIP("192.168.0.0/12")._fix()
            outer_src_port, outer_dst_port = randint(49152, 65535), 4789
            vni = randint(1, 16777215)
        else:
            return None
    elif fuzzy == 'n':
        if inner_pkt != None and len(vxlan_inputs) != 0:
            outer_dst_mac = vxlan_inputs[1]
            mac_pattern = re.compile(
                r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
            if mac_pattern.match(vxlan_inputs[0].strip()):
                outer_src_mac = vxlan_inputs[0]
            else:
                outer_src_mac = get_if_hwaddr(vxlan_inputs[8])
            outer_src_ip = vxlan_inputs[2]
            ip_pattern = re.compile(
                r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
            if not ip_pattern.match(outer_src_ip):
                outer_src_ip = RandIP("192.168.0.0/12")._fix()
            outer_dst_ip = vxlan_inputs[3]
            outer_src_port, outer_dst_port = int(vxlan_inputs[4]), int(vxlan_inputs[5])
            vni = int(vxlan_inputs[6])
        else:
            return None
    final_pkt = Ether(src=outer_src_mac, dst=outer_dst_mac) / IP(
        flags='DF', src=outer_src_ip, dst=outer_dst_ip, ttl=randint(
            10, 255)) / UDP(sport=outer_src_port, dport=outer_dst_port) / VXLAN(
                vni=vni, flags=8) / inner_pkt
    return final_pkt


def build_vxlan(msg_type):
    if msg_type == 'VXLAN_ICMP':
        vxlan_input_param, common_param = requires("VXLAN")
        icmp_input_param, _ = requires('ICMP')
        inner_icmp_pkt, vxlan_icmp_pkt = None, None
        fuzzy = (input("Generate random Vxlan ICMP Packet? (y/n) > ").strip()).lower()
        if fuzzy == 'y':
            icmp_type = (input("ICMP Type (req/reply) > ").strip()).lower()
            inputs = []
            for i in range(0, len(common_param)):
                inputs.insert(i, input("{} > ".format(common_param[i])))
            inner_icmp_pkt = icmp_packet(fuzzy, 'VXLAN', icmp_type, inputs)
            vxlan_icmp_pkt = vxlan_packet(fuzzy, inner_icmp_pkt, inputs)
            if inner_icmp_pkt != None and vxlan_icmp_pkt != None:
                logger.info("Inner ICMP packet built")
                logger.info("Vxlan ICMP Packet built")
                vxlan_icmp_pkt.show()
                return vxlan_icmp_pkt, inputs[0], inputs[1]
            else:
                return None
        elif fuzzy == 'n':
            icmp_type = (input("ICMP Type (req/reply) > ").strip()).lower()
            inputs = []
            del icmp_input_param[-1]
            for i in range(0, len(icmp_input_param)):
                temp_input = input("Inner {} > ".format(icmp_input_param[i]))
                inputs.insert(i, temp_input)
            inner_icmp_pkt = icmp_packet(fuzzy, 'VXLAN', icmp_type, inputs)
            vxlan_inputs = []
            for i in range(0, len(vxlan_input_param)):
                temp_input = input("{} > ".format(vxlan_input_param[i]))
                if "4789" in vxlan_input_param[i] and temp_input != True:
                    temp_input = '4789'
                vxlan_inputs.insert(i, temp_input)
            for j in range(0, len(common_param)):
                i = i + 1
                vxlan_inputs.insert(i, input("{} > ".format(common_param[j])))
            vxlan_icmp_pkt = vxlan_packet(fuzzy, inner_icmp_pkt, vxlan_inputs)
            if inner_icmp_pkt != None and vxlan_icmp_pkt != None:
                logger.info("Inner ICMP packet built")
                logger.info("Vxlan ICMP Packet built")
                vxlan_icmp_pkt.show()
                return vxlan_icmp_pkt, vxlan_inputs[7], vxlan_inputs[8]
            else:
                return None
        else:
            logger.critical(
                "Invalid input '{}' Expected string (y/n)".format(fuzzy))
            return None
    elif msg_type == 'VXLAN_UDP':
        vxlan_input_param, common_param = requires("VXLAN")
        udp_input_param, _ = requires("UDP")
        inner_udp_pkt, vxlan_udp_pkt = None, None
        fuzzy = (input("Generate random Vxlan UDP Packet? (y/n) > ").strip()).lower()
        if fuzzy == 'y':
            inputs = []
            for i in range(0, len(common_param)):
                inputs.insert(i, input("{} > ".format(common_param[i])))
            inner_udp_pkt = udp_packet(fuzzy, 'VXLAN', None)
            vxlan_udp_pkt = vxlan_packet(fuzzy, inner_udp_pkt, inputs)
            if inner_udp_pkt != None and vxlan_udp_pkt != None:
                logger.info("Inner UDP packet built")
                logger.info("Vxlan UDP Packet built")
                vxlan_udp_pkt.show()
                return vxlan_udp_pkt, inputs[0], inputs[1]
            else:
                return None
        elif fuzzy == 'n':
            udp_inputs = []
            del udp_input_param[-1]
            for i in range(0, len(udp_input_param)):
                temp_input = input("Inner {} > ".format(udp_input_param[i]))
                udp_inputs.insert(i, temp_input)
            inner_udp_pkt = udp_packet(fuzzy, 'VXLAN', udp_inputs)
            vxlan_inputs = []
            for i in range(0, len(vxlan_input_param)):
                temp_input = input("{} > ".format(vxlan_input_param[i]))
                if "4789" in vxlan_input_param[i] and temp_input != True:
                    temp_input = '4789'
                vxlan_inputs.insert(i, temp_input)
            for j in range(0, len(common_param)):
                i = i + 1
                vxlan_inputs.insert(i, input("{} > ".format(common_param[j])))
            vxlan_udp_pkt = vxlan_packet(fuzzy, inner_udp_pkt, vxlan_inputs)
            if inner_udp_pkt != None and vxlan_udp_pkt != None:
                logger.info("Inner UDP packet built")
                logger.info("Vxlan UDP Packet built")
                vxlan_udp_pkt.show()
                return vxlan_udp_pkt, vxlan_inputs[7], vxlan_inputs[8]
            else:
                return None
        else:
            logger.critical(
                "Invalid input '{}' Expected string (y/n)".format(fuzzy))
            return None
    elif msg_type == 'VXLAN_TCP':
        vxlan_input_param, common_param = requires("VXLAN")
        tcp_input_param, _ = requires("TCP")
        inner_tcp_pkt, vxlan_tcp_pkt = None, None
        fuzzy = (input("Generate random Vxlan TCP Packet? (y/n) > ").strip()).lower()
        if fuzzy == 'y':
            inputs = []
            for i in range(0, len(common_param)):
                inputs.insert(i, input("{} > ".format(common_param[i])))
            inner_tcp_pkt = tcp_packet(fuzzy, 'VXLAN', None)
            vxlan_tcp_pkt = vxlan_packet(fuzzy, inner_tcp_pkt, inputs)
            if inner_tcp_pkt != None and vxlan_tcp_pkt != None:
                logger.info("Inner TCP packet built")
                logger.info("Vxlan TCP Packet built")
                vxlan_tcp_pkt.show()
                return vxlan_tcp_pkt, inputs[0], inputs[1]
            else:
                return None
        elif fuzzy == 'n':
            tcp_inputs = []
            del tcp_input_param[-1]
            for i in range(0, len(tcp_input_param)):
                temp_input = input("Inner {} > ".format(tcp_input_param[i]))
                tcp_inputs.insert(i, temp_input)
            inner_tcp_pkt = tcp_packet(fuzzy, 'VXLAN', tcp_inputs)
            vxlan_inputs = []
            for i in range(0, len(vxlan_input_param)):
                temp_input = input("{} > ".format(vxlan_input_param[i]))
                if "4789" in vxlan_input_param[i] and temp_input != True:
                    temp_input = '4789'
                vxlan_inputs.insert(i, temp_input)
            for j in range(0, len(common_param)):
                i = i + 1
                vxlan_inputs.insert(i, input("{} > ".format(common_param[j])))
            vxlan_tcp_pkt = vxlan_packet(fuzzy, inner_tcp_pkt, vxlan_inputs)
            if inner_tcp_pkt != None and vxlan_tcp_pkt != None:
                logger.info("Inner TCP packet built")
                logger.info("Vxlan TCP Packet built")
                vxlan_tcp_pkt.show()
                return vxlan_tcp_pkt, vxlan_inputs[7], vxlan_inputs[8]
            else:
                return None
        else:
            logger.critical(
                "Invalid input '{}' Expected string (y/n)".format(fuzzy))
            return None
    elif msg_type == 'VXLAN_ARP':
        vxlan_input_param, common_param = requires("VXLAN")
        arp_input_param, _ = requires('ARP')
        inner_arp_pkt, vxlan_arp_pkt = None, None
        fuzzy = (input("Generate random Vxlan ARP Packet? (y/n) > ").strip()).lower()
        if fuzzy == 'y':
            arp_type = (input("ARP Type (req/resp) > ").strip()).lower()
            inputs = []
            for i in range(0, len(common_param)):
                inputs.insert(i, input("{} > ".format(common_param[i])))
            inner_arp_pkt = arp_packet(fuzzy, 'VXLAN', arp_type, inputs)
            vxlan_arp_pkt = vxlan_packet(fuzzy, inner_arp_pkt, inputs)
            if inner_arp_pkt != None and vxlan_arp_pkt != None:
                logger.info("Inner ARP packet built")
                logger.info("VXLAN ARP packet built")
                vxlan_arp_pkt.show()
                return vxlan_arp_pkt, inputs[0], inputs[1]
        elif fuzzy == 'n':
            arp_type = (input("ARP Type (req/resp) > ").strip()).lower()
            inputs = []
            del arp_input_param[-1]
            for i in range(0, len(arp_input_param)):
                temp_input = input("Inner {} > ".format(arp_input_param[i]))
                inputs.insert(i, temp_input)
            inner_arp_pkt = arp_packet(fuzzy, 'VXLAN', arp_type, inputs)
            vxlan_inputs = []
            for i in range(0, len(vxlan_input_param)):
                temp_input = input("{} > ".format(vxlan_input_param[i]))
                if "4789" in vxlan_input_param[i] and temp_input != True:
                    temp_input = '4789'
                vxlan_inputs.insert(i, temp_input)
            for j in range(0, len(common_param)):
                i = i + 1
                vxlan_inputs.insert(i, input("{} > ".format(common_param[j])))
            vxlan_arp_pkt = vxlan_packet(fuzzy, inner_arp_pkt, vxlan_inputs)
            if inner_arp_pkt != None and vxlan_arp_pkt != None:
                logger.info("Inner ARP packet built")
                logger.info("Vxlan ARP Packet built")
                vxlan_arp_pkt.show()
                return vxlan_arp_pkt, vxlan_inputs[7], vxlan_inputs[8]
        else:
            logger.critical(
                "Invalid input '{}' Expected string (y/n)".format(fuzzy))
            return None
    else:
        logger.critical("Invalid msg_type: '{}' provided.".format(msg_type))
        return None


def vxlan():
    avail_vxlan_mods = {
        1: 'Vxlan - Inner ICMP',
        2: 'Vxlan - Inner UDP',
        3: 'Vxlan - Inner TCP',
        4: 'Vxlan - Inner ARP',
    }
    print('Packet Type:\n')
    for key in avail_vxlan_mods.keys():
        print(key, '--', avail_vxlan_mods[key])
    try:
        msg_type = int(input("\nEnter your choice (1-3) > ").strip())
        if msg_type == 1:
            return build_vxlan("VXLAN_ICMP")
        elif msg_type == 2:
            return build_vxlan("VXLAN_UDP")
        elif msg_type == 3:
            return build_vxlan("VXLAN_TCP")
        elif msg_type == 4:
            return build_vxlan("VXLAN_ARP")
        else:
            logger.critical("Invalid msg_type, expected integer (1-3)")
            return None
    except ValueError:
        logger.critical("Invalid msg_type, expected integer (1-3)")
        return None

