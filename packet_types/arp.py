from scapy.all import Ether, ARP, RandMAC, RandIP, get_if_hwaddr, get_if_addr
import re

from .helpers import requires, add_vlan, validate_cos, logger


def arp_packet(fuzzy, module, arp_type, arp_inputs):
    final_packet = None
    if arp_type == 'req':
        op_code = "who-has"
    elif arp_type == 'resp':
        op_code = "is-at"
    else:
        logger.critical(
            "Invalid arp_type: '{}' Expected value (req/resp)".format(arp_type))
        return None
    if fuzzy == 'y':
        if module != None and len(arp_inputs) != 0:
            if module == 'VXLAN' or module  == 'MPLS':
                src_mac = sender_mac = RandMAC()._fix()
                sender_ip = RandIP("172.16.0.0/12")._fix()
                trgt_ip = RandIP("172.16.0.0/12")._fix()
                if arp_type == "req":
                    dst_mac = 'ff:ff:ff:ff:ff:ff'
                    trgt_mac = '00:00:00:00:00:00'
                elif arp_type == "resp":
                    dst_mac = trgt_mac = RandMAC()._fix()
            elif module == 'ARP':
                src_mac = sender_mac = get_if_hwaddr(arp_inputs[1])
                sender_ip = get_if_addr(arp_inputs[1])
                ip_pattern = re.compile(r'^0\.0\.0\.0$')
                if ip_pattern.match(sender_ip):
                    sender_ip = RandIP("172.16.0.0/12")._fix()
                trgt_ip = RandIP("172.16.0.0/12")._fix()
                if arp_type == "req":
                    dst_mac = 'ff:ff:ff:ff:ff:ff'
                    trgt_mac = '00:00:00:00:00:00'
                elif arp_type == 'resp':
                    dst_mac = trgt_mac = RandMAC()._fix()
            else:
                return None
    elif fuzzy == 'n':
        if module != None and len(arp_inputs) != 0:
            if module == 'ARP' or module == 'VXLAN' or module == 'MPLS':
                src_mac = arp_inputs[0]
                sender_mac = arp_inputs[2]
                sender_ip = arp_inputs[3]
                trgt_ip = arp_inputs[5]
                if arp_type == "req":
                    dst_mac = 'ff:ff:ff:ff:ff:ff'
                    trgt_mac = '00:00:00:00:00:00'
                elif arp_type == 'resp':
                    dst_mac = arp_inputs[1]
                    trgt_mac = arp_inputs[4]
        else:
            return None
    final_packet = (Ether(src=src_mac, dst=dst_mac)) / ARP(op=op_code,
                                                           hwsrc=sender_mac,
                                                           psrc=sender_ip,
                                                           hwdst=trgt_mac,
                                                           pdst=trgt_ip)
    return final_packet


def build_arp():
    input_param, common_param = requires("ARP")
    inputs = [None] * len(input_param)
    arp_pkt = None
    fuzzy = (input("Generate random ARP Packet? (y/n) > ").strip()).lower()
    if fuzzy == "y":
        arp_type = (input("ARP Type (req/resp) > ").strip()).lower()
        inputs = []
        for i in range(0, len(common_param)):
            inputs.insert(i, input("{} > ".format(common_param[i])))
        arp_pkt = arp_packet(fuzzy, 'ARP', arp_type, inputs)
        if arp_pkt != None:
            logger.info("ARP packet built")
            arp_pkt.show()
            return arp_pkt, inputs[0], inputs[1]
        else:
            return None
    elif fuzzy == "n":
        arp_type = (input("ARP Type (req/resp) > ").strip()).lower()
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
        if not (inputs[6]):
            arp_pkt = arp_packet(fuzzy, 'ARP', arp_type, inputs)
        else:
            vlans = inputs[6].split(",")
            cos = (dot1q_prio[0]).strip().split(",")
            try:
                vlans = [int(i) for i in vlans]
            except ValueError:
                logger.critical(
                    "Invalid vlan id'{}' Expected integer".format(vlans))
                logger.critical(ValueError, exc_info=True)
                return None
            arp_pkt = arp_packet(fuzzy, 'ARP', arp_type, inputs)
            cos = validate_cos(cos, vlans)
            if arp_pkt != None and cos != None:
                arp_pkt = add_vlan(arp_pkt, vlans, cos)
            else:
                return None
        if arp_pkt != None:
            logger.info("ARP packet built")
            arp_pkt.show()
            return arp_pkt, inputs[7], inputs[8]
        else:
            return None
    else:
        logger.critical(
            "Invalid input '{}' Expected string (y/n)".format(fuzzy))
        return None
