import re
from random import randint

from scapy.all import Ether, RandMAC, RandIP, get_if_hwaddr
from scapy.contrib.mpls import MPLS, EoMCW

from .helpers import requires, logger
from .icmp import icmp_packet
from .arp import arp_packet
from .transport import udp_packet, tcp_packet


def mpls_packet(fuzzy, inner_pkt, mpls_inputs):
    final_pkt = None
    mpls_headers = None
    if fuzzy == 'y':
        mpls_labels_list = None
        mpls_label_count = 0
        if inner_pkt != None and len(mpls_inputs) != 0:
            outer_dst_mac, outer_src_mac = RandMAC()._fix(), get_if_hwaddr(mpls_inputs[1])
            mpls_label_count = int((input("No. of MPLS labels (maximum = 10) > ").strip()).lower())
            if mpls_label_count == 1:
                mpls_headers = MPLS(label=randint(16, 1048575), cos=0, s=1, ttl=255)
            elif 2 <= mpls_label_count <= 10:
                mpls_headers = MPLS(label=randint(16, 1048575), cos=0, s=0, ttl=255)
                for i in range(1, mpls_label_count):
                    bos = 0
                    if i == mpls_label_count - 1:
                        bos = 1
                    mpls_headers = mpls_headers / MPLS(label=randint(16, 1048575), cos=0, s=bos, ttl=255)
            else:
                logger.critical("Invalid input '{}' Expected value <= 10".format(mpls_label_count))
                return None
        else:
            return None
        final_pkt = Ether(src=outer_src_mac, dst=outer_dst_mac, type=0x8847) / mpls_headers / inner_pkt
        return final_pkt
    elif fuzzy == 'n':
        mpls_labels_list = None
        mpls_label_count = 0
        if inner_pkt != None and len(mpls_inputs) != 0:
            outer_dst_mac = mpls_inputs[1]
            mac_pattern = re.compile(
                r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
            if mac_pattern.match(mpls_inputs[0].strip()):
                outer_src_mac = mpls_inputs[0]
            else:
                outer_src_mac = get_if_hwaddr(mpls_inputs[5])
            mpls_labels_list = mpls_inputs[2]
            mpls_label_count = len(mpls_labels_list)
            if mpls_label_count == 1:
                mpls_headers = MPLS(label=int(mpls_labels_list[0]), cos=0, s=1, ttl=255)
            elif mpls_label_count >= 2:
                mpls_headers = MPLS(label=int(mpls_labels_list[0]), cos=0, s=0, ttl=255)
                for i in range(1, mpls_label_count):
                    bos = 0
                    if i == mpls_label_count - 1:
                        bos = 1
                    mpls_headers = mpls_headers / MPLS(label=int(mpls_labels_list[i]), cos=0, s=bos, ttl=255)
        else:
            return None
        if mpls_inputs[3] is True:
            final_pkt = Ether(src=outer_src_mac, dst=outer_dst_mac, type=0x8847) / mpls_headers / EoMCW(zero=0, reserved=0, seq=0) / inner_pkt
        else:
            final_pkt = Ether(src=outer_src_mac, dst=outer_dst_mac, type=0x8847) / mpls_headers / inner_pkt
        return final_pkt


def build_mpls(msg_type):
    if msg_type == 'MPLS_ICMP':
        mpls_input_param, common_param = requires("MPLS")
        icmp_input_param, _ = requires('ICMP')
        inner_icmp_pkt, mpls_icmp_pkt = None, None
        fuzzy = (input("Generate random MPLS ICMP Packet? (y/n) > ").strip()).lower()
        if fuzzy == 'y':
            icmp_type = (input("ICMP Type (req/reply) > ").strip()).lower()
            inputs = []
            for i in range(0, len(common_param)):
                inputs.insert(i, input("{} > ".format(common_param[i])))
            inner_icmp_pkt = icmp_packet(fuzzy, 'MPLS', icmp_type, inputs)
            mpls_icmp_pkt = mpls_packet(fuzzy, inner_icmp_pkt, inputs)
            if inner_icmp_pkt != None and mpls_icmp_pkt != None:
                logger.info("Inner ICMP packet built")
                logger.info("MPLS ICMP Packet built")
                mpls_icmp_pkt.show()
                return mpls_icmp_pkt, inputs[0], inputs[1]
            else:
                return None
        elif fuzzy == 'n':
            labels = None
            icmp_type = (input("ICMP Type (req/reply) > ").strip()).lower()
            inputs = []
            del icmp_input_param[-1]
            for i in range(0, len(icmp_input_param)):
                temp_input = input("Inner {} > ".format(icmp_input_param[i]))
                inputs.insert(i, temp_input)
            inner_icmp_pkt = icmp_packet(fuzzy, 'MPLS', icmp_type, inputs)
            mpls_inputs = []
            for i in range(0, len(mpls_input_param)):
                temp_input = input("{} > ".format(mpls_input_param[i]))
                if "Labels" in mpls_input_param[i]:
                    labels = [x.strip() for x in temp_input.split(',')]
                    for k in range(0, len(labels)):
                        try:
                            if (0 <= int(labels[k]) <= 1048575) is False:
                                logger.error(
                                    "Invalid input '{}' Expected label in range (0-1048575)".format(labels[k]))
                                return None
                        except ValueError:
                            logger.error(
                                "Invalid input '{}' Expected comma separated values in range (0-1048575)".format(labels[k]))
                            return None
                    mpls_inputs.insert(i, labels)
                elif "Control Word" in mpls_input_param[i] and temp_input.lower() == "y":
                    mpls_inputs.insert(i, True)
                elif "Control Word" in mpls_input_param[i] and temp_input.lower() == "n":
                    mpls_inputs.insert(i, False)
                elif "Control Word" not in mpls_input_param[i]:
                    mpls_inputs.insert(i, temp_input)
                else:
                    logger.critical("Invalid choice, got '{}' expected values (y/n)".format(temp_input))
                    return None
            for j in range(0, len(common_param)):
                i = i + 1
                mpls_inputs.insert(i, input("{} > ".format(common_param[j])))
            mpls_icmp_pkt = mpls_packet(fuzzy, inner_icmp_pkt, mpls_inputs)
            if inner_icmp_pkt != None and mpls_icmp_pkt != None:
                logger.info("Inner ICMP packet built")
                logger.info("MPLS ICMP Packet built")
                mpls_icmp_pkt.show()
                return mpls_icmp_pkt, mpls_inputs[4], mpls_inputs[5]
            else:
                return None
        else:
            logger.critical(
                "Invalid input '{}' Expected string (y/n)".format(fuzzy))
            return None
    elif msg_type == 'MPLS_UDP':
        mpls_input_param, common_param = requires("MPLS")
        udp_input_param, _ = requires("UDP")
        inner_udp_pkt, mpls_udp_pkt = None, None
        fuzzy = (input("Generate random MPLS UDP Packet? (y/n) > ").strip()).lower()
        if fuzzy == 'y':
            inputs = []
            for i in range(0, len(common_param)):
                inputs.insert(i, input("{} > ".format(common_param[i])))
            inner_udp_pkt = udp_packet(fuzzy, 'MPLS', None)
            mpls_udp_pkt = mpls_packet(fuzzy, inner_udp_pkt, inputs)
            if inner_udp_pkt != None and mpls_udp_pkt != None:
                logger.info("Inner UDP packet built")
                logger.info("MPLS UDP Packet built")
                mpls_udp_pkt.show()
                return mpls_udp_pkt, inputs[0], inputs[1]
            else:
                return None
        elif fuzzy == 'n':
            labels = None
            inputs = []
            del udp_input_param[-1]
            for i in range(0, len(udp_input_param)):
                temp_input = input("Inner {} > ".format(udp_input_param[i]))
                inputs.insert(i, temp_input)
            inner_udp_pkt = udp_packet(fuzzy, 'MPLS', inputs)
            mpls_inputs = []
            for i in range(0, len(mpls_input_param)):
                temp_input = input("{} > ".format(mpls_input_param[i]))
                if "Labels" in mpls_input_param[i]:
                    labels = [x.strip() for x in temp_input.split(',')]
                    for k in range(0, len(labels)):
                        try:
                            if (0 <= int(labels[k]) <= 1048575) is False:
                                logger.error(
                                    "Invalid input '{}' Expected label in range (0-1048575)".format(labels[k]))
                                return None
                        except ValueError:
                            logger.error(
                                "Invalid input '{}' Expected comma separated values in range (0-1048575)".format(labels[k]))
                            return None
                    mpls_inputs.insert(i, labels)
                elif "Control Word" in mpls_input_param[i] and temp_input.lower() == "y":
                    mpls_inputs.insert(i, True)
                elif "Control Word" in mpls_input_param[i] and temp_input.lower() == "n":
                    mpls_inputs.insert(i, False)
                elif "Control Word" not in mpls_input_param[i]:
                    mpls_inputs.insert(i, temp_input)
                else:
                    logger.critical("Invalid choice, got '{}' expected values (y/n)".format(temp_input))
                    return None
            for j in range(0, len(common_param)):
                i = i + 1
                mpls_inputs.insert(i, input("{} > ".format(common_param[j])))
            mpls_udp_pkt = mpls_packet(fuzzy, inner_udp_pkt, mpls_inputs)
            if inner_udp_pkt != None and mpls_udp_pkt != None:
                logger.info("Inner UDP packet built")
                logger.info("MPLS UDP Packet built")
                mpls_udp_pkt.show()
                return mpls_udp_pkt, mpls_inputs[4], mpls_inputs[5]
            else:
                return None
        else:
            logger.critical(
                "Invalid input '{}' Expected string (y/n)".format(fuzzy))
            return None
    elif msg_type == 'MPLS_TCP':
        mpls_input_param, common_param = requires("MPLS")
        tcp_input_param, _ = requires("TCP")
        inner_tcp_pkt, mpls_tcp_pkt = None, None
        fuzzy = (input("Generate random MPLS TCP Packet? (y/n) > ").strip()).lower()
        if fuzzy == 'y':
            inputs = []
            for i in range(0, len(common_param)):
                inputs.insert(i, input("{} > ".format(common_param[i])))
            inner_tcp_pkt = tcp_packet(fuzzy, 'MPLS', None)
            mpls_tcp_pkt = mpls_packet(fuzzy, inner_tcp_pkt, inputs)
            if inner_tcp_pkt != None and mpls_tcp_pkt != None:
                logger.info("Inner TCP packet built")
                logger.info("MPLS TCP Packet built")
                mpls_tcp_pkt.show()
                return mpls_tcp_pkt, inputs[0], inputs[1]
            else:
                return None
        elif fuzzy == 'n':
            labels = None
            inputs = []
            del tcp_input_param[-1]
            for i in range(0, len(tcp_input_param)):
                temp_input = input("Inner {} > ".format(tcp_input_param[i]))
                inputs.insert(i, temp_input)
            inner_tcp_pkt = tcp_packet(fuzzy, 'MPLS', inputs)
            mpls_inputs = []
            for i in range(0, len(mpls_input_param)):
                temp_input = input("{} > ".format(mpls_input_param[i]))
                if "Labels" in mpls_input_param[i]:
                    labels = [x.strip() for x in temp_input.split(',')]
                    for k in range(0, len(labels)):
                        try:
                            if (0 <= int(labels[k]) <= 1048575) is False:
                                logger.error(
                                    "Invalid input '{}' Expected label in range (0-1048575)".format(labels[k]))
                                return None
                        except ValueError:
                            logger.error(
                                "Invalid input '{}' Expected comma separated values in range (0-1048575)".format(labels[k]))
                            return None
                    mpls_inputs.insert(i, labels)
                elif "Control Word" in mpls_input_param[i] and temp_input.lower() == "y":
                    mpls_inputs.insert(i, True)
                elif "Control Word" in mpls_input_param[i] and temp_input.lower() == "n":
                    mpls_inputs.insert(i, False)
                elif "Control Word" not in mpls_input_param[i]:
                    mpls_inputs.insert(i, temp_input)
                else:
                    logger.critical("Invalid choice, got '{}' expected values (y/n)".format(temp_input))
                    return None
            for j in range(0, len(common_param)):
                i = i + 1
                mpls_inputs.insert(i, input("{} > ".format(common_param[j])))
            mpls_tcp_pkt = mpls_packet(fuzzy, inner_tcp_pkt, mpls_inputs)
            if inner_tcp_pkt != None and mpls_tcp_pkt != None:
                logger.info("Inner TCP packet built")
                logger.info("MPLS TCP Packet built")
                mpls_tcp_pkt.show()
                return mpls_tcp_pkt, mpls_inputs[4], mpls_inputs[5]
            else:
                return None
        else:
            logger.critical(
                "Invalid input '{}' Expected string (y/n)".format(fuzzy))
            return None
    elif msg_type == 'MPLS_ARP':
        mpls_input_param, common_param = requires("MPLS")
        arp_input_param, _ = requires('ARP')
        inner_arp_pkt, mpls_arp_pkt = None, None
        fuzzy = (input("Generate random MPLS ARP Packet? (y/n) > ").strip()).lower()
        if fuzzy == 'y':
            arp_type = (input("ARP Type (req/resp) > ").strip()).lower()
            inputs = []
            for i in range(0, len(common_param)):
                inputs.insert(i, input("{} > ".format(common_param[i])))
            inner_arp_pkt = arp_packet(fuzzy, 'MPLS', arp_type, inputs)
            mpls_arp_pkt = mpls_packet(fuzzy, inner_arp_pkt, inputs)
            if inner_arp_pkt != None and mpls_arp_pkt != None:
                logger.info("Inner ARP packet built")
                logger.info("MPLS ARP packet built")
                mpls_arp_pkt.show()
                return mpls_arp_pkt, inputs[0], inputs[1]
        elif fuzzy == 'n':
            arp_type = (input("ARP Type (req/resp) > ").strip()).lower()
            inputs = []
            del arp_input_param[-1]
            for i in range(0, len(arp_input_param)):
                if arp_type == 'req' and (arp_input_param[i] in ['Destination MAC', 'Target MAC']):
                    inputs.insert(i, None)
                    continue
                temp_input = input("Inner {} > ".format(arp_input_param[i]))
                inputs.insert(i, temp_input)
            inner_arp_pkt = arp_packet(fuzzy, 'MPLS', arp_type, inputs)
            mpls_inputs = []
            for i in range(0, len(mpls_input_param)):
                temp_input = input("{} > ".format(mpls_input_param[i]))
                if "Labels" in mpls_input_param[i]:
                    labels = [x.strip() for x in temp_input.split(',')]
                    for k in range(0, len(labels)):
                        try:
                            if (0 <= int(labels[k]) <= 1048575) is False:
                                logger.error(
                                    "Invalid input '{}' Expected label in range (0-1048575)".format(labels[k]))
                                return None
                        except ValueError:
                            logger.error(
                                "Invalid input '{}' Expected comma separated values in range (0-1048575)".format(labels[k]))
                            return None
                    mpls_inputs.insert(i, labels)
                elif "Control Word" in mpls_input_param[i] and temp_input.lower() == "y":
                    mpls_inputs.insert(i, True)
                elif "Control Word" in mpls_input_param[i] and temp_input.lower() == "n":
                    mpls_inputs.insert(i, False)
                elif "Control Word" not in mpls_input_param[i]:
                    mpls_inputs.insert(i, temp_input)
                else:
                    logger.critical("Invalid choice, got '{}' expected values (y/n)".format(temp_input))
                    return None
            for j in range(0, len(common_param)):
                i = i + 1
                mpls_inputs.insert(i, input("{} > ".format(common_param[j])))
            mpls_arp_pkt = mpls_packet(fuzzy, inner_arp_pkt, mpls_inputs)
            if inner_arp_pkt != None and mpls_arp_pkt != None:
                logger.info("Inner ARP packet built")
                logger.info("MPLS ARP Packet built")
                mpls_arp_pkt.show()
                return mpls_arp_pkt, mpls_inputs[4], mpls_inputs[5]
        else:
            logger.critical(
                "Invalid input '{}' Expected string (y/n)".format(fuzzy))
            return None
    else:
        logger.critical("Invalid msg_type: '{}' provided.".format(msg_type))
        return None


def mpls():
    avail_mpls_modules = {
        1: 'MPLS - Inner ICMP',
        2: 'MPLS - Inner UDP',
        3: 'MPLS - Inner TCP',
        4: 'MPLS - Inner ARP',
    }
    print('Packet Type:\n')
    for key in avail_mpls_modules.keys():
        print(key, '--', avail_mpls_modules[key])
    try:
        msg_type = int(input("\nEnter your choice (1-4) > ").strip())
        if msg_type == 1:
            return build_mpls("MPLS_ICMP")
        elif msg_type == 2:
            return build_mpls("MPLS_UDP")
        elif msg_type == 3:
            return build_mpls("MPLS_TCP")
        elif msg_type == 4:
            return build_mpls("MPLS_ARP")
        else:
            logger.critical("Invalid msg_type, expected integer (1-4)")
            return None
    except ValueError:
        logger.critical("Invalid msg_type, expected integer (1-4)")
        return None

