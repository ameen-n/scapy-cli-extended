from .helpers import requires, add_vlan, validate_cos, logger
from .transport import udp_packet


def build_mcast():
    input_param, common_param = requires("MCAST")
    udp_pkt = None
    fuzzy = (input("Random Multicast Packet? (y/n) > ").strip()).lower()
    if fuzzy == "y":
        inputs = []
        for i in range(0, len(common_param)):
            inputs.insert(i, input("{} > ".format(common_param[i])))
        udp_pkt = udp_packet(fuzzy, 'MCAST', inputs)
        if udp_pkt != None:
            logger.info("Multicast Packet built")
            udp_pkt.show()
            return udp_pkt, inputs[0], inputs[1]
        else:
            return None
    elif fuzzy == "n":
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
            udp_pkt = udp_packet(fuzzy, 'MCAST', inputs)
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
            udp_pkt = udp_packet(fuzzy, 'MCAST', inputs)
            cos = validate_cos(cos, vlans)
            if udp_pkt != None and cos != None:
                udp_pkt = add_vlan(udp_pkt, vlans, cos)
            else:
                return None
        if udp_pkt != None:
            logger.info("UDP Packet built")
            udp_pkt.show()
            return udp_pkt, inputs[6], inputs[7]
        else:
            return None
    else:
        logger.critical(
            "Invalid input '{}' Expected string (y/n)".format(fuzzy))
        return None

