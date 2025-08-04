from .helpers import requires, logger
from .flow_control import flow_control_packet


def build_pfc():
    pfc_pkt = None
    input_param, common_param = requires("PFC")
    fuzzy = (input("Random 802.1Qbb PFC Frame? (y/n) > ").strip()).lower()
    if fuzzy == "y":
        inputs = []
        for i in range(0, len(common_param)):
            inputs.insert(i, input("{} > ".format(common_param[i])))
        pfc_pkt = flow_control_packet(fuzzy, 'PFC', inputs)
        if pfc_pkt != None:
            logger.info("802.1Qbb PFC Frame built")
            pfc_pkt.show()
            return pfc_pkt, inputs[0], inputs[1]
        else:
            return None
    elif fuzzy == "n":
        inputs = []
        for i in range(0, len(input_param)):
            inputs.insert(i, input("{} > ".format(input_param[i])))
        for j in range(0, len(common_param)):
            i = i + 1
            inputs.insert(i, input("{} > ".format(common_param[j])))
        pfc_pkt = flow_control_packet(fuzzy, 'PFC', inputs)
        if pfc_pkt != None:
            logger.info("802.1Qbb PFC Frame built")
            pfc_pkt.show()
            return pfc_pkt, inputs[3], inputs[4]
        else:
            return None
    else:
        logger.critical(
            "Invalid input '{}' Expected string (y/n)".format(fuzzy))
        return None

