from .helpers import requires, logger
from .flow_control import flow_control_packet


def build_llfc():
    llfc_pkt = None
    input_param, common_param = requires("LLFC")
    fuzzy = (input("Random 802.3x Pause Frame? (y/n) > ").strip()).lower()
    if fuzzy == "y":
        inputs = []
        for i in range(0, len(common_param)):
            inputs.insert(i, input("{} > ".format(common_param[i])))
        llfc_pkt = flow_control_packet(fuzzy, 'LLFC', inputs)
        if llfc_pkt != None:
            logger.info("802.3x Pause Frame built")
            llfc_pkt.show()
            return llfc_pkt, inputs[0], inputs[1]
        else:
            return None
    elif fuzzy == "n":
        inputs = []
        for i in range(0, len(input_param)):
            inputs.insert(i, input("{} > ".format(input_param[i])))
        for j in range(0, len(common_param)):
            i = i + 1
            inputs.insert(i, input("{} > ".format(common_param[j])))
        llfc_pkt = flow_control_packet(fuzzy, 'LLFC', inputs)
        if llfc_pkt != None:
            logger.info("802.3x Pause Frame built")
            llfc_pkt.show()
            return llfc_pkt, inputs[2], inputs[3]
        else:
            return None
    else:
        logger.critical(
            "Invalid input '{}' Expected string (y/n)".format(fuzzy))
        return None

