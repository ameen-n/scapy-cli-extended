import random
import re
import struct
from random import randint

from scapy.all import Ether, Padding, RandMAC, get_if_hwaddr
from scapy.contrib.mac_control import MACControl, MACControlPause

from .helpers import logger


def flow_control_packet(fuzzy, module_type, module_inputs):
    final_frame = None
    if module_type not in ['LLFC', 'PFC']:
        logger.critical(
            "Invalid flow control type: '{}' Expected value (LLFC/PFC)".format(
                module_type))
        return None
    if fuzzy == "y":
        if module_type == 'LLFC':
            src_mac, dst_mac = RandMAC()._fix(), MACControl.DEFAULT_DST_MAC
            time_quanta = randint(0, 65535)
        elif module_type == 'PFC':
            src_mac, dst_mac = RandMAC()._fix(), MACControl.DEFAULT_DST_MAC
            class_enable_vector = [
                random.choice([True, False]) for _ in range(8)
            ]
            class_pause_times = [
                randint(1, 65535) if class_enable_vector[i] else 0 for i in range(8)
            ]
        else:
            return None
    if fuzzy == "n":
        if module_type == 'LLFC':
            mac_pattern = re.compile(
                r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
            if mac_pattern.match(module_inputs[0].strip()):
                src_mac = module_inputs[0]
            else:
                logger.error(
                    "Invalid source MAC provided. Extracting source MAC from source interface.")
                src_mac = get_if_hwaddr(module_inputs[3])
            dst_mac = MACControl.DEFAULT_DST_MAC
            try:
                time_quanta = int(module_inputs[1])
            except ValueError:
                logger.critical(
                    "Invalid input '{}' Expected integer (0-65535)".format(module_inputs[1]))
                logger.critical(ValueError, exc_info=True)
                return None
            if time_quanta < 0 or time_quanta > 65535:
                logger.critical(
                    "Invalid Quanta value provided '{}' Expected value in range (0-65535)".format(time_quanta))
                return None
        elif module_type == 'PFC':
            mac_pattern = re.compile(
                r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
            if mac_pattern.match(module_inputs[0].strip()):
                src_mac = module_inputs[0]
            else:
                logger.error(
                    "Invalid source MAC provided. Extracting source MAC from source interface.")
                src_mac = get_if_hwaddr(module_inputs[4])
            dst_mac = MACControl.DEFAULT_DST_MAC
            cev_input = (module_inputs[1].strip()).split(",")
            cev_input = [x.strip().upper() for x in cev_input]
            quanta_input = (module_inputs[2].strip()).split(",")
            quanta_input = [x.strip().upper() for x in quanta_input]
            class_enable_vector, class_pause_times = validate_cev_quanta(cev_input, quanta_input)
            if class_enable_vector == None or class_pause_times == None:
                return None
    if module_type == 'LLFC':
        final_frame = Ether(src=src_mac, dst=dst_mac) / MACControlPause(pause_time=time_quanta)
    elif module_type == 'PFC':
        final_frame = Ether(src=src_mac, dst=dst_mac, type=0x8808)
        pfc_opcode = 0x0101
        cev_value = sum(2**i if class_enable_vector[i] else 0 for i in range(8))
        class_pause_times_bytes = b''.join([time.to_bytes(2, byteorder='big') for time in class_pause_times])
        pfc_payload = struct.pack("!H", pfc_opcode) + cev_value.to_bytes(2, byteorder='big') + class_pause_times_bytes
        padding_length = 46 - len(pfc_payload)
        padding = Padding(load=b'\x00' * padding_length)
        final_frame = final_frame / pfc_payload / padding
    return final_frame


def validate_cev_quanta(cev, quanta):
    class_names = ['C0', 'C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7']
    default_cev = [False] * 8
    default_quanta = [0] * 8
    if len(quanta) > len(cev):
        logger.error("Mismatched Quanta and Class inputs")
        return None, None
    elif len(quanta) <= len(cev):
        if (len(quanta) == 1 and len(cev) == 1) and (cev[0] == "" and quanta[0] == ""):
            return default_cev, default_quanta
        for class_id in cev:
            if class_id not in class_names:
                logger.error(
                    "Invalid Class value '{}' Expected comma separated values in range C0 - C7".format(class_id))
                return None, None
        if len(quanta) == 1 and quanta[0] == "":
            _ = quanta.pop(0)
        quanta.extend([0] * (len(cev) - len(quanta)))
        try:
            quanta = [int(i) for i in quanta]
        except ValueError:
            logger.critical(
                "Invalid Quanta value '{}' Expected integer in range 0 - 65535".format(quanta))
            logger.critical(ValueError, exc_info=True)
            return None, None
        if (any((i > 65535) or (i < 0) for i in quanta)):
            logger.error(
                "Invalid Quanta value '{}' Expected value in range 0 - 65535".format(quanta))
            return None, None
        for i in range(0, len(cev)):
            default_cev[class_names.index(cev[i])] = True
            default_quanta[class_names.index(cev[i])] = quanta[i]
        return default_cev, default_quanta

