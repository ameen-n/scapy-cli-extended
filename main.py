import sys

from packet_types.icmp import build_icmp
from packet_types.arp import build_arp
from packet_types.igmp import igmp
from packet_types.mcast import build_mcast
from packet_types.vxlan import vxlan
from packet_types.llfc import build_llfc
from packet_types.pfc import build_pfc
from packet_types.mpls import mpls
from packet_types.helpers import logger


def print_menu():
    print("1 -- ICMP")
    print("2 -- ARP")

    print("3 -- IGMP")
    print("4 -- Multicast")
    print("5 -- VXLAN")
    print("6 -- Pause Frame")
    print("7 -- Priority Flow Control")
    print("8 -- MPLS")
    print("9 -- Quit")



def call_module(choice):
    if choice == 1:
        build_icmp()
    elif choice == 2:
        build_arp()
    elif choice == 3:

        igmp()
    elif choice == 4:
        build_mcast()
    elif choice == 5:
        vxlan()
    elif choice == 6:
        build_llfc()
    elif choice == 7:
        build_pfc()
    elif choice == 8:
        mpls()
    elif choice == 9:
        logger.info("See you later, alligator!")
        sys.exit(0)
    else:
        logger.info('Invalid input. Please select a number (1-9)')



if __name__ == "__main__":
    call_mod = None

    while call_mod != 9:
        print_menu()
        try:
            call_mod = int((input("\nEnter your choice (1-9): ")).strip())
            call_module(call_mod)
        except ValueError:
            logger.info('Invalid input. Please select a number (1-9)')

