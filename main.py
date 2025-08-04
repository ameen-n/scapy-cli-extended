import sys

from packet_types.icmp import build_icmp
from packet_types.arp import build_arp
from packet_types.helpers import logger


def print_menu():
    print("1 -- ICMP")
    print("2 -- ARP")
    print("3 -- Quit")


def call_module(choice):
    if choice == 1:
        build_icmp()
    elif choice == 2:
        build_arp()
    elif choice == 3:
        logger.info("See you later, alligator!")
        sys.exit(0)
    else:
        logger.info('Invalid input. Please select a number (1-3)')


if __name__ == "__main__":
    call_mod = None
    while call_mod != 3:
        print_menu()
        try:
            call_mod = int((input("\nEnter your choice (1-3): ")).strip())
            call_module(call_mod)
        except ValueError:
            logger.info('Invalid input. Please select a number (1-3)')
