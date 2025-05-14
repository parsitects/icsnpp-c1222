#!/usr/bin/python3

import logging
import argparse
from scapy.all import *
from c1222_classes import *
from packet_generators.read_write_service_packets_gen import *
from packet_generators.ident_service_packets_gen import *
from packet_generators.trace_service_packets_gen import *
from packet_generators.logon_service_packets_gen import *
from packet_generators.registration_service_packets_gen import *
from packet_generators.message_packet_gen import *

logging.basicConfig(
    format='%(levelname)s: %(message)s',
    level=logging.INFO
)

logger = logging.getLogger(__name__)

class C1222PacketBuilder:
    def __init__(self, debug=False, src_ip=None, dst_ip=None, src_port=None, dst_port=None, protocol='tcp'):
        # Enable debug logging if requested
        if debug:
            logger.setLevel(logging.DEBUG)
        
        # Network configuration
        self.src_ip = src_ip or "192.168.100.124"
        self.dst_ip = dst_ip or "192.168.1.101"
        self.src_port = src_port or 1153
        self.dst_port = dst_port or 1577
        self.initial_seq = 100
        self.protocol = protocol.lower()
        
        # Hardcoded MAC addresses to avoid ARP lookup warnings
        self.src_mac = "00:11:22:33:44:55"
        self.dst_mac = "66:77:88:99:aa:bb"

    # def calculate_crc(self, message):
    #     """Calculate CRC for the message"""
    #     logger.debug(f"Calculating CRC for message of length {len(message)}")
    #     crc16 = crcmod.mkCrcFun(0x18005, rev=True, initCrc=0xFFFF, xorOut=0x0000)
    #     crc = crc16(message)
    #     logger.debug(f"CRC calculated: {crc:04x}")
    #     return crc.to_bytes(2, byteorder='little')

    def create_packet(self, message, is_response=False):
        """Create a single packet (TCP or UDP)"""
        #logger.debug(f"Creating {self.protocol.upper()} packet with {len(message_bytes)} bytes")
        
        if self.protocol == 'tcp':
            return self._create_tcp_packet(message, is_response)
        else:  # UDP
            return self._create_udp_packet(message, is_response)
            
    def _create_tcp_packet(self, message, is_response=False):
        if is_response:
            # Response packet (from dst to src)
            packet = Ether(src=self.dst_mac, dst=self.src_mac) / IP(src=self.dst_ip, dst=self.src_ip) / TCP(
                sport=self.dst_port,
                dport=self.src_port,
                seq=self.initial_seq,
                flags="PA"
            ) / message
        else:
            # Request packet (from src to dst)
            packet = Ether(src=self.src_mac, dst=self.dst_mac) / IP(src=self.src_ip, dst=self.dst_ip) / TCP(
                sport=self.src_port,
                dport=self.dst_port,
                seq=self.initial_seq,
                flags="PA"
            ) / message

        return packet

    def _create_udp_packet(self, message, is_response=False):
        """Create a single UDP packet with explicit Ethernet header"""
        if is_response:
            # Response packet (from dst to src)
            packet = Ether(src=self.dst_mac, dst=self.src_mac) / IP(src=self.dst_ip, dst=self.src_ip) / UDP(
                sport=self.dst_port,
                dport=self.src_port
            ) / message
        else:
            # Request packet (from src to dst)
            packet = Ether(src=self.src_mac, dst=self.dst_mac) / IP(src=self.src_ip, dst=self.dst_ip) / UDP(
                sport=self.src_port,
                dport=self.dst_port
            ) / message
        
        # Explicitly calculate and set length fields to avoid Wireshark warnings
        # This forces Scapy to recalculate all length fields properly
        if hasattr(packet, 'len'):
            del packet.len  # Remove any existing len field so Scapy recalculates it
        
        return packet

    def build_pcap(self, packets, output_file):
        """Build and save the PCAP file"""
        try:
            wrpcap(output_file, packets)
            logger.info(f"Successfully created {self.protocol.upper()} PCAP file: {output_file}")
        except Exception as e:
            logger.error(f"Unexpected error while creating PCAP: {str(e)}")
            raise

################################################################################
# Main Function
################################################################################
if "__main__" == __name__:
    parser = argparse.ArgumentParser(description="Build ROC Plus PCAP files")
    parser.add_argument('--output', type=str, help='Output PCAP filename')
    parser.add_argument('--req', action='store_true', help='Generate request packet')
    parser.add_argument('--res', action='store_true', help='Generate response packet')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--src-ip', type=str, help='Source IP address (default: 192.168.1.100)')
    parser.add_argument('--dst-ip', type=str, help='Destination IP address (default: 192.168.1.200)')
    parser.add_argument('--src-port', type=int, help='Source port (default: 1577)')
    parser.add_argument('--dst-port', type=int, help='Destination port (default: 1153)')
    parser.add_argument('--comprehensive', '--all', action='store_true', help='Generate a comprehensive PCAP')
    parser.add_argument('--protocol', choices=['tcp', 'udp'], default='tcp', help='Protocol to use (default: tcp)')
    parser.add_argument('--type', choices=['rw_service','ident_service', 'trace_service', 'logon_service', 'reg_service'], default='rw_service', help='The type of packet to generate.')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    # Create builder with network params directly passed to constructor
    builder = C1222PacketBuilder(
        debug=args.debug,
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        src_port=args.src_port,
        dst_port=args.dst_port,
        protocol=args.protocol
    )

    req_resp = "response" if args.res else "request"
    protocol_suffix = args.protocol

    if (args.type == ""):
        logger.error("There was no type passed in via --type")

    type = args.type
    pcap_folder = "../../Traces"
    output_file = args.output or f"{pcap_folder}/c1222_{type}_{req_resp}_{protocol_suffix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    
    if (args.type == "rw_service"):
        packets = [
            builder.create_packet(createMessageFromService(rw_service_req, "req"), False),
            builder.create_packet(createMessageFromService(rw_service_resp, "resp"), True)
        ]

        builder.build_pcap(packets, output_file)
    elif (args.type == "ident_service"):
        packets = [
            builder.create_packet(createMessageFromService(ident_service_req, "req"), False),
            builder.create_packet(createMessageFromService(ident_service_resp, "resp"), True)
        ]

        builder.build_pcap(packets, output_file)
    elif (args.type == "trace_service"):
        packets = [
            builder.create_packet(createMessageFromService(trace_service_req, "req"), False),
            builder.create_packet(createMessageFromService(trace_service_resp, "resp"), True)
        ]
        
        builder.build_pcap(packets, output_file)
    elif (args.type == "logon_service"):
        packets = [
            builder.create_packet(createMessageFromService(logon_service_req, "req"), False),
            builder.create_packet(createMessageFromService(logon_service_resp, "resp"), True)
        ]

        builder.build_pcap(packets, output_file)
    elif (args.type == "reg_service"):
        packets = [
            builder.create_packet(createMessageFromService(reg_service_req, "req"), False),
            builder.create_packet(createMessageFromService(reg_service_resp, "resp"), True)
        ]

        builder.build_pcap(packets, output_file)
    else:
        logger.error("The type passed in via --type is incorrect!")
