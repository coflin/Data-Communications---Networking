from scapy.all import *

try:
    pcap_file_path = "icmp.pcap"
except FileNotFoundError:
    print(f"File not found icmp.pcap. Please change the path or try again")

packets = rdpcap(pcap_file_path)

for packet in packets:
    if IP in packet and ICMP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        print(f"Source IP: {source_ip}, Destination IP: {destination_ip}")
