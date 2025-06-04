import scapy.all as scapy

def get_protocol_name(packet):
    if packet.haslayer(scapy.TCP):
        return "TCP"
    elif packet.haslayer(scapy.UDP):
        return "UDP"
    elif packet.haslayer(scapy.ICMP):
        return "ICMP"
    elif packet.haslayer(scapy.ARP):
        return "ARP"
    elif packet.haslayer(scapy.DNS):
        return "DNS"
    elif "ICMPv6" in packet.summary():
        return "ICMPv6"
    else:
        return "Unknown"
