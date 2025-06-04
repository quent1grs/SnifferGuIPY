import scapy.all as scapy
from .analyzer import analyze_packet

def start_sniffer(interface_name, count):
    print(f"\nDébut de la capture de {count} paquets sur l'interface {interface_name}...\n")
    packets = scapy.sniff(iface=interface_name, prn=analyze_packet, count=count)
    return packets
