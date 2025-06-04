import os
import scapy.all as scapy
from .analyzer import analyze_packet

def start_sniffer(interface_name, count, pcap_filename="logs/capture/capture.pcap"):
    print(f"\nDébut de la capture de {count} paquets sur l'interface {interface_name}...\n")

    # Capture les paquets en temps réel, analyse chaque paquet
    packets = scapy.sniff(iface=interface_name, prn=analyze_packet, count=count)

    # Crée le dossier de sauvegarde si nécessaire
    os.makedirs(os.path.dirname(pcap_filename), exist_ok=True)

    # Sauvegarde des paquets capturés dans un fichier .pcap
    scapy.wrpcap(pcap_filename, packets)
    print(f"\nCapture enregistrée dans {pcap_filename}")

    return packets
