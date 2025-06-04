import scapy.all as scapy
from .protocol import get_protocol_name
from .logger import log_ip
from . import config

def analyze_packet(packet):
    try:
        protocol = get_protocol_name(packet)
        print(f"Protocole: {protocol}")

        if packet.haslayer(scapy.IP):
            print(f"IP Source: {packet[scapy.IP].src}")
            print(f"IP Destination: {packet[scapy.IP].dst}")
            log_ip(packet[scapy.IP].src)

        if packet.haslayer(scapy.TCP):
            print(f"Port Source: {packet[scapy.TCP].sport}")
            print(f"Port Destination: {packet[scapy.TCP].dport}")
            config.TCPcount += 1

        if packet.haslayer(scapy.UDP):
            print(f"Port Source: {packet[scapy.UDP].sport}")
            print(f"Port Destination: {packet[scapy.UDP].dport}")
            config.UDPcount += 1

        if "ICMPv6" in packet.summary():
            config.ICMPv6count += 1
            print("[+] ICMPv6 détecté")

        if packet.haslayer(scapy.ICMP):
            print(f"ICMP Type: {packet[scapy.ICMP].type}")
            print(f"ICMP Code: {packet[scapy.ICMP].code}")
            config.ICMPcount += 1

        if packet.haslayer(scapy.ARP):
            print(f"Type ARP: {packet[scapy.ARP].op}")
            print(f"IP Source: {packet[scapy.ARP].psrc}")
            print(f"IP Destination: {packet[scapy.ARP].pdst}")
            print(f"MAC Source: {packet[scapy.ARP].hwsrc}")
            print(f"MAC Destination: {packet[scapy.ARP].hwdst}")
            config.ARPcount += 1

        if packet.haslayer(scapy.DNS):
            dns = packet[scapy.DNS]
            if dns.qr == 0:
                print(f"DNS Query: {dns.qd.qname.decode()}")
            elif dns.qr == 1:
                print(f"DNS Response for: {dns.qd.qname.decode()}")
                if dns.an:
                    for i in range(dns.ancount):
                        print(f"Answer {i + 1}: {dns.an[i].rdata}")
            config.DNScount += 1

        if protocol == "Unknown":
            config.unknowncount += 1

        print(f"Résumé: {packet.summary()}")
        print("\n" + "-"*50 + "\n")

    except Exception as e:
        print(f"Erreur lors de l'analyse du paquet: {e}")
