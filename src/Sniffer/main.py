import scapy.all as scapy
from .core import start_sniffer
from . import config

def main():
    print("\nInterfaces réseau disponibles:\n")
    interfaces = scapy.get_if_list()
    print(interfaces)

    while True:
        interface = input("\nEntrez le nom de l'interface réseau à écouter : ")
        if interface in interfaces:
            break
        print("Erreur : l'interface spécifiée n'existe pas.")

    while True:
        count = input("\nEntrez le nombre de paquets à capturer : ")
        if count.isdigit() and int(count) > 0:
            count = int(count)
            break
        print("Erreur : veuillez entrer un entier positif.")

    packets = start_sniffer(interface, count)

    print(f"\nCapture terminée. {len(packets)} paquets capturés.")
    print(f"Paquets TCP capturés: {config.TCPcount}")
    print(f"Paquets UDP capturés: {config.UDPcount}")
    print(f"Paquets ARP capturés: {config.ARPcount}")
    print(f"Paquets ICMP capturés: {config.ICMPcount}")
    print(f"Paquets ICMPv6 capturés: {config.ICMPv6count}")
    print(f"Paquets DNS capturés: {config.DNScount}")
    print(f"Paquets inconnus capturés: {config.unknowncount}")

    if config.RegisteredIpErrors:
        print("Erreurs lors de l'enregistrement des IPs :")
        for err in config.RegisteredIpErrors:
            print(f"- {err}")
    else:
        print(f"{config.RegisteredIpCount} IPs enregistrées dans {config.filename}")

if __name__ == "__main__":
    main()
