import os
import scapy.all as scapy
from . import config

def log_ip(ip):
    if ip not in config.Iplist:
        config.Iplist.add(ip)
        config.RegisteredIpCount += 1
        print("IP enregistrée avec succès")

        try:
            os.makedirs(os.path.dirname(config.filename), exist_ok=True)

            with open(config.filename, "a") as f:
                f.write(ip + "\n")
        except Exception as err:
            config.RegisteredIpErrors.append(f"Erreur d'écriture IP: {err}")

def start_capture(interface="eth0", pcap_filename="captures/capture.pcap"):
    """
    Démarre la capture sur l'interface donnée et enregistre tout dans un fichier .pcap
    """

    # Crée le dossier si besoin
    os.makedirs(os.path.dirname(pcap_filename), exist_ok=True)

    print(f"Capture en cours sur {interface}... Appuyez sur Ctrl+C pour arrêter.")

    try:
        # Capture illimitée (Ctrl+C pour arrêter)
        packets = scapy.sniff(iface=interface, prn=process_packet)

        # À la fin de la capture, enregistre les paquets dans un fichier .pcap
        scapy.wrpcap(pcap_filename, packets)
        print(f"Capture enregistrée dans {pcap_filename}")

    except KeyboardInterrupt:
        print("\nCapture arrêtée par l'utilisateur.")
        # Sauvegarder les paquets même en cas d'arrêt
        scapy.wrpcap(pcap_filename, packets)
        print(f"Capture sauvegardée dans {pcap_filename}")

def process_packet(packet):
    """
    Traite chaque paquet : ici, extrait les IP et appelle log_ip()
    """
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        log_ip(src_ip)

