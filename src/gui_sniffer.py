import scapy.all as scapy
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk
import os
from Sniffer import config
from Sniffer.core import start_sniffer
from Sniffer.logger import log_ip
from Sniffer.protocol import get_protocol_name

class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("Sniffeur de Paquets Réseau")

        # Interfaces
        self.interfaces = scapy.get_if_list()
        self.interface_label = tk.Label(master, text="Interface Réseau :")
        self.interface_label.pack()
        self.interface_combo = ttk.Combobox(master, values=self.interfaces)
        self.interface_combo.pack()

        # Nombre de paquets
        self.packet_count_label = tk.Label(master, text="Nombre de paquets à capturer :")
        self.packet_count_label.pack()
        self.packet_count_entry = tk.Entry(master)
        self.packet_count_entry.insert(0, "20")
        self.packet_count_entry.pack()

        # Boutons
        self.start_button = tk.Button(master, text="Capture Limitée", command=self.start_limited_sniffer)
        self.start_button.pack(pady=5)
        self.unlimited_button = tk.Button(master, text="Capture Illimitée", command=self.start_unlimited_sniffer)
        self.unlimited_button.pack(pady=5)
        self.stop_button = tk.Button(master, text="Arrêter", command=self.stop_sniffer, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        # Sortie texte
        self.output_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=100, height=20)
        self.output_text.pack()

        # Stats
        self.stats_frame = tk.LabelFrame(master, text="Statistiques", padx=10, pady=10)
        self.stats_frame.pack(pady=5)
        self.stats_labels = {
            "TCP": tk.Label(self.stats_frame, text="TCP : 0"),
            "UDP": tk.Label(self.stats_frame, text="UDP : 0"),
            "ARP": tk.Label(self.stats_frame, text="ARP : 0"),
            "ICMP": tk.Label(self.stats_frame, text="ICMP : 0"),
            "ICMPv6": tk.Label(self.stats_frame, text="ICMPv6 : 0"),
            "DNS": tk.Label(self.stats_frame, text="DNS : 0"),
            "Unknown": tk.Label(self.stats_frame, text="Inconnus : 0"),
        }
        for label in self.stats_labels.values():
            label.pack(anchor="w")

        self.stop_flag = threading.Event()
        self.update_stats()

    def update_stats(self):
        self.stats_labels["TCP"].config(text=f"TCP : {config.TCPcount}")
        self.stats_labels["UDP"].config(text=f"UDP : {config.UDPcount}")
        self.stats_labels["ARP"].config(text=f"ARP : {config.ARPcount}")
        self.stats_labels["ICMP"].config(text=f"ICMP : {config.ICMPcount}")
        self.stats_labels["ICMPv6"].config(text=f"ICMPv6 : {config.ICMPv6count}")
        self.stats_labels["DNS"].config(text=f"DNS : {config.DNScount}")
        self.stats_labels["Unknown"].config(text=f"Inconnus : {config.unknowncount}")
        self.master.after(1000, self.update_stats)

    def start_limited_sniffer(self):
        interface = self.interface_combo.get()
        count = self.packet_count_entry.get()

        if not interface or not count.isdigit():
            self.output_text.insert(tk.END, "Vérifiez les champs interface et nombre de paquets.\n")
            return

        self.output_text.delete(1.0, tk.END)
        self.stop_flag.clear()
        self.start_button.config(state=tk.DISABLED)
        self.unlimited_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        threading.Thread(target=self.capture_limited, args=(interface, int(count)), daemon=True).start()

    def start_unlimited_sniffer(self):
        interface = self.interface_combo.get()
        if not interface:
            self.output_text.insert(tk.END, "Veuillez choisir une interface.\n")
            return

        self.output_text.delete(1.0, tk.END)
        self.stop_flag.clear()
        self.start_button.config(state=tk.DISABLED)
        self.unlimited_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        threading.Thread(target=self.capture_unlimited, args=(interface,), daemon=True).start()

    def stop_sniffer(self):
        self.stop_flag.set()
        self.start_button.config(state=tk.NORMAL)
        self.unlimited_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def capture_limited(self, interface, count):
        scapy.sniff(iface=interface, prn=self.process_packet, stop_filter=lambda x: self.stop_flag.is_set(), count=count)
        self.output_text.insert(tk.END, f"\nCapture terminée.\n")

    def capture_unlimited(self, interface):
        scapy.sniff(iface=interface, prn=self.process_packet, stop_filter=lambda x: self.stop_flag.is_set())
        self.output_text.insert(tk.END, "\nCapture illimitée arrêtée.\n")

    def process_packet(self, packet):
        try:
            protocol = get_protocol_name(packet)
            text = f"Protocole : {protocol}\n"

            if packet.haslayer(scapy.IP):
                text += f"IP Source : {packet[scapy.IP].src}\n"
                text += f"IP Destination : {packet[scapy.IP].dst}\n"
                log_ip(packet[scapy.IP].src)

            if packet.haslayer(scapy.TCP):
                config.TCPcount += 1
                text += f"Port Source : {packet[scapy.TCP].sport}\n"
                text += f"Port Destination : {packet[scapy.TCP].dport}\n"

            elif packet.haslayer(scapy.UDP):
                config.UDPcount += 1
                text += f"Port Source : {packet[scapy.UDP].sport}\n"
                text += f"Port Destination : {packet[scapy.UDP].dport}\n"

            elif packet.haslayer(scapy.ICMP):
                config.ICMPcount += 1

            elif "ICMPv6" in packet.summary():
                config.ICMPv6count += 1

            elif packet.haslayer(scapy.ARP):
                config.ARPcount += 1

            elif packet.haslayer(scapy.DNS):
                config.DNScount += 1

            if protocol == "Unknown":
                config.unknowncount += 1

            text += f"Résumé : {packet.summary()}\n{'-'*50}\n"
            self.output_text.insert(tk.END, text)
            self.output_text.see(tk.END)

        except Exception as e:
            self.output_text.insert(tk.END, f"[Erreur] {e}\n")
            self.output_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

