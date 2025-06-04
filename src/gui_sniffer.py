import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
from Sniffer.core import start_sniffer
from Sniffer import config
import scapy.all as scapy

class SnifferGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Sniffeur de Paquets")

        # Liste des interfaces
        self.interfaces = scapy.get_if_list()

        # Interface réseau
        ttk.Label(master, text="Interface réseau:").pack()
        self.interface_combo = ttk.Combobox(master, values=self.interfaces)
        self.interface_combo.pack()

        # Nombre de paquets
        ttk.Label(master, text="Nombre de paquets à capturer:").pack()
        self.packet_count_entry = ttk.Entry(master)
        self.packet_count_entry.insert(0, "10")
        self.packet_count_entry.pack()

        # Bouton démarrer
        self.start_button = ttk.Button(master, text="Démarrer", command=self.start_capture)
        self.start_button.pack()

        # Zone d'affichage
        self.output = scrolledtext.ScrolledText(master, width=80, height=25)
        self.output.pack()

    def start_capture(self):
        interface = self.interface_combo.get()
        try:
            count = int(self.packet_count_entry.get())
        except ValueError:
            self.output.insert(tk.END, "Erreur: le nombre de paquets doit être un entier.\n")
            return

        self.output.insert(tk.END, f"Capture de {count} paquets sur {interface}...\n")
        threading.Thread(target=self.run_sniffer, args=(interface, count), daemon=True).start()

    def run_sniffer(self, interface, count):
        try:
            packets = start_sniffer(interface, count)
            self.output.insert(tk.END, f"Capture terminée. {len(packets)} paquets capturés.\n")
            self.output.insert(tk.END, f"TCP: {config.TCPcount}, UDP: {config.UDPcount}, ARP: {config.ARPcount}, ICMP: {config.ICMPcount}, ICMPv6: {config.ICMPv6count}, DNS: {config.DNScount}, Inconnus: {config.unknowncount}\n")

            if config.RegisteredIpErrors:
                self.output.insert(tk.END, "Erreurs d'enregistrement IP:\n")
                for err in config.RegisteredIpErrors:
                    self.output.insert(tk.END, f"- {err}\n")
            else:
                self.output.insert(tk.END, f"{config.RegisteredIpCount} IPs enregistrées dans {config.filename}\n")

        except Exception as e:
            self.output.insert(tk.END, f"Erreur pendant la capture : {e}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferGUI(root)
    root.mainloop()

