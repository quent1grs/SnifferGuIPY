import scapy.all as scapy
import threading
import tkinter as tk
import os
from tkinter import scrolledtext, ttk
from Sniffer import config
from Sniffer.logger import log_ip
from Sniffer.protocol import get_protocol_name
from datetime import datetime

LOG_DIR = "logs"
CAPTURE_LOG_DIR = os.path.join(LOG_DIR, "captures")
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(CAPTURE_LOG_DIR, exist_ok=True)

GLOBAL_LOG_FILE = os.path.join(LOG_DIR, "logs.txt")

def get_new_capture_log_file():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"capture_{timestamp}.txt"
    return os.path.join(CAPTURE_LOG_DIR, filename)

class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("Sniffeur de Paquets Réseau")
        master.geometry("1000x750")

        self.logged_ips = set()

        self.main_frame = tk.Frame(master)
        self.main_frame.pack(fill="both", expand=True)

        self.left_frame = tk.Frame(self.main_frame)
        self.left_frame.grid(row=0, column=0, sticky="n", padx=10, pady=10)

        self.stats_frame = tk.LabelFrame(self.left_frame, text="Statistiques", padx=10, pady=10)
        self.stats_frame.grid(row=0, column=0, sticky="nw", pady=5)

        self.stats_labels = {
            "TCP": tk.Label(self.stats_frame, text="TCP : 0"),
            "UDP": tk.Label(self.stats_frame, text="UDP : 0"),
            "ARP": tk.Label(self.stats_frame, text="ARP : 0"),
            "ICMP": tk.Label(self.stats_frame, text="ICMP : 0"),
            "ICMPv6": tk.Label(self.stats_frame, text="ICMPv6 : 0"),
            "DNS": tk.Label(self.stats_frame, text="DNS : 0"),
            "Unknown": tk.Label(self.stats_frame, text="Inconnus : 0"),
            "Logged IPs": tk.Label(self.stats_frame, text="IP enregistrées : 0"),
        }

        for i, label in enumerate(self.stats_labels.values()):
            label.grid(row=i, column=0, sticky="w")

        self.controls_frame = tk.Frame(self.left_frame)
        self.controls_frame.grid(row=1, column=0, pady=20)

        # Interface
        self.interface_label = tk.Label(self.controls_frame, text="Interface Réseau :")
        self.interface_label.grid(row=0, column=0, sticky="w")
        self.interface_combo = ttk.Combobox(self.controls_frame, values=scapy.get_if_list())
        self.interface_combo.grid(row=1, column=0, pady=5, sticky="we")

        # Nombre de paquets
        self.packet_count_label = tk.Label(self.controls_frame, text="Nombre de paquets à capturer :")
        self.packet_count_label.grid(row=2, column=0, sticky="w")
        self.packet_count_entry = tk.Entry(self.controls_frame)
        self.packet_count_entry.insert(0, "20")
        self.packet_count_entry.grid(row=3, column=0, pady=5, sticky="we")

        # Boutons
        self.start_button = tk.Button(self.controls_frame, text="Capture Limitée", command=self.start_limited_sniffer)
        self.start_button.grid(row=4, column=0, pady=5, sticky="we")

        self.unlimited_button = tk.Button(self.controls_frame, text="Capture Illimitée", command=self.start_unlimited_sniffer)
        self.unlimited_button.grid(row=5, column=0, pady=5, sticky="we")

        self.stop_button = tk.Button(self.controls_frame, text="Arrêter", command=self.stop_sniffer, state=tk.DISABLED)
        self.stop_button.grid(row=6, column=0, pady=5, sticky="we")

        self.output_text = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD, width=100, height=40, state=tk.DISABLED)
        self.output_text.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(0, weight=1)

        self.stop_flag = threading.Event()
        self.update_stats()
        self.current_capture_file = None      
    
    def update_stats(self):
        self.stats_labels["TCP"].config(text=f"TCP : {config.TCPcount}")
        self.stats_labels["UDP"].config(text=f"UDP : {config.UDPcount}")
        self.stats_labels["ARP"].config(text=f"ARP : {config.ARPcount}")
        self.stats_labels["ICMP"].config(text=f"ICMP : {config.ICMPcount}")
        self.stats_labels["ICMPv6"].config(text=f"ICMPv6 : {config.ICMPv6count}")
        self.stats_labels["DNS"].config(text=f"DNS : {config.DNScount}")
        self.stats_labels["Unknown"].config(text=f"Inconnus : {config.unknowncount}")
        self.stats_labels["Logged IPs"].config(text=f"IP enregistrées : {len(self.logged_ips)}")
        self.master.after(1000, self.update_stats)

    def reset_stats(self):
        config.TCPcount = 0
        config.UDPcount = 0
        config.ARPcount = 0
        config.ICMPcount = 0
        config.ICMPv6count = 0
        config.DNScount = 0
        config.unknowncount = 0
        self.logged_ips.clear()


    def start_limited_sniffer(self):
        interface = self.interface_combo.get()
        count = self.packet_count_entry.get()

        if not interface or not count.isdigit():
            self.write_output("Vérifiez les champs interface et nombre de paquets.\n")
            return

        self.clear_output()
        self.reset_stats()
        self.logged_ips.clear()
        self.stop_flag.clear()
        self.toggle_buttons(True)
        threading.Thread(target=self.capture_limited, args=(interface, int(count)), daemon=True).start()
        self.current_capture_file = get_new_capture_log_file()
        
        with open(self.current_capture_file, "w", encoding="utf-8") as f:
            f.write(f"--- Nouvelle capture limitée : {datetime.now()} ---\n")
        self.toggle_buttons(True)
        threading.Thread(target=self.capture_limited, args=(interface, int(count)), daemon=True).start()

    def start_unlimited_sniffer(self):
        interface = self.interface_combo.get()
        if not interface:
            self.write_output("Veuillez choisir une interface.\n")
            return

        self.clear_output()
        self.reset_stats()
        self.logged_ips.clear()
        self.stop_flag.clear()
        self.toggle_buttons(True)
        threading.Thread(target=self.capture_unlimited, args=(interface,), daemon=True).start()

    def stop_sniffer(self):
        self.stop_flag.set()
        self.toggle_buttons(False)

    def toggle_buttons(self, running):
        self.start_button.config(state=tk.DISABLED if running else tk.NORMAL)
        self.unlimited_button.config(state=tk.DISABLED if running else tk.NORMAL)
        self.stop_button.config(state=tk.NORMAL if running else tk.DISABLED)

    def capture_limited(self, interface, count):
        scapy.sniff(iface=interface, prn=self.process_packet, stop_filter=lambda x: self.stop_flag.is_set(), count=count)
        self.write_output("\nCapture terminée.\n")

    def capture_unlimited(self, interface):
        scapy.sniff(iface=interface, prn=self.process_packet, stop_filter=lambda x: self.stop_flag.is_set())
        self.write_output("\nCapture illimitée arrêtée.\n")

    def write_output(self, message):
        # Affichage dans l'interface
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, message)
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
        if self.current_capture_file:
            with open(self.current_capture_file, "a", encoding="utf-8") as f:
                f.write(message)

        # Journal global avec timestamp
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
        with open(GLOBAL_LOG_FILE, "a", encoding="utf-8") as f:
            for line in message.strip().split("\n"):
                f.write(f"{timestamp}{line}\n")

    def clear_output(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)


    def process_packet(self, packet):
        try:
            protocol = get_protocol_name(packet)
            text = f"Protocole : {protocol}\n"

            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                text += f"IP Source : {src_ip}\n"
                text += f"IP Destination : {dst_ip}\n"
                log_ip(src_ip)
                self.logged_ips.add(src_ip)

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

            text += f"Résumé : {packet.summary()}\n{'-'*70}\n"
            self.write_output(text)

        except Exception as e:
            self.write_output(f"[Erreur] {e}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

