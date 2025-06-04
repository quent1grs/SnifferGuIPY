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
