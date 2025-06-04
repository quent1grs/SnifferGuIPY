
# Sniffer Réseau

## Projet Python Sniffer réseau




## Installation

Pour lancer ce projet, clonez le repo
Déplacez vous dans le dossier du repo 

Si vous souhaitez un environnement python run :```python3 -m venv 
Nom_De_l'environnement``` 

Pour activer l'environnement faites : 

```source Nom_De_l'environnement/bin/activate ```

Maintenant vous devez installer les dépendance : ```pip install -r requierement.txt ```

## Lancement

Afin de lancer le projet il vous faudra être en root ou du moins lancer en sudo  car Scapy a besoin des autorisations root pour fonctionner.
Pour cela deplacer vous a la racine du projet et 

Faites : ``` sudo python3 -m src.Sniffer.main ``` pour lancer le sniffer.

Choisissez l'interface sur laquelle vous voulez écoutez et ensuite choisissez le nombre de paquet a Capturer .

Après avoir utilisé le sniffer, si vous voulez quitter l'environnement faites la commande:

``` deactivate ```



## Features

Enregistrement des captures : Vous pouvez enregistrer vos captures en .pcap ou .txt.

Interface utilisateur graphique : Une interface utilisateur graphique est disponible pour une meilleure expérience utilisateur.

Analyse des protocoles : Le sniffer prend en charge plusieurs protocoles, et d'autres comme SSH, POP3, SMB, RDP, LDAP, et IMAP seront ajoutés dans les futures mises à jour.

Outils complémentaires : Des outils tels que Nmap, Hashcat, Nikto, Gobuster, ou encore Enum4linux viendront compléter notre sniffer afin de pouvoir faire un outil de réseau/pentest assez complet.

## Packages
| Package             | Liens                                              
| ----------------- | ------------------------------------------------------------------ |
Scapy |https://scapy.net

#### (suite du projet)
| Package             | Liens                                              
| ----------------- | ------------------------------------------------------------------ |
| Smtplib |https://docs.python.org/3/library/smtplib.html|
| Os |https://docs.python.org/fr/3.13/library/os.html|
| Subprocess|https://docs.python.org/3/library/subprocess.html|

## TCP Flags

| Lettre | Signification (Flag TCP) | Description |
|:------:|:------------------------:|:-----------:|
| S      | SYN (Synchronize)         | Début de connexion |
| A      | ACK (Acknowledge)         | Accusé de réception |
| F      | FIN (Finish)              | Fin de connexion |
| R      | RST (Reset)               | Réinitialisation de connexion |
| P      | PSH (Push)                | Demande de traitement immédiat des données |
| U      | URG (Urgent)              | Données urgentes |
| E      | ECE (Explicit Congestion Notification Echo) | Signal de congestion |
| W      | CWR (Congestion Window Reduced) | Contrôle de congestion |
| RAW    | RAW DATA                  | Données brutes |


## Authors

- [@quent1grs](https://github.com/quent1grs)
- [@Alikakila](https://github.com/AlikakilA)
