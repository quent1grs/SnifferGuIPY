from datetime import datetime

TCPcount = 0
UDPcount = 0
ARPcount = 0
ICMPcount = 0
ICMPv6count = 0
DNScount = 0
unknowncount = 0
RegisteredIpCount = 0

Iplist = set()
RegisteredIpErrors = []
filename = f"logs/IP/ips_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
