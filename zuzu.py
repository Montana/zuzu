import os
import time
import logging
from scapy.all import sniff, IP, TCP, UDP

logging.basicConfig(filename='network_monitor.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

SUSPICIOUS_IPS = ["192.168.1.100", "10.0.0.200"]
MAX_CONNECTIONS = 10
connections = {}
whitelist = ["192.168.1.1"]
blacklist = ["192.168.1.50"]

def is_suspicious(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if src_ip in blacklist or dst_ip in blacklist:
            return True, f"Connection to/from blacklisted IP: {src_ip} -> {dst_ip}"
        
        if src_ip in whitelist or dst_ip in whitelist:
            return False, ""
        
        if dst_ip in SUSPICIOUS_IPS:
            return True, f"Connection to suspicious IP: {dst_ip}"
        
        if src_ip not in connections:
            connections[src_ip] = 1
        else:
            connections[src_ip] += 1
        
        if connections[src_ip] > MAX_CONNECTIONS:
            return True, f"Too many connections from IP: {src_ip}"
    
    return False, ""

def packet_callback(packet):
    is_suspicious_activity, reason = is_suspicious(packet)
    if is_suspicious_activity:
        logging.warning(reason)
        print(f"Suspicious activity detected: {reason}")
        send_alert(reason)
        disable_internet()

def disable_internet(interface='eth0'):
    os.system(f"sudo ifconfig {interface} down")
    logging.info("Internet connection disabled.")

def restore_internet(interface='eth0'):
    os.system(f"sudo ifconfig {interface} up")
    logging.info("Internet connection restored.")

def send_alert(reason):
    print(f"Alert: {reason}")

def add_to_blacklist(ip):
    if ip not in blacklist:
        blacklist.append(ip)
        logging.info(f"Added IP to blacklist: {ip}")

def add_to_whitelist(ip):
    if ip not in whitelist:
        whitelist.append(ip)
        logging.info(f"Added IP to whitelist: {ip}")

def remove_from_blacklist(ip):
    if ip in blacklist:
        blacklist.remove(ip)
        logging.info(f"Removed IP from blacklist: {ip}")

def remove_from_whitelist(ip):
    if ip in whitelist:
        whitelist.remove(ip)
        logging.info(f"Removed IP from whitelist: {ip}")

def load_configuration(filename='config.txt'):
    global SUSPICIOUS_IPS, MAX_CONNECTIONS, whitelist, blacklist
    with open(filename, 'r') as file:
        lines = file.readlines()
        for line in lines:
            key, value = line.strip().split('=')
            if key == 'SUSPICIOUS_IPS':
                SUSPICIOUS_IPS = value.split(',')
            elif key == 'MAX_CONNECTIONS':
                MAX_CONNECTIONS = int(value)
            elif key == 'whitelist':
                whitelist = value.split(',')
            elif key == 'blacklist':
                blacklist = value.split(',')
    logging.info("Configuration loaded from file.")

def save_configuration(filename='config.txt'):
    with open(filename, 'w') as file:
        file.write(f"SUSPICIOUS_IPS={','.join(SUSPICIOUS_IPS)}\n")
        file.write(f"MAX_CONNECTIONS={MAX_CONNECTIONS}\n")
        file.write(f"whitelist={','.join(whitelist)}\n")
        file.write(f"blacklist={','.join(blacklist)}\n")
    logging.info("Configuration saved to file.")

def display_configuration():
    print("Current Configuration:")
    print(f"SUSPICIOUS_IPS: {SUSPICIOUS_IPS}")
    print(f"MAX_CONNECTIONS: {MAX_CONNECTIONS}")
    print(f"Whitelist: {whitelist}")
    print(f"Blacklist: {blacklist}")

def start_packet_sniffing():
    try:
        print("Starting packet sniffing...")
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("Stopping packet sniffing...")
        restore_internet()

if __name__ == "__main__":
    load_configuration()

    display_configuration()

    start_packet_sniffing()

    save_configuration()
