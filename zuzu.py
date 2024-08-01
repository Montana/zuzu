import os
import time
import logging
import smtplib
from scapy.all import sniff, IP, TCP, UDP, DNS, HTTP
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logging.basicConfig(filename='network_monitor.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

SUSPICIOUS_IPS = ["192.168.1.100", "10.0.0.200"]
MAX_CONNECTIONS = 10
connections = {}
whitelist = ["192.168.1.1"]
blacklist = ["192.168.1.50"]

# email configuration (i don't need it, but some people might want it for alerts, so i added it in here.) 
EMAIL_ADDRESS = "your_email@example.com"
EMAIL_PASSWORD = "your_password"
ALERT_RECIPIENT = "alert_recipient@example.com"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587

def send_email(subject, body):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = ALERT_RECIPIENT
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_ADDRESS, ALERT_RECIPIENT, text)
        server.quit()
        logging.info(f"Email alert sent to {ALERT_RECIPIENT}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

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
        send_email("Suspicious Activity Detected", reason)
        disable_internet()

    if DNS in packet:
        log_dns_request(packet)
    if TCP in packet and packet[TCP].dport == 80:
        log_http_request(packet)
    if UDP in packet:
        log_udp_traffic(packet)

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
    try:
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
    except Exception as e:
        logging.error(f"Failed to load configuration: {e}")

def save_configuration(filename='config.txt'):
    try:
        with open(filename, 'w') as file:
            file.write(f"SUSPICIOUS_IPS={','.join(SUSPICIOUS_IPS)}\n")
            file.write(f"MAX_CONNECTIONS={MAX_CONNECTIONS}\n")
            file.write(f"whitelist={','.join(whitelist)}\n")
            file.write(f"blacklist={','.join(blacklist)}\n")
        logging.info("Configuration saved to file.")
    except Exception as e:
        logging.error(f"Failed to save configuration: {e}")

def display_configuration():
    print("Current Configuration:")
    print(f"SUSPICIOUS_IPS: {SUSPICIOUS_IPS}")
    print(f"MAX_CONNECTIONS: {MAX_CONNECTIONS}")
    print(f"Whitelist: {whitelist}")
    print(f"Blacklist: {blacklist}")

def reload_configuration_periodically(interval=60):
    while True:
        load_configuration()
        time.sleep(interval)

def interactive_console():
    while True:
        print("\n1. Add to blacklist")
        print("2. Add to whitelist")
        print("3. Remove from blacklist")
        print("4. Remove from whitelist")
        print("5. Display configuration")
        print("6. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            ip = input("Enter IP to add to blacklist: ")
            add_to_blacklist(ip)
        elif choice == '2':
            ip = input("Enter IP to add to whitelist: ")
            add_to_whitelist(ip)
        elif choice == '3':
            ip = input("Enter IP to remove from blacklist: ")
            remove_from_blacklist(ip)
        elif choice == '4':
            ip = input("Enter IP to remove from whitelist: ")
            remove_from_whitelist(ip)
        elif choice == '5':
            display_configuration()
        elif choice == '6':
            break
        else:
            print("Invalid choice. Please try again.")

def log_dns_request(packet):
    query_name = packet[DNS].qd.qname if packet[DNS].qd else 'Unknown'
    logging.info(f"DNS Request: {packet[IP].src} -> {query_name}")

def log_http_request(packet):
    try:
        host = packet[HTTP].Host.decode() if packet[HTTP].Host else 'Unknown'
        path = packet[HTTP].Path.decode() if packet[HTTP].Path else 'Unknown'
        logging.info(f"HTTP Request: {packet[IP].src} -> {host}{path}")
    except Exception as e:
        logging.error(f"Failed to log HTTP request: {e}")

def log_udp_traffic(packet):
    logging.info(f"UDP Traffic: {packet[IP].src} -> {packet[IP].dst}:{packet[UDP].dport}")

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

    from threading import Thread
    config_thread = Thread(target=reload_configuration_periodically)
    config_thread.daemon = True
    config_thread.start()

    console_thread = Thread(target=interactive_console)
    console_thread.daemon = True
    console_thread.start()

    start_packet_sniffing()

    save_configuration()
