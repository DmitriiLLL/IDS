import argparse
import time
import logging
import smtplib
import sqlite3
import threading
import os
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
from email.mime.text import MIMEText

class IDS:
    def __init__(self, signature_file=None, blacklist_file=None,
                 threshold=100, time_window=60,
                 port_threshold=20, port_time_window=60,
                 syn_threshold=200, syn_window=60,
                 http_threshold=20, http_time_window=60,
                 payload_size_threshold=1024,
                 ssh_threshold=5, ssh_time_window=300,
                 log_file='ids.log', db_file='ids_alerts.db',
                 email_config=None, block=False):
        self.signature_db = []
        if signature_file and os.path.exists(signature_file):
            with open(signature_file, 'rb') as f:
                self.signature_db = [line.strip() for line in f if line.strip()]

        self.blacklist = set()
        if blacklist_file and os.path.exists(blacklist_file):
            with open(blacklist_file) as f:
                self.blacklist = {ip.strip() for ip in f if ip.strip()}

        self.threshold = threshold
        self.time_window = time_window
        self.port_threshold = port_threshold
        self.port_time_window = port_time_window
        self.syn_threshold = syn_threshold
        self.syn_window = syn_window
        self.http_threshold = http_threshold
        self.http_time_window = http_time_window
        self.payload_size_threshold = payload_size_threshold
        self.ssh_threshold = ssh_threshold
        self.ssh_time_window = ssh_time_window
        self.block = block

        self.ip_counters = defaultdict(list)
        self.port_counters = defaultdict(lambda: defaultdict(list))
        self.syn_counters = defaultdict(list)
        self.http_counters = defaultdict(list)
        self.ssh_counters = defaultdict(list)

        logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s %(message)s')
        self.email_config = email_config or {}

        self.db_conn = sqlite3.connect(db_file, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        cursor = self.db_conn.cursor()
        cursor.execute(
            '''CREATE TABLE IF NOT EXISTS alerts (
                timestamp REAL,
                alert_type TEXT,
                src_ip TEXT,
                details TEXT
            )'''
        )
        self.db_conn.commit()

    def load_signatures(self, signature_list):
        self.signature_db = signature_list

    def load_blacklist(self, path):
        with open(path) as f:
            for line in f:
                ip = line.strip()
                if ip:
                    self.blacklist.add(ip)

    def log_alert(self, message):
        logging.info(message)

    def save_alert(self, alert_type, src_ip, details):
        cursor = self.db_conn.cursor()
        cursor.execute(
            'INSERT INTO alerts VALUES (?, ?, ?, ?)',
            (time.time(), alert_type, src_ip, details)
        )
        self.db_conn.commit()

    def send_email_alert(self, subject, body):
        cfg = self.email_config
        if not cfg:
            return
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = cfg['sender']
        msg['To'] = ', '.join(cfg['recipients'])
        with smtplib.SMTP(cfg['server'], cfg['port']) as smtp:
            if cfg.get('username') and cfg.get('password'):
                smtp.login(cfg['username'], cfg['password'])
            smtp.sendmail(cfg['sender'], cfg['recipients'], msg.as_string())

    def block_ip(self, ip):
        if self.block:
            os.system(f"iptables -A INPUT -s {ip} -j DROP")
            logging.info(f"Blocked IP: {ip}")

    def alert(self, alert_type, src_ip, details, packet):
        summary = f"{alert_type} | {src_ip} | {details} | {packet.summary()}"
        print(f"[ALERT] {summary}")
        self.log_alert(summary)
        self.save_alert(alert_type, src_ip, details)
        self.send_email_alert(f"IDS Alert: {alert_type}", summary)
        self.block_ip(src_ip)

    def check_blacklist(self, packet):
        src = packet[IP].src
        if src in self.blacklist:
            self.alert('BlacklistedIP', src, 'pre-configured blacklist hit', packet)

    def check_signature(self, packet):
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            for sig in self.signature_db:
                if sig in payload:
                    self.alert('SignatureMatch', packet[IP].src, sig.hex(), packet)

    def check_anomaly(self, packet):
        src = packet[IP].src
        now = time.time()
        self.ip_counters[src].append(now)
        window_start = now - self.time_window
        recent = [t for t in self.ip_counters[src] if t >= window_start]
        self.ip_counters[src] = recent
        if len(recent) > self.threshold:
            self.alert('HighPacketRate', src, f"{len(recent)} packets/{self.time_window}s", packet)

    def check_port_scan(self, packet):
        src = packet[IP].src
        now = time.time()
        if TCP in packet:
            dport = packet[TCP].dport
        elif UDP in packet:
            dport = packet[UDP].dport
        else:
            return
        self.port_counters[src][dport].append(now)
        window_start = now - self.port_time_window
        active_ports = [p for p, times in self.port_counters[src].items() if any(t >= window_start for t in times)]
        if len(active_ports) > self.port_threshold:
            self.alert('PortScan', src, f"{len(active_ports)} ports/{self.port_time_window}s", packet)

    def check_syn_flood(self, packet):
        if TCP in packet and packet[TCP].flags & 0x02:
            src = packet[IP].src
            now = time.time()
            self.syn_counters[src].append(now)
            window_start = now - self.syn_window
            recent = [t for t in self.syn_counters[src] if t >= window_start]
            self.syn_counters[src] = recent
            if len(recent) > self.syn_threshold:
                self.alert('SYNFlood', src, f"{len(recent)} SYNs/{self.syn_window}s", packet)

    def check_http(self, packet):
        if Raw in packet:
            data = packet[Raw].load
            if data.startswith(b"GET") or data.startswith(b"POST"):
                src = packet[IP].src
                now = time.time()
                self.http_counters[src].append(now)
                window_start = now - self.http_time_window
                recent = [t for t in self.http_counters[src] if t >= window_start]
                self.http_counters[src] = recent
                if len(recent) > self.http_threshold:
                    self.alert('HTTPFlood', src, f"{len(recent)} reqs/{self.http_time_window}s", packet)
                if b"' OR '1'='1" in data or b"../" in data or b"<script>" in data:
                    self.alert('HTTPInj', src, 'suspicious payload', packet)

    def check_payload_size(self, packet):
        size = len(packet)
        if size > self.payload_size_threshold:
            self.alert('LargePacket', packet[IP].src, f"size={size}", packet)

    def check_ssh_bruteforce(self, packet):
        if TCP in packet and packet[TCP].dport == 22 and Raw in packet:
            src = packet[IP].src
            now = time.time()
            self.ssh_counters[src].append(now)
            window_start = now - self.ssh_time_window
            recent = [t for t in self.ssh_counters[src] if t >= window_start]
            self.ssh_counters[src] = recent
            if len(recent) > self.ssh_threshold:
                self.alert('SSHBruteForce', src, f"{len(recent)} attempts/{self.ssh_time_window}s", packet)

    def check_dns(self, packet):
        if DNS in packet and packet[DNS].qd:
            domain = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
            if domain.endswith('.xyz') or domain.endswith('.top'):
                self.alert('SuspiciousDNS', packet[IP].src, domain, packet)
            if len(domain) > 50:
                self.alert('DNSTunnel', packet[IP].src, domain, packet)

    def packet_handler(self, packet):
        if IP not in packet:
            return
        self.check_blacklist(packet)
        self.check_signature(packet)
        self.check_anomaly(packet)
        self.check_port_scan(packet)
        self.check_syn_flood(packet)
        self.check_http(packet)
        self.check_payload_size(packet)
        self.check_ssh_bruteforce(packet)
        self.check_dns(packet)

    def start(self, interface=None, count=0, summary_interval=None):
        if summary_interval:
            t = threading.Thread(target=self.periodic_summary, args=(summary_interval,), daemon=True)
            t.start()
        sniff(iface=interface, prn=self.packet_handler, store=False, count=count)

    def periodic_summary(self, interval):
        while True:
            time.sleep(interval)
            cursor = self.db_conn.cursor()
            since = time.time() - interval
            cursor.execute('SELECT alert_type, COUNT(*) FROM alerts WHERE timestamp >= ? GROUP BY alert_type', (since,))
            rows = cursor.fetchall()
            print(f"\n--- Summary ({interval}s) ---")
            for alert_type, count in rows:
                print(f"{alert_type}: {count}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Advanced IDS with extended detection')
    parser.add_argument('-i', '--interface', default=None)
    parser.add_argument('-s', '--signatures')
    parser.add_argument('-b', '--blacklist')
    parser.add_argument('--threshold', type=int, default=50)
    parser.add_argument('--time-window', type=int, default=30)
    parser.add_argument('--port-threshold', type=int, default=10)
    parser.add_argument('--port-window', type=int, default=30)
    parser.add_argument('--syn-threshold', type=int, default=200)
    parser.add_argument('--syn-window', type=int, default=60)
    parser.add_argument('--http-threshold', type=int, default=20)
    parser.add_argument('--http-window', type=int, default=60)
    parser.add_argument('--payload-size', type=int, default=1024)
    parser.add_argument('--ssh-threshold', type=int, default=5)
    parser.add_argument('--ssh-window', type=int, default=300)
    parser.add_argument('--log-file', default='ids.log')
    parser.add_argument('--db-file', default='ids_alerts.db')
    parser.add_argument('--email-server')
    parser.add_argument('--email-port', type=int)
    parser.add_argument('--email-sender')
    parser.add_argument('--email-recipients', nargs='+')
    parser.add_argument('--email-user')
    parser.add_argument('--email-pass')
    parser.add_argument('--block', action='store_true', help='Block detected IPs via iptables')
    parser.add_argument('--summary-interval', type=int, help='Periodic summary interval (sec)')
    args = parser.parse_args()

    email_cfg = None
    if args.email_server and args.email_recipients and args.email_sender:
        email_cfg = {
            'server': args.email_server,
            'port': args.email_port,
            'sender': args.email_sender,
            'recipients': args.email_recipients,
            'username': args.email_user,
            'password': args.email_pass
        }

    ids = IDS(
        signature_file=args.signatures,
        blacklist_file=args.blacklist,
        threshold=args.threshold,
        time_window=args.time_window,
        port_threshold=args.port_threshold,
        port_time_window=args.port_window,
        syn_threshold=args.syn_threshold,
        syn_window=args.syn_window,
        http_threshold=args.http_threshold,
        http_time_window=args.http_window,
        payload_size_threshold=args.payload_size,
        ssh_threshold=args.ssh_threshold,
        ssh_time_window=args.ssh_window,
        log_file=args.log_file,
        db_file=args.db_file,
        email_config=email_cfg,
        block=args.block
    )
    print('Starting Advanced IDS...')
    ids.start(interface=args.interface, summary_interval=args.summary_interval)
