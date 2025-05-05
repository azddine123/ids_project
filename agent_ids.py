import scapy.all as scapy
from collections import defaultdict
import requests
import json
import time

# Chargement des signatures
with open("signatures.json") as f:
    SIGNATURES = json.load(f)

ALERT_SERVER = "http://localhost:5000/api/alert"

traffic_counter = defaultdict(int)
last_sent = {}

def send_alert(ip, msg):
    now = time.time()
    if last_sent.get(ip, 0) + 60 < now:  # éviter spam
        alert = {"ip": ip, "alert": msg, "time": time.strftime("%Y-%m-%d %H:%M:%S")}
        try:
            requests.post(ALERT_SERVER, json=alert)
            print(f"[ALERTE] {ip} → {msg}")
            last_sent[ip] = now
        except Exception as e:
            print("Erreur d'envoi:", e)

def match_signature(pkt):
    for sig in SIGNATURES:
        if pkt.haslayer(scapy.TCP):
            if pkt[scapy.TCP].flags == sig["flags"] and pkt[scapy.TCP].dport in sig["dport"]:
                return sig["name"]
    return None

def process(pkt):
    if pkt.haslayer(scapy.IP):
        src_ip = pkt[scapy.IP].src
        traffic_counter[src_ip] += 1

        # Règle 1 : trafic excessif
        if traffic_counter[src_ip] > 100:
            send_alert(src_ip, "Trafic excessif détecté")

        # Règle 2 : détection par signature
        matched = match_signature(pkt)
        if matched:
            send_alert(src_ip, f"Signature détectée : {matched}")

print("[IDS] Démarrage de l'agent IDS...")

scapy.sniff(prn=process, store=0)
