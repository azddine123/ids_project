import scapy.all as scapy
from collections import defaultdict
import requests
import json
import time
import threading
import logging
import os
import sys
from advanced_detection import AdvancedDetection

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ids.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("EnhancedIDS")

# Chargement des signatures
try:
    with open("advanced_signatures.json") as f:
        SIGNATURES = json.load(f)
    logger.info(f"Chargement de {len(SIGNATURES)} signatures avancées")
except FileNotFoundError:
    logger.warning("Fichier de signatures avancées non trouvé, utilisation des signatures de base")
    with open("signatures.json") as f:
        SIGNATURES = json.load(f)

# Configuration
CONFIG = {
    "alert_server": "http://localhost:5000/api/alert",
    "dashboard_server": "http://localhost:5001/api/alert",
    "traffic_threshold": 100,
    "packet_history_size": 1000,
    "ml_enabled": True,
    "interface": None,  # None = toutes les interfaces
    "log_packets": True,
    "save_pcap": True,
    "pcap_rotate_size": 100 * 1024 * 1024,  # 100 MB
    "pcap_dir": "pcaps"
}

# Création du dossier pour les pcaps si nécessaire
if CONFIG["save_pcap"] and not os.path.exists(CONFIG["pcap_dir"]):
    os.makedirs(CONFIG["pcap_dir"])
    logger.info(f"Dossier {CONFIG['pcap_dir']} créé pour les captures pcap")

# Variables globales
traffic_counter = defaultdict(int)
last_sent = {}
packet_writer = None
current_pcap_size = 0
pcap_file = None

# Initialisation du système de détection avancé
advanced_detection = AdvancedDetection(
    history_size=CONFIG["packet_history_size"],
    anomaly_threshold=0.8
)

def rotate_pcap_if_needed():
    """Rotation du fichier pcap si nécessaire"""
    global packet_writer, current_pcap_size, pcap_file
    
    if CONFIG["save_pcap"]:
        if packet_writer is None or current_pcap_size >= CONFIG["pcap_rotate_size"]:
            if packet_writer:
                packet_writer.close()
                logger.info(f"Fermeture du fichier pcap {pcap_file}")
            
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            pcap_file = os.path.join(CONFIG["pcap_dir"], f"ids-capture-{timestamp}.pcap")
            packet_writer = scapy.PcapWriter(pcap_file, append=True, sync=True)
            current_pcap_size = 0
            logger.info(f"Nouveau fichier pcap créé: {pcap_file}")

def send_alert(ip, msg, severity="MEDIUM"):
    """Envoie une alerte aux serveurs configurés"""
    now = time.time()
    # Éviter le spam en limitant les alertes pour une même IP
    if last_sent.get(ip, 0) + 60 < now:
        alert = {
            "ip": ip,
            "alert": msg,
            "severity": severity,
            "time": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Envoi au serveur d'alertes principal
        try:
            requests.post(CONFIG["alert_server"], json=alert)
            logger.info(f"[ALERTE] {ip} → {msg} ({severity})")
            last_sent[ip] = now
        except Exception as e:
            logger.error(f"Erreur d'envoi au serveur d'alertes: {e}")
        
        # Envoi au tableau de bord
        try:
            requests.post(CONFIG["dashboard_server"], json=alert)
        except Exception as e:
            logger.error(f"Erreur d'envoi au tableau de bord: {e}")

def match_signature(pkt):
    """Vérifie si un paquet correspond à une signature connue"""
    for sig in SIGNATURES:
        # Vérification TCP
        if sig.get("proto") == "TCP" and pkt.haslayer(scapy.TCP):
            if (not sig.get("flags") or pkt[scapy.TCP].flags == sig["flags"]) and \
               (not sig.get("dport") or pkt[scapy.TCP].dport in sig["dport"]):
                return sig["name"], sig.get("severity", "MEDIUM")
        
        # Vérification UDP
        elif sig.get("proto") == "UDP" and pkt.haslayer(scapy.UDP):
            if not sig.get("dport") or pkt[scapy.UDP].dport in sig["dport"]:
                return sig["name"], sig.get("severity", "MEDIUM")
        
        # Vérification ICMP
        elif sig.get("proto") == "ICMP" and pkt.haslayer(scapy.ICMP):
            return sig["name"], sig.get("severity", "MEDIUM")
    
    return None, None

def process(pkt):
    """Traite un paquet réseau capturé"""
    # Enregistrement du paquet si activé
    if CONFIG["save_pcap"]:
        rotate_pcap_if_needed()
        global current_pcap_size
        packet_size = len(pkt)
        current_pcap_size += packet_size
        packet_writer.write(pkt)
    
    # Journalisation des paquets si activée
    if CONFIG["log_packets"] and pkt.haslayer(scapy.IP):
        src_ip = pkt[scapy.IP].src
        dst_ip = pkt[scapy.IP].dst
        proto = "TCP" if pkt.haslayer(scapy.TCP) else "UDP" if pkt.haslayer(scapy.UDP) else "ICMP" if pkt.haslayer(scapy.ICMP) else "Autre"
        logger.debug(f"Paquet: {src_ip} → {dst_ip} ({proto}, {len(pkt)} octets)")
    
    # Analyse du paquet
    if pkt.haslayer(scapy.IP):
        src_ip = pkt[scapy.IP].src
        traffic_counter[src_ip] += 1
        
        # 1. Détection basée sur le volume de trafic
        if traffic_counter[src_ip] > CONFIG["traffic_threshold"]:
            send_alert(src_ip, "Trafic excessif détecté", "MEDIUM")
            # Réinitialiser le compteur pour éviter des alertes répétées
            traffic_counter[src_ip] = 0
        
        # 2. Détection basée sur les signatures
        sig_name, severity = match_signature(pkt)
        if sig_name:
            send_alert(src_ip, f"Signature détectée : {sig_name}", severity)
        
        # 3. Détection avancée avec ML et analyse comportementale
        if CONFIG["ml_enabled"]:
            alerts = advanced_detection.analyze_packet(pkt)
            for alert_msg, alert_severity in alerts:
                send_alert(src_ip, alert_msg, alert_severity)

def start_periodic_training():
    """Démarre l'entraînement périodique du modèle ML"""
    if CONFIG["ml_enabled"]:
        logger.info("Démarrage de l'entraînement périodique du modèle ML")
        
        def train_periodically():
            while True:
                time.sleep(3600)  # Entraînement toutes les heures
                logger.info("Entraînement périodique du modèle ML")
                advanced_detection.train_model()
        
        training_thread = threading.Thread(target=train_periodically, daemon=True)
        training_thread.start()

def start_ids():
    """Démarre l'agent IDS"""
    logger.info("=== Démarrage de l'agent IDS Avancé ===")
    logger.info(f"Configuration: {CONFIG}")
    
    # Démarrer l'entraînement périodique
    if CONFIG["ml_enabled"]:
        start_periodic_training()
    
    try:
        # Démarrer la capture de paquets
        logger.info(f"Démarrage de la capture sur l'interface: {CONFIG['interface'] or 'toutes'}")
        scapy.sniff(iface=CONFIG["interface"], prn=process, store=0)
    except KeyboardInterrupt:
        logger.info("Arrêt de l'agent IDS (Ctrl+C)")
    except Exception as e:
        logger.error(f"Erreur lors de la capture: {e}")
    finally:
        if packet_writer:
            packet_writer.close()
            logger.info("Fichier pcap fermé")

if __name__ == "__main__":
    start_ids()
