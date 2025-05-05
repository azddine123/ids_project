import scapy.all as scapy
import numpy as np
from collections import defaultdict, deque
import time
import json
import pickle
import os
from sklearn.ensemble import IsolationForest

class AdvancedDetection:
    def __init__(self, history_size=1000, anomaly_threshold=0.8):
        self.history_size = history_size
        self.anomaly_threshold = anomaly_threshold
        
        # Historique du trafic pour l'analyse statistique
        self.packet_history = deque(maxlen=history_size)
        
        # Compteurs pour différentes métriques
        self.ip_connections = defaultdict(set)  # IP source -> ensemble d'IPs destinations
        self.port_scan_counter = defaultdict(lambda: defaultdict(int))  # IP -> {port -> count}
        self.protocol_counter = defaultdict(lambda: defaultdict(int))  # IP -> {proto -> count}
        self.packet_size_stats = defaultdict(list)  # IP -> [tailles des paquets]
        
        # Modèle d'apprentissage automatique
        self.model = None
        self.load_or_create_model()
        
        # Signatures avancées (comportements)
        self.load_advanced_signatures()
    
    def load_advanced_signatures(self):
        try:
            with open("advanced_signatures.json", "r") as f:
                self.advanced_signatures = json.load(f)
        except FileNotFoundError:
            self.advanced_signatures = {
                "port_scan": {"threshold": 15, "time_window": 5},
                "ddos": {"pps_threshold": 50, "time_window": 3},
                "bruteforce": {"attempts_threshold": 5, "time_window": 60, "ports": [22, 23, 3389]}
            }
            # Sauvegarder les signatures par défaut
            with open("advanced_signatures.json", "w") as f:
                json.dump(self.advanced_signatures, f, indent=2)
    
    def load_or_create_model(self):
        try:
            with open("ids_model.pkl", "rb") as f:
                self.model = pickle.load(f)
            print("[ML] Modèle de détection chargé")
        except FileNotFoundError:
            # Créer un modèle par défaut
            self.model = IsolationForest(contamination=0.05)
            print("[ML] Nouveau modèle de détection créé")
    
    def save_model(self):
        with open("ids_model.pkl", "wb") as f:
            pickle.dump(self.model, f)
        print("[ML] Modèle de détection sauvegardé")
    
    def extract_features(self, pkt):
        """Extrait les caractéristiques d'un paquet pour l'analyse"""
        features = {
            "size": len(pkt),
            "has_tcp": 1 if pkt.haslayer(scapy.TCP) else 0,
            "has_udp": 1 if pkt.haslayer(scapy.UDP) else 0,
            "has_icmp": 1 if pkt.haslayer(scapy.ICMP) else 0,
            "tcp_flags": pkt[scapy.TCP].flags if pkt.haslayer(scapy.TCP) else 0,
            "ttl": pkt[scapy.IP].ttl if pkt.haslayer(scapy.IP) else 0,
            "src_port": pkt.sport if hasattr(pkt, 'sport') else 0,
            "dst_port": pkt.dport if hasattr(pkt, 'dport') else 0
        }
        return features
    
    def update_statistics(self, pkt):
        """Met à jour les statistiques de trafic basées sur le paquet"""
        if pkt.haslayer(scapy.IP):
            src_ip = pkt[scapy.IP].src
            dst_ip = pkt[scapy.IP].dst
            
            # Mise à jour des connexions
            self.ip_connections[src_ip].add(dst_ip)
            
            # Mise à jour des tailles de paquets
            self.packet_size_stats[src_ip].append(len(pkt))
            if len(self.packet_size_stats[src_ip]) > 100:  # Limiter la taille
                self.packet_size_stats[src_ip] = self.packet_size_stats[src_ip][-100:]
            
            # Mise à jour des protocoles
            if pkt.haslayer(scapy.TCP):
                self.protocol_counter[src_ip]["TCP"] += 1
                dst_port = pkt[scapy.TCP].dport
                self.port_scan_counter[src_ip][dst_port] += 1
            elif pkt.haslayer(scapy.UDP):
                self.protocol_counter[src_ip]["UDP"] += 1
                dst_port = pkt[scapy.UDP].dport
                self.port_scan_counter[src_ip][dst_port] += 1
            elif pkt.haslayer(scapy.ICMP):
                self.protocol_counter[src_ip]["ICMP"] += 1
            
            # Ajouter le paquet à l'historique
            features = self.extract_features(pkt)
            self.packet_history.append((time.time(), src_ip, features))
    
    def detect_port_scan(self, ip):
        """Détecte un scan de ports basé sur le nombre de ports uniques contactés"""
        sig = self.advanced_signatures["port_scan"]
        threshold = sig["threshold"]
        time_window = sig["time_window"]
        
        current_time = time.time()
        recent_ports = set()
        
        for t, src, _ in self.packet_history:
            if src == ip and current_time - t <= time_window:
                if hasattr(src, 'dport'):
                    recent_ports.add(src.dport)
        
        return len(recent_ports) >= threshold
    
    def detect_ddos(self, ip):
        """Détecte une attaque DDoS basée sur le taux de paquets par seconde"""
        sig = self.advanced_signatures["ddos"]
        pps_threshold = sig["pps_threshold"]
        time_window = sig["time_window"]
        
        current_time = time.time()
        packet_count = 0
        
        for t, src, _ in self.packet_history:
            if src == ip and current_time - t <= time_window:
                packet_count += 1
        
        pps = packet_count / time_window
        return pps >= pps_threshold
    
    def detect_bruteforce(self, ip):
        """Détecte une tentative de brute force sur des ports sensibles"""
        sig = self.advanced_signatures["bruteforce"]
        threshold = sig["attempts_threshold"]
        time_window = sig["time_window"]
        sensitive_ports = sig["ports"]
        
        current_time = time.time()
        attempts = defaultdict(int)
        
        for t, src, features in self.packet_history:
            if src == ip and current_time - t <= time_window:
                if features["dst_port"] in sensitive_ports:
                    attempts[features["dst_port"]] += 1
        
        for port, count in attempts.items():
            if count >= threshold:
                return True, port
        
        return False, None
    
    def detect_anomaly_ml(self, pkt):
        """Utilise le modèle ML pour détecter des anomalies"""
        if not pkt.haslayer(scapy.IP):
            return False
            
        features = self.extract_features(pkt)
        # Convertir en tableau numpy pour le modèle
        feature_vector = np.array([[
            features["size"], 
            features["has_tcp"], 
            features["has_udp"], 
            features["has_icmp"],
            features["ttl"],
            features["src_port"],
            features["dst_port"]
        ]])
        
        # Prédiction (-1 pour anomalie, 1 pour normal)
        try:
            prediction = self.model.predict(feature_vector)
            return prediction[0] == -1
        except:
            # Si le modèle n'est pas encore entraîné
            return False
    
    def train_model(self):
        """Entraîne le modèle sur les données collectées"""
        if len(self.packet_history) < 100:
            print("[ML] Pas assez de données pour entraîner le modèle")
            return False
            
        print("[ML] Entraînement du modèle...")
        features = []
        
        for _, _, feature_dict in self.packet_history:
            feature_vector = [
                feature_dict["size"],
                feature_dict["has_tcp"],
                feature_dict["has_udp"],
                feature_dict["has_icmp"],
                feature_dict["ttl"],
                feature_dict["src_port"],
                feature_dict["dst_port"]
            ]
            features.append(feature_vector)
            
        X = np.array(features)
        self.model.fit(X)
        self.save_model()
        print(f"[ML] Modèle entraîné sur {len(features)} échantillons")
        return True
    
    def analyze_packet(self, pkt):
        """Analyse complète d'un paquet et retourne les alertes détectées"""
        if not pkt.haslayer(scapy.IP):
            return []
            
        src_ip = pkt[scapy.IP].src
        alerts = []
        
        # Mettre à jour les statistiques
        self.update_statistics(pkt)
        
        # 1. Détection par ML
        if self.detect_anomaly_ml(pkt):
            alerts.append(("Anomalie détectée par ML", "MEDIUM"))
        
        # 2. Détection de scan de ports
        if self.detect_port_scan(src_ip):
            alerts.append(("Scan de ports détecté", "HIGH"))
        
        # 3. Détection de DDoS
        if self.detect_ddos(src_ip):
            alerts.append(("Possible attaque DDoS", "CRITICAL"))
        
        # 4. Détection de brute force
        is_bruteforce, port = self.detect_bruteforce(src_ip)
        if is_bruteforce:
            alerts.append((f"Tentative de brute force sur le port {port}", "HIGH"))
        
        # 5. Analyse statistique des tailles de paquets
        if len(self.packet_size_stats[src_ip]) > 10:
            avg_size = np.mean(self.packet_size_stats[src_ip])
            std_size = np.std(self.packet_size_stats[src_ip])
            current_size = len(pkt)
            
            # Si la taille actuelle est très différente de la moyenne
            if abs(current_size - avg_size) > 3 * std_size:
                alerts.append(("Taille de paquet anormale", "LOW"))
        
        # Entraîner le modèle périodiquement
        if len(self.packet_history) % 500 == 0 and len(self.packet_history) > 0:
            self.train_model()
            
        return alerts
