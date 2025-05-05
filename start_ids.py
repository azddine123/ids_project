import os
import sys
import subprocess
import time
import argparse
import threading
import webbrowser

def parse_arguments():
    parser = argparse.ArgumentParser(description="Démarrer le système IDS avancé")
    parser.add_argument("--no-dashboard", action="store_true", help="Ne pas démarrer le tableau de bord")
    parser.add_argument("--no-server", action="store_true", help="Ne pas démarrer le serveur d'alertes")
    parser.add_argument("--basic", action="store_true", help="Utiliser l'agent IDS de base au lieu de la version avancée")
    parser.add_argument("--open-browser", action="store_true", help="Ouvrir automatiquement le tableau de bord dans le navigateur")
    return parser.parse_args()

def start_server():
    print("[Démarrage] Serveur d'alertes...")
    return subprocess.Popen([sys.executable, "server_flask.py"], 
                           stdout=subprocess.PIPE, 
                           stderr=subprocess.PIPE)

def start_dashboard():
    print("[Démarrage] Tableau de bord...")
    return subprocess.Popen([sys.executable, "dashboard.py"], 
                           stdout=subprocess.PIPE, 
                           stderr=subprocess.PIPE)

def start_ids(basic=False):
    print(f"[Démarrage] Agent IDS {'basique' if basic else 'avancé'}...")
    script = "agent_ids.py" if basic else "enhanced_ids.py"
    return subprocess.Popen([sys.executable, script], 
                           stdout=subprocess.PIPE, 
                           stderr=subprocess.PIPE)

def monitor_process(process, name):
    """Surveille un processus et affiche sa sortie standard et d'erreur"""
    def read_output(stream, prefix):
        for line in iter(stream.readline, b''):
            print(f"{prefix}: {line.decode('utf-8', errors='replace').strip()}")
    
    # Créer des threads pour lire stdout et stderr
    stdout_thread = threading.Thread(target=read_output, args=(process.stdout, f"[{name}]"))
    stderr_thread = threading.Thread(target=read_output, args=(process.stderr, f"[{name} ERROR]"))
    
    # Démarrer les threads
    stdout_thread.daemon = True
    stderr_thread.daemon = True
    stdout_thread.start()
    stderr_thread.start()

def check_requirements():
    """Vérifie si toutes les dépendances sont installées"""
    try:
        import scapy
        import flask
        import requests
        import numpy
        import pandas
        import sklearn
        import plotly
        return True
    except ImportError as e:
        print(f"[ERREUR] Dépendance manquante: {e}")
        print("Veuillez installer les dépendances avec: pip install -r requirements.txt")
        return False

def check_files():
    """Vérifie si tous les fichiers nécessaires sont présents"""
    required_files = {
        "agent_ids.py": "Agent IDS de base",
        "enhanced_ids.py": "Agent IDS avancé",
        "server_flask.py": "Serveur d'alertes",
        "dashboard.py": "Tableau de bord",
        "advanced_detection.py": "Module de détection avancée",
        "signatures.json": "Signatures de base",
        "advanced_signatures.json": "Signatures avancées"
    }
    
    missing = []
    for file, description in required_files.items():
        if not os.path.exists(file):
            missing.append(f"- {file} ({description})")
    
    if missing:
        print("[ERREUR] Fichiers manquants:")
        for item in missing:
            print(item)
        return False
    
    return True

def main():
    args = parse_arguments()
    
    print("=== Système IDS Avancé ===")
    print("Vérification de l'environnement...")
    
    # Vérifier les dépendances et les fichiers
    if not check_requirements() or not check_files():
        print("[ERREUR] Configuration incomplète. Arrêt du démarrage.")
        return
    
    processes = []
    
    try:
        # Démarrer le serveur d'alertes
        if not args.no_server:
            server_process = start_server()
            processes.append((server_process, "Serveur"))
            monitor_process(server_process, "Serveur")
            time.sleep(2)  # Attendre que le serveur démarre
        
        # Démarrer le tableau de bord
        if not args.no_dashboard:
            dashboard_process = start_dashboard()
            processes.append((dashboard_process, "Dashboard"))
            monitor_process(dashboard_process, "Dashboard")
            time.sleep(2)  # Attendre que le tableau de bord démarre
            
            # Ouvrir le navigateur si demandé
            if args.open_browser:
                print("[INFO] Ouverture du tableau de bord dans le navigateur...")
                webbrowser.open("http://localhost:5001")
        
        # Démarrer l'agent IDS
        ids_process = start_ids(args.basic)
        processes.append((ids_process, "IDS"))
        monitor_process(ids_process, "IDS")
        
        print("\n[INFO] Système IDS démarré avec succès!")
        print("Appuyez sur Ctrl+C pour arrêter tous les services.")
        
        # Maintenir le script en vie
        while True:
            time.sleep(1)
            
            # Vérifier si tous les processus sont toujours en cours d'exécution
            for process, name in processes:
                if process.poll() is not None:
                    print(f"[ERREUR] Le processus {name} s'est arrêté de manière inattendue (code: {process.returncode})")
                    # Vous pouvez choisir de redémarrer le processus ici
        
    except KeyboardInterrupt:
        print("\n[INFO] Arrêt du système IDS...")
        for process, name in processes:
            print(f"[INFO] Arrêt de {name}...")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print(f"[ATTENTION] {name} ne répond pas, forçage de l'arrêt...")
                process.kill()
        print("[INFO] Tous les services ont été arrêtés.")

if __name__ == "__main__":
    main()
