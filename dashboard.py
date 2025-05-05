from flask import Flask, render_template, jsonify, request
import json
import os
import datetime
import threading
import time
import sqlite3
import pandas as pd
import plotly
import plotly.express as px
import plotly.graph_objects as go

app = Flask(__name__)

# Base de données pour stocker les alertes de manière persistante
DB_FILE = "ids_alerts.db"

def init_db():
    """Initialise la base de données SQLite"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip TEXT,
        message TEXT,
        severity TEXT,
        acknowledged INTEGER DEFAULT 0
    )
    ''')
    conn.commit()
    conn.close()
    print("[DB] Base de données initialisée")

def get_alerts(limit=100, offset=0, severity=None, ip=None, acknowledged=None):
    """Récupère les alertes de la base de données avec filtrage"""
    conn = sqlite3.connect(DB_FILE)
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    
    if ip:
        query += " AND ip LIKE ?"
        params.append(f"%{ip}%")
    
    if acknowledged is not None:
        query += " AND acknowledged = ?"
        params.append(1 if acknowledged else 0)
    
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    df = pd.read_sql_query(query, conn, params=params)
    conn.close()
    return df

def add_alert(timestamp, ip, message, severity="MEDIUM"):
    """Ajoute une alerte à la base de données"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO alerts (timestamp, ip, message, severity) VALUES (?, ?, ?, ?)",
        (timestamp, ip, message, severity)
    )
    conn.commit()
    conn.close()

def acknowledge_alert(alert_id):
    """Marque une alerte comme traitée"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
    conn.commit()
    conn.close()

# Routes pour l'interface web
@app.route('/')
def index():
    """Page d'accueil du tableau de bord"""
    return render_template('dashboard.html')

@app.route('/api/alerts')
def api_alerts():
    """API pour récupérer les alertes"""
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    severity = request.args.get('severity', None)
    ip = request.args.get('ip', None)
    acknowledged = request.args.get('acknowledged', None)
    
    if acknowledged is not None:
        acknowledged = (acknowledged.lower() == 'true')
    
    df = get_alerts(limit, offset, severity, ip, acknowledged)
    return jsonify(df.to_dict(orient='records'))

@app.route('/api/stats')
def api_stats():
    """API pour les statistiques des alertes"""
    conn = sqlite3.connect(DB_FILE)
    
    # Statistiques par sévérité
    severity_stats = pd.read_sql_query(
        "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity",
        conn
    )
    
    # Statistiques par IP (top 10)
    ip_stats = pd.read_sql_query(
        "SELECT ip, COUNT(*) as count FROM alerts GROUP BY ip ORDER BY count DESC LIMIT 10",
        conn
    )
    
    # Statistiques temporelles (alertes par jour)
    time_stats = pd.read_sql_query(
        "SELECT date(timestamp) as date, COUNT(*) as count FROM alerts GROUP BY date(timestamp) ORDER BY date",
        conn
    )
    
    # Statistiques des alertes non traitées
    unack_stats = pd.read_sql_query(
        "SELECT COUNT(*) as count, severity FROM alerts WHERE acknowledged = 0 GROUP BY severity",
        conn
    )
    
    conn.close()
    
    return jsonify({
        'severity': severity_stats.to_dict(orient='records'),
        'ip': ip_stats.to_dict(orient='records'),
        'time': time_stats.to_dict(orient='records'),
        'unacknowledged': unack_stats.to_dict(orient='records')
    })

@app.route('/api/acknowledge/<int:alert_id>', methods=['POST'])
def api_acknowledge(alert_id):
    """API pour marquer une alerte comme traitée"""
    acknowledge_alert(alert_id)
    return jsonify({'status': 'success'})

@app.route('/api/alert', methods=['POST'])
def receive_alert():
    """Endpoint pour recevoir les alertes de l'agent IDS"""
    data = request.json
    timestamp = data.get('time', datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    ip = data.get('ip', 'unknown')
    message = data.get('alert', 'Unknown alert')
    severity = data.get('severity', 'MEDIUM')
    
    add_alert(timestamp, ip, message, severity)
    
    print(f"[{timestamp}] 🚨 ALERTE : {ip} → {message} ({severity})")
    return jsonify({"status": "ok"})

@app.route('/api/graphs/severity')
def graph_severity():
    """Génère un graphique de répartition des alertes par sévérité"""
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query(
        "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity",
        conn
    )
    conn.close()
    
    fig = px.pie(df, values='count', names='severity', 
                title='Répartition des alertes par sévérité',
                color_discrete_map={
                    'LOW': 'green',
                    'MEDIUM': 'orange',
                    'HIGH': 'red',
                    'CRITICAL': 'darkred'
                })
    
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

@app.route('/api/graphs/timeline')
def graph_timeline():
    """Génère un graphique d'évolution des alertes dans le temps"""
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query(
        "SELECT date(timestamp) as date, severity, COUNT(*) as count FROM alerts GROUP BY date(timestamp), severity ORDER BY date",
        conn
    )
    conn.close()
    
    fig = px.line(df, x='date', y='count', color='severity',
                 title='Évolution des alertes dans le temps',
                 color_discrete_map={
                     'LOW': 'green',
                     'MEDIUM': 'orange',
                     'HIGH': 'red',
                     'CRITICAL': 'darkred'
                 })
    
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

# Initialisation de la base de données au démarrage
init_db()

if __name__ == "__main__":
    print("[DASHBOARD] Tableau de bord en écoute sur http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=True)
