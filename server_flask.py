from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)
alerts = []

@app.route("/api/alert", methods=["POST"])
def receive_alert():
    data = request.json
    alerts.append(data)
    print(f"[{data['time']}] 🚨 ALERTE : {data['ip']} → {data['alert']}")
    return jsonify({"status": "ok"})

@app.route("/alerts", methods=["GET"])
def get_alerts():
    return jsonify(alerts)

if __name__ == "__main__":
    print("[FLASK] Serveur d'alertes en écoute sur http://localhost:5000")
    app.run(host="0.0.0.0", port=5000)
