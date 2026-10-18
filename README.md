# Python Network IDS

**A lightweight intrusion detection system: live packet capture, signature rules,
behavioural detection and an Isolation Forest anomaly model, with a web dashboard for alerts.**

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.5-1f425f?style=flat-square)
![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=flat-square&logo=scikitlearn&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=flat-square&logo=flask&logoColor=white)
![Plotly](https://img.shields.io/badge/Plotly-3F4F75?style=flat-square&logo=plotly&logoColor=white)

---

## What it detects

| Layer | Technique | Examples |
|---|---|---|
| **Signatures** | TCP flag / port / threshold rules in [`advanced_signatures.json`](advanced_signatures.json) | Nmap SYN scan, SYN-FIN, Xmas and NULL scans, SSH / FTP / RDP brute force, SMB scan, ICMP flood, DNS amplification |
| **Behaviour** | Sliding time windows per source IP | Port scans (unique ports contacted), DDoS (packets per second), brute force (connection bursts) |
| **Machine learning** | `IsolationForest` trained on live traffic features, retrained periodically | Unusual packets that match no rule |

Every alert carries a **severity** (MEDIUM / HIGH / CRITICAL), is stored in SQLite and shown on the dashboard.
Captured traffic is also written to rotating `.pcap` files for later forensics.

## Architecture

```
 network interface
        │  (Scapy sniffing)
        ▼
 ┌─────────────────────┐   POST /api/alert   ┌────────────────────────────┐
 │  IDS agent          │ ──────────────────► │  Dashboard (Flask :5001)   │
 │  enhanced_ids.py    │                     │  SQLite alerts · Plotly    │
 │  + advanced_        │                     │  stats · acknowledge       │
 │    detection.py     │ ───────┐            └────────────────────────────┘
 └─────────────────────┘        │ POST /api/alert
        │                       ▼
        ▼               Alert server (Flask :5000)
   pcaps/ (rotating captures)
```

| File | Role |
|---|---|
| `start_ids.py` | One-command launcher: checks dependencies, starts the dashboard, alert server and agent |
| `enhanced_ids.py` | Advanced agent: signatures + behaviour + ML, pcap rotation |
| `advanced_detection.py` | Detection engine (port scan, DDoS, brute force, Isolation Forest) |
| `agent_ids.py` / `server_flask.py` | Minimal first version (signatures + simple alert server) |
| `dashboard.py` + `templates/` | Web dashboard: alert list, filters, severity charts, acknowledgement |
| `rapport.tex` | Project report (French, LaTeX) |

## Run it

```bash
pip install -r requirements.txt

# packet capture needs root privileges
sudo python start_ids.py --open-browser      # dashboard on http://localhost:5001
sudo python start_ids.py --basic             # minimal agent only
```

Options: `--no-dashboard`, `--no-server`, `--basic`, `--open-browser`.

Test it from another machine on the lab network, for example `nmap -sS <target>` or `nmap -sX <target>`.

> ⚠️ Only run captures and scans on networks you own or are authorised to test.

## Next steps

- Export alerts to a SIEM (ELK / Wazuh) in a standard format
- Map signatures to MITRE ATT&CK techniques
- Evaluate the anomaly model on a labelled dataset (CIC-IDS2017)

---

Built by **Azddine El Hamdaoui** · AI & Cybersecurity engineering student, ENSA Béni Mellal
