import psutil
import time
import hashlib
import os
import json
from datetime import datetime

LOG_FILE = "../logs/security_log.json"

# 🎯 Processos que realmente parecem malware simples
SUSPICIOUS_PREFIXES = [
    "keylogger",
    "injector",
    "payload",
    "backdoor"
]

SAFE_PROCESSES = [
    "systemd",
    "gnome-keyring",
    "login",
    "sshd",
    "bash",
    "python"
]

seen_processes = set()


def calculate_hash(filepath):
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None


def log_event(event_type, process=None, destination=None, risk="low"):
    event = {
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "process": process,
        "destination": destination,
        "risk_level": risk
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")


print("🔎 Monitor de Segurança iniciado...\n")

while True:
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'].lower()

            # 🔥 Regra refinada: verificar se começa com prefixo suspeito
            if any(name.startswith(prefix) for prefix in SUSPICIOUS_PREFIXES):
                if not any(safe in name for safe in SAFE_PROCESSES):

                    if proc.info["pid"] not in seen_processes:
                        seen_processes.add(proc.info["pid"])

                        print(f"⚠ Processo altamente suspeito: {proc.info}")

                        log_event(
                            event_type="suspicious_process",
                            process=proc.info["name"],
                            risk="high"
                        )

            # 🌐 Conexões de rede
            connections = proc.net_connections(kind='inet')
            for conn in connections:
                if conn.status == "ESTABLISHED" and conn.raddr:

                    log_event(
                        event_type="network_connection",
                        process=proc.info['name'],
                        destination=str(conn.raddr),
                        risk="medium"
                    )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # 📁 Arquivo suspeito
    if os.path.exists("../logs/temp_data.txt"):
        file_hash = calculate_hash("../logs/temp_data.txt")

        log_event(
            event_type="file_detected",
            process="file_monitor",
            destination=file_hash,
            risk="medium"
        )

    time.sleep(5)