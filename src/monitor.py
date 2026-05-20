import os
import json
import time
import hashlib
from datetime import datetime
import psutil

# Garante que a pasta de logs exista no caminho correto
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../logs"))
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "security_log.json")
TEMP_DATA_FILE = os.path.join(LOG_DIR, "temp_data.txt")

SUSPICIOUS_PREFIXES = ["keylogger", "injector", "payload", "backdoor"]
SAFE_PROCESSES = ["systemd", "gnome-keyring", "login", "sshd", "bash", "python"]

# Caches para evitar duplicidade exaustiva de logs
seen_processes = set()
seen_connections = set()
seen_files = set()

def calculate_hash(filepath):
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def log_event(event_type, process=None, destination=None, risk="low"):
    event = {
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "process": process,
        "destination": destination,
        "risk_level": risk
    }
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")
    except IOError as e:
        print(f"❌ Erro ao escrever no log: {e}")

print("🔎 Monitor de Segurança Blue Team iniciado...\n")

while True:
    # 1. Varredura de Processos e Redes (Inspecionando cmdline)
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            pid = proc.info['pid']
            name = proc.info['name'].lower() if proc.info['name'] else ""
            
            # Pega os argumentos do comando executado (ex: ['python', 'src/keylogger_process.py'])
            cmdline_list = proc.info['cmdline'] or []
            cmdline_str = " ".join(cmdline_list).lower()

            is_suspicious = False

            # Regra 1: Verifica se o nome do executável principal é suspeito
            if any(prefix in name for prefix in SUSPICIOUS_PREFIXES):
                is_suspicious = True

            # Regra 2: Se for o interpretador python, checa se o script chamado é suspeito
            if "python" in name and any(prefix in cmdline_str for prefix in SUSPICIOUS_PREFIXES):
                is_suspicious = True

            # Validação do processo suspeito encontrado
            if is_suspicious:
                # Alerta se não estiver na lista segura OU se for um script python suspeito explicitamente
                if not any(safe in name for safe in SAFE_PROCESSES) or ("python" in name and any(prefix in cmdline_str for prefix in SUSPICIOUS_PREFIXES)):
                    
                    if pid not in seen_processes:
                        seen_processes.add(pid)
                        process_display_name = cmdline_str if cmdline_str else name
                        
                        print(f"⚠ Processo altamente suspeito detectado: {process_display_name} (PID: {pid})")
                        log_event(
                            event_type="suspicious_process",
                            process=process_display_name,
                            risk="high"
                        )

            # Verificação de conexões de rede ativas
            connections = proc.net_connections(kind='inet')
            for conn in connections:
                if conn.status == "ESTABLISHED" and conn.raddr:
                    conn_signature = f"{pid}-{conn.raddr.ip}-{conn.raddr.port}"
                    if conn_signature not in seen_connections:
                        seen_connections.add(conn_signature)
                        log_event(
                            event_type="network_connection",
                            process=name,
                            destination=f"{conn.raddr.ip}:{conn.raddr.port}",
                            risk="medium"
                        )

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    # 2. Monitoramento de Arquivos Suspeitos
    if os.path.exists(TEMP_DATA_FILE):
        file_hash = calculate_hash(TEMP_DATA_FILE)
        if file_hash and file_hash not in seen_files:
            seen_files.add(file_hash)
            print(f"📁 Arquivo suspeito modificado/detectado. Hash: {file_hash}")
            log_event(
                event_type="file_detected",
                process="file_monitor",
                destination=file_hash,
                risk="medium"
            )

    time.sleep(5)

# Atualizado em 2026-05-19.