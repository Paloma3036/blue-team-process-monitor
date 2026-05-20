import os
import json
import time
import hashlib
import shutil
from datetime import datetime
import psutil

# Caminhos de diretórios e arquivos
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../logs"))
QUARANTINE_DIR = os.path.join(LOG_DIR, "quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "security_log.json")
TEMP_DATA_FILE = os.path.join(LOG_DIR, "temp_data.txt")

SUSPICIOUS_PREFIXES = ["keylogger", "injector", "payload", "backdoor"]
SAFE_PROCESSES = ["systemd", "gnome-keyring", "login", "sshd", "bash", "python"]

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

def quarantine_file(filepath):
    """Move o arquivo suspeito para a pasta de quarentena e altera sua extensão."""
    if not os.path.exists(filepath):
        return None
    
    file_hash = calculate_hash(filepath)
    if not file_hash:
        return None

    # Define o novo nome usando o hash para evitar colisões e desarmar o arquivo
    filename = f"malware_{file_hash[:10]}.quarantine"
    destination = os.path.join(QUARANTINE_DIR, filename)
    
    try:
        shutil.move(filepath, destination)
        print(f"🔒 ARQUIVO EM QUARENTENA: {filepath} -> {destination}")
        return file_hash
    except Exception as e:
        print(f"❌ Falha ao mover arquivo para quarentena: {e}")
        return None

print("🛡️ Monitor & Defesa Ativa Blue Team iniciado...\n")

while True:
    # 1. Varredura e Remediação de Processos e Redes
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            pid = proc.info['pid']
            name = proc.info['name'].lower() if proc.info['name'] else ""
            cmdline_list = proc.info['cmdline'] or []
            cmdline_str = " ".join(cmdline_list).lower()

            is_suspicious = False

            if any(prefix in name for prefix in SUSPICIOUS_PREFIXES):
                is_suspicious = True

            if "python" in name and any(prefix in cmdline_str for prefix in SUSPICIOUS_PREFIXES):
                is_suspicious = True

            if is_suspicious:
                if not any(safe in name for safe in SAFE_PROCESSES) or ("python" in name and any(prefix in cmdline_str for prefix in SUSPICIOUS_PREFIXES)):
                    
                    process_display_name = cmdline_str if cmdline_str else name
                    
                    if pid not in seen_processes:
                        seen_processes.add(pid)
                        print(f"⚠ AMEAÇA DETECTADA: {process_display_name} (PID: {pid})")
                        log_event(
                            event_type="suspicious_process_detected",
                            process=process_display_name,
                            risk="high"
                        )
                        
                        # 🔥 REMEDIAÇÃO ATIVA: Finaliza o processo malicioso imediatamente
                        try:
                            proc.kill()
                            print(f"💥 REMEDIAÇÃO: Processo {pid} finalizado com sucesso (KILL).")
                            log_event(
                                event_type="process_remediation_success",
                                process=process_display_name,
                                risk="low"
                            )
                        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                            print(f"❌ Falha ao finalizar o processo {pid}: {e}")
                            log_event(
                                event_type="process_remediation_failed",
                                process=process_display_name,
                                risk="high"
                            )

            # Verificação de conexões de rede ativas (Apenas logs)
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

    # 2. Monitoramento e Isolamento de Arquivos
    if os.path.exists(TEMP_DATA_FILE):
        file_hash = calculate_hash(TEMP_DATA_FILE)
        if file_hash and file_hash not in seen_files:
            seen_files.add(file_hash)
            log_event(
                event_type="file_incident_detected",
                process="file_monitor",
                destination=file_hash,
                risk="medium"
            )
            # 🔥 QUARENTENA ATIVA: Isola o arquivo do sistema
            quarantine_file(TEMP_DATA_FILE)

    time.sleep(2)  # Reduzido para 2 segundos para respostas mais rápidas contra ameaças

# Atualizado em 2026-05-19.