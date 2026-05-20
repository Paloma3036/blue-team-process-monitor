import os
import json
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "../logs/security_log.json")

event_counter = Counter()
risk_counter = Counter()
total_events = 0
remediations = 0

if not os.path.exists(LOG_FILE):
    print(f"❌ Arquivo de log não encontrado em: {LOG_FILE}")
    exit()

try:
    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                e_type = event.get("event_type", "unknown")
                event_counter[e_type] += 1
                risk_counter[event.get("risk_level", "low")] += 1
                total_events += 1
                
                if "remediation_success" in e_type:
                    remediations += 1
            except json.JSONDecodeError:
                continue
except Exception as e:
    print(f"❌ Erro ao ler o arquivo: {e}")
    exit()

print("\n📊 DASHBOARD DE DEFESA ATIVA (EDR)\n")
print(f"Total de eventos processados: {total_events}")
print(f"🛡️ Total de ameaças bloqueadas automaticamente: {remediations}\n")

print("Eventos por categoria:")
for event_type, count in event_counter.items():
    print(f" - {event_type}: {count}")

print("\nAnálise de risco residual:")
for risk, count in risk_counter.items():
    percentage = (count / total_events) * 100 if total_events > 0 else 0
    print(f" - {risk.upper()}: {count} ({percentage:.2f}%)")

print("\n🧠 Diagnóstico do Blue Team:")
if remediations > 0:
    print(f"✅ O sistema foi atacado, mas a Defesa Ativa neutralizou {remediations} ameaça(s).")
elif risk_counter["high"] > 0:
    print("⚠ Alertas de alto risco ainda ativos. Verifique se o monitor possui privilégios de Admin/Sudo.")
else:
    print("🟢 Nenhum incidente crítico ou atividade maliciosa pendente.")
# Atualizado em 2026-05-19.