import os
import json
from collections import Counter

# Alinha o caminho com a estrutura do monitor
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "../logs/security_log.json")

event_counter = Counter()
risk_counter = Counter()
total_events = 0

if not os.path.exists(LOG_FILE):
    print(f"❌ Arquivo de log não encontrado em: {LOG_FILE}")
    print("Execute o monitor primeiro para gerar tráfego e logs.")
    exit()

try:
    with open(LOG_FILE, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                event_counter[event.get("event_type", "unknown")] += 1
                risk_counter[event.get("risk_level", "low")] += 1
                total_events += 1
            except json.JSONDecodeError:
                print(f"⚠ Linha {line_num} corrompida no log ignorada.")

except Exception as e:
    print(f"❌ Erro ao ler o arquivo: {e}")
    exit()

print("\n📊 RELATÓRIO DE ANÁLISE DE SEGURANÇA\n")
print(f"Total de eventos registrados: {total_events}\n")

print("Eventos por tipo:")
for event_type, count in event_counter.items():
    print(f" - {event_type}: {count}")

print("\nEventos por nível de risco:")
for risk, count in risk_counter.items():
    percentage = (count / total_events) * 100 if total_events > 0 else 0
    print(f" - {risk.upper()}: {count} ({percentage:.2f}%)")

print("\n🧠 Interpretação automática:")
if risk_counter["high"] > 0:
    print("⚠ CRÍTICO: Foram detectados eventos de alto risco. Investigação imediata recomendada.")
elif risk_counter["medium"] > 0:
    print("🔎 ATENÇÃO: Sistema apresenta eventos de risco médio. Monitoramento contínuo recomendado.")
else:
    print("✅ LIMPO: Nenhum evento crítico identificado até o momento.")
# Atualizado em 2026-05-19.