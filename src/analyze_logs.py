import json
from collections import Counter

LOG_FILE = "../logs/security_log.json"

event_counter = Counter()
risk_counter = Counter()
total_events = 0

try:
    with open(LOG_FILE, "r") as f:
        for line in f:
            event = json.loads(line)

            event_counter[event["event_type"]] += 1
            risk_counter[event["risk_level"]] += 1
            total_events += 1

except FileNotFoundError:
    print("Arquivo de log não encontrado.")
    exit()

print("\n📊 RELATÓRIO DE ANÁLISE DE SEGURANÇA\n")

print(f"Total de eventos registrados: {total_events}\n")

print("Eventos por tipo:")
for event_type, count in event_counter.items():
    print(f" - {event_type}: {count}")

print("\nEventos por nível de risco:")
for risk, count in risk_counter.items():
    percentage = (count / total_events) * 100
    print(f" - {risk}: {count} ({percentage:.2f}%)")

print("\n🧠 Interpretação automática:")

if risk_counter["high"] > 0:
    print("⚠ Foram detectados eventos de alto risco. Investigação recomendada.")
elif risk_counter["medium"] > 0:
    print("🔎 Sistema apresenta eventos de risco médio. Monitoramento contínuo recomendado.")
else:
    print("✅ Nenhum evento crítico identificado.")
