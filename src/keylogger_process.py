import time
import sys

print("🎯 [FAKE MALWARE] Processo simulador de Keylogger iniciado...")
print("Pressione CTRL+C para encerrar este processo simulado.")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nSimulação encerrada.")
    sys.exit(0)
# Atualizado em 2026-05-19.