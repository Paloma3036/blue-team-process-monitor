import os
import socket
import time
import sys

# Garante que o arquivo temporário caia na pasta de logs correta
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMP_FILE_PATH = os.path.abspath(os.path.join(BASE_DIR, "../logs/temp_data.txt"))

print("🧪 Iniciando simulador de atividades suspeitas de rede e arquivo...")
print(f"Escrevendo dados de teste em: {TEMP_FILE_PATH}")
print("Pressione CTRL+C para parar.")

try:
    while True:
        # 1. Simular conexão de rede de saída (HTTP padrão para testar captura)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect(("example.com", 80))
            print("🔗 Conexão de teste estabelecida com sucesso.")
        except Exception:
            pass
        finally:
            s.close()

        # 2. Simular modificação/escrita de arquivo suspeito
        with open(TEMP_FILE_PATH, "a") as f:
            f.write(f"Atividade suspeita simulada em: {time.time()}\n")

        time.sleep(10)
except KeyboardInterrupt:
    print("\nSimulador parado.")
    sys.exit(0)
# Atualizado em 2026-05-19.