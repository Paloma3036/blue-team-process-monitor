import socket
import time
import os

# Simular processo persistente
while True:
    # Abrir conexão local
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("example.com", 80))
    except:
        pass
    s.close()

    # Simular escrita de arquivo
    with open("temp_data.txt", "a") as f:
        f.write("Simulated suspicious activity\n")

    time.sleep(10)
