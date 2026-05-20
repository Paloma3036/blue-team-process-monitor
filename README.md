# 🛡️ Blue Team Process Monitor (EDR / IPS / SIEM Emulator)

Uma ferramenta leve de monitoramento de processos baseada em regras desenvolvida para simular a detecção, análise e **remediação automatizada** de ameaças do Blue Team em ambiente local. O projeto agora funciona como um emulador completo de EDR (Endpoint Detection and Response) com interface visual integrada.

## 📌 Objetivo
O objetivo do projeto é:
- Monitorar processos ativos na máquina inspecionando os argumentos de linha de comando (`cmdline`).
- Identificar e **neutralizar instantaneamente** comportamentos suspeitos com base em assinaturas heurísticas.
- Isolar e mover arquivos maliciosos em tempo real para um diretório seguro de quarentena.
- Centralizar e exibir métricas críticas de segurança em um Dashboard interativo estilo SIEM.

## 🧠 Conceitos Aplicados
- Monitoramento heurístico avançado de processos e conexões de rede (`psutil`).
- **Remediação Ativa (Incident Response):** Auto-Kill automatizado de ameaças persistentes.
- **Isolamento de Artefatos:** Rotinas de quarentena baseadas em assinaturas SHA-256.
- Engenharia e estruturação de logs padronizados em JSON.
- Análise visual de telemetria de segurança orientada a dados.

## 🏗️ Estrutura do Projeto
```text
blue-team-process-monitor/
│
├── src/
│   ├── monitor.py           # Core do EDR: detecção, auto-kill e quarentena
│   ├── analyze_logs.py      # Analisador estatístico de terminal
│   ├── dashboard.py         # Interface visual interativa (SIEM)
│   └── keylogger_process.py # Simulação controlada de malware
│
├── logs/
│   ├── quarantine/          # Repositório de arquivos isolados pelo EDR
│   └── security_log.json    # Logs de auditoria estruturados
│
├── tests/
│   └── simulate_activity.py # Gerador automatizado de tráfego e artefatos
│
├── requirements.txt
├── README.md
└── .gitignore
```

## 🧩 Arquitetura das Camadas
- **Monitor (`monitor.py`):** Age como o agente de segurança do endpoint. Interrompe processos maliciosos e gerencia o isolamento de arquivos.
- **Simuladores:** `keylogger_process.py` (simula ameaça de processo) e `simulate_activity.py` (simula indicadores de rede e escrita em disco).
- **Visibilidade:** `dashboard.py` consome e renderiza os logs brutos gerados, transformando dados de auditoria em inteligência visual.

## ⚙️ Tecnologias Utilizadas
- **Python 3** (Interpretador principal)
- **Psutil** (Inspeção de chamadas do sistema e conexões de rede)
- **Streamlit** (Framework de interface web)
- **Pandas** (Tratamento e agregação de dados textuais)
- **JSON & Hashlib** (Estruturação de logs e assinaturas criptográficas)

## 🚀 Como Executar

1️⃣ **Criar ambiente virtual**
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

2️⃣ **Instalar dependências**
```bash
pip install -r requirements.txt
```

3️⃣ **Iniciar o Monitor de Segurança**
```bash
python src/monitor.py
```

4️⃣ **Iniciar o Dashboard SIEM (Em outro terminal com venv ativado)**
```bash
streamlit run src/dashboard.py
```

## 🧪 Teste Controlado de Detecção e Prevenção

Para validar os motores de contenção ativa do projeto:

- **Teste de IPS (Process Kill):** Execute o malware simulado em um terminal separado:
  ```bash
  python src/keylogger_process.py
  ```
  *O monitor detectará a assinatura na linha de comando e encerrará o processo imediatamente.*

- **Teste de Quarentena (File Isolation):** Execute o injetor de logs e arquivos de teste:
  ```bash
  python tests/simulate_activity.py
  ```
  *O monitor interceptará o arquivo criado, calculará seu hash SHA-256 e o moverá imediatamente para a pasta `logs/quarantine/`.*

## 📊 Análise e Visibilidade
Abra o navegador no endereço indicado pelo Streamlit para acompanhar gráficos em tempo real de:
- Volumetria total de eventos ocorridos no endpoint.
- Relação de processos efetivamente mitigados/derrubados (**Remediações Ativas**).
- Severidade de incidentes por nível de risco (Baixo, Médio, Alto).

## 🎯 Principais Aprendizados
- Engenharia de software aplicada à detecção e resposta a incidentes (IR).
- Manipulação de chamadas de sistema e bibliotecas nativas para controle de processos do S.O.
- Mitigação de condições de corrida (*race conditions*) e redundâncias com otimização via caches de memória.
- Desenvolvimento ágil de Dashboards analíticos voltados para equipes de SOC.

## 📌 Próximos Passos desejados
- Implementar mecanismos de persistência no sistema operacional (falso daemon/serviço).
- Migrar armazenamento de arquivos brutos para banco de dados relacional leve (SQLite).
- Adicionar integrações para envio de alertas instantâneos via webhook (Slack/Discord).

## 👨‍💻 Autor
Projeto expandido e refatorado para fins de estudo focado em engenharia de detecção e automação de Segurança da Informação.

