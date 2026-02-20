# 🛡️ Cybersecurity Process Monitor

Projeto desenvolvido com foco em monitoramento de processos suspeitos em ambiente local, simulando um cenário básico de detecção utilizado em operações de segurança (SOC / Blue Team).

---

## 📌 Objetivo

O objetivo do projeto é:

- Monitorar processos ativos na máquina
- Identificar possíveis comportamentos suspeitos com base em regras definidas
- Registrar eventos em log estruturado (JSON)
- Gerar relatório analítico dos eventos detectados
- Validar regras através de simulação controlada de ameaça

---

## 🧠 Conceitos Aplicados

- Monitoramento de processos
- Detecção baseada em regras (rule-based detection)
- Redução de falsos positivos
- Simulação de ameaça controlada
- Estruturação de logs para análise
- Separação de responsabilidades no código

---

## 🏗️ Estrutura do Projeto

```
blue-team-process-monitor/
│
├── src/
│   ├── monitor.py
│   ├── analyze_logs.py
│   └── keylogger_process.py
│
├── logs/
│   ├── security_log.json
│   └── security_log_example.json
│
├── tests/
│   └── fake_activity.py
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

## ⚙️ Tecnologias Utilizadas

- Python 3
- Biblioteca `psutil`
- JSON para armazenamento de logs

---

## 🚀 Como Executar

### 1️⃣ Criar ambiente virtual

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

### 2️⃣ Instalar dependências

```bash
pip install -r requirements.txt
```

### 3️⃣ Executar monitor

```bash
python src/monitor.py
```

---

## 🧪 Teste Controlado de Detecção

Para validar a regra de detecção:

1. Execute o processo simulado:

```bash
python src/keylogger_process.py
```

2. Em outro terminal, execute o monitor:

```bash
python src/monitor.py
```

O sistema detectará o processo simulado como altamente suspeito.

---

## 📊 Análise de Logs

Após a execução do monitor:

```bash
python src/analyze_logs.py
```

Será exibido um resumo estatístico dos eventos registrados.

---

## 🎯 Aprendizados

Durante o desenvolvimento foram trabalhados:

- Construção de regras de detecção
- Ajuste fino para evitar falsos positivos
- Simulação prática de cenários de ameaça
- Organização profissional de projeto

---

## 📌 Próximos Passos

- Implementar detecção baseada em comportamento
- Adicionar níveis de severidade
- Exportar relatório em formato CSV
- Implementar monitoramento em tempo real contínuo

---

## 👨‍💻 Autor

Projeto desenvolvido para fins de estudo e prática em Segurança da Informação.