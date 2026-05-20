import os
import json
import pandas as pd
import streamlit as st

# Configuração da página
st.set_page_config(page_title="Blue Team EDR Dashboard", page_icon="🛡️", layout="wide")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "../logs/security_log.json")

st.title("🛡️ Blue Team Process Monitor - EDR Dashboard")
st.markdown("Monitoramento de endpoints e remediação automatizada em tempo real.")

# Verifica se o log existe
if not os.path.exists(LOG_FILE):
    st.warning("⚠️ Arquivo de log não encontrado. Execute o monitor e gere tráfego primeiro!")
else:
    # Carrega os dados do arquivo JSON estruturado em linhas
    data = []
    with open(LOG_FILE, "r") as f:
        for line in f:
            if line.strip():
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    if not data:
        st.info("Nenhum evento registrado ainda.")
    else:
        # Transforma os logs em um DataFrame do Pandas para facilitar gráficos
        df = pd.DataFrame(data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])

        # 📊 Métricas principais na tela (Cards estilo SIEM)
        total_events = len(df)
        high_risks = len(df[df['risk_level'] == 'high'])
        remediations = len(df[df['event_type'] == 'process_remediation_success'])

        col1, col2, col3 = st.columns(3)
        col1.metric("Total de Eventos", total_events)
        col2.metric("Ameaças Críticas (Alta)", high_risks, delta="- Bloqueadas" if remediations > 0 else None, delta_color="inverse")
        col3.metric("Remediações (Kills) Ativas", remediations)

        # 📈 Gráficos
        st.markdown("---")
        g1, g2 = st.columns(2)

        with g1:
            st.subheader("Eventos por Severidade (Nível de Risco)")
            risk_counts = df['risk_level'].value_counts()
            st.bar_chart(risk_counts)

        with g2:
            st.subheader("Tipos de Incidentes Detectados")
            type_counts = df['event_type'].value_counts()
            # Ajustado para usar bar_chart nativo e evitar o erro de atributo anterior
            st.bar_chart(type_counts)

        # 📋 Tabela de logs brutos recentes
        st.markdown("---")
        st.subheader("📋 Últimos Eventos Registrados")
        st.dataframe(df.sort_values(by='timestamp', ascending=False), use_container_width=True)

        # Botão de atualização
        if st.button("🔄 Atualizar Dados"):
            st.rerun()
