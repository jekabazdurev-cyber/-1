import streamlit as st
import pandas as pd
import re
import plotly.express as px
from datetime import datetime

# --- 1. НАЛАШТУВАННЯ СТОРІНКИ ТА ДИЗАЙНУ ---
# Використання широкого макету сторінки згідно з п. 4 вашого плану
st.set_page_config(
    page_title="CyberGuard | Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Додавання кастомного CSS для професійного вигляду (Dark Theme)
st.markdown("""
    <style>
    /* Стилізація карток метрик для забезпечення наочності */
    [data-testid="stMetric"] {
        background-color: #161b22;
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #30363d;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    [data-testid="stMetricLabel"] {
        color: #8b949e;
        font-size: 16px;
    }
    [data-testid="stMetricValue"] {
        color: #58a6ff;
    }
    .main {
        background-color: #0d1117;
    }
    h1, h2, h3 {
        color: #c9d1d9;
    }
    </style>
    """, unsafe_allow_html=True)

# --- 2. ЛОГІКА ОБРОБКИ ДАНИХ (РОЗДІЛ 2 ПЛАНУ) ---
def parse_logs(uploaded_file):
    """
    Парсинг логів за допомогою регулярних виразів (Regex).
    Реалізує ітеративний підхід обробки рядків (п. 1 плану).
    """
    log_data = []
    # Патерн для стандартного формату auth.log (SSH)
    pattern = r'(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(Failed|Accepted)\s+password\s+for\s+(\S+)\s+from\s+(\S+)'
    
    try:
        content = uploaded_file.read().decode("utf-8")
        for line in content.splitlines():
            match = re.search(pattern, line)
            if match:
                timestamp_str, status, user, ip = match.groups()
                # Додавання поточного року для коректної побудови часових рядів
                current_year = datetime.now().year
                full_date = f"{timestamp_str} {current_year}"
                dt_obj = datetime.strptime(full_date, "%b %d %H:%M:%S %Y")
                
                log_data.append({
                    "Час": dt_obj,
                    "Користувач": user,
                    "IP-адреса": ip,
                    "Статус": "Успішно" if status == "Accepted" else "Невдало"
                })
        # Повертаємо DataFrame для подальшого аналізу (п. 3 плану)
        return pd.DataFrame(log_data)
    except Exception as e:
        # Обробка винятків згідно з вимогами надійності (п. 5 плану)
        st.error(f"Помилка при обробці файлу: {e}")
        return pd.DataFrame()

# --- 3. БІЧНА ПАНЕЛЬ (SIDEBAR) ---
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=80)
    st.title("Керування")
    st.markdown("---")
    # Валідація вхідних даних за форматом файлу
    uploaded_file = st.file_uploader("Завантажте файл журналу", type=['log', 'txt'])
    st.markdown("---")
    st.info("Інструмент виявлення Brute-force атак на основі аналізу журналів автентифікації.")
    if st.button("Оновити дані"):
        st.rerun()

# --- 4. ГОЛОВНИЙ ІНТЕРФЕЙС (РОЗДІЛ 4 ПЛАНУ) ---
st.title("🛡️ Аналізатор журналів автентифікації")

if uploaded_file:
    df = parse_logs(uploaded_file)
    
    if not df.empty:
        # Розрахунок статистичних показників (Математична модель, п. 2)
        total = len(df)
        success = len(df[df['Статус'] == 'Успішно'])
        failed = len(df[df['Статус'] == 'Невдало'])
        unique_ips = df['IP-адреса'].nunique()

        # Відображення ключових метрик
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Всього спроб", total)
        m2.metric("Успішні входи", success)
        m3.metric("Невдалі (Ризики)", failed, delta=f"{(failed/total)*100:.1f}%", delta_color="inverse")
        m4.metric("Унікальні IP", unique_ips)

        st.markdown("---")

        # Структурування інтерфейсу за допомогою вкладок
        tab_viz, tab_analysis, tab_raw = st.tabs(["📊 Візуалізація", "🔍 Аналіз аномалій", "📑 Журнал подій"])

        with tab_viz:
            st.subheader("Динаміка активності за часом")
            # Групування даних з виправленим форматом години 'h'
            df_counts = df.groupby([df['Час'].dt.floor('h'), 'Статус']).size().reset_index(name='Кількість')
            fig = px.area(df_counts, x='Час', y='Кількість', color='Статус',
                         color_discrete_map={'Успішно': '#238636', 'Невдало': '#da3633'},
                         template="plotly_dark")
            fig.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig, use_container_width=True)

        with tab_analysis:
            c1, c2 = st.columns(2)
            with c1:
                st.subheader("Топ-10 підозрілих IP")
                top_ips = df[df['Статус'] == 'Невдало']['IP-адреса'].value_counts().head(10)
                st.bar_chart(top_ips, color="#58a6ff")
            
            with c2:
                st.subheader("Атаки на користувачів")
                top_users = df[df['Статус'] == 'Невдало']['Користувач'].value_counts().head(10)
                st.table(top