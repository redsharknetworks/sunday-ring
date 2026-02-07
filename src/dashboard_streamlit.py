import streamlit as st
import sqlite3
import pandas as pd

def load_data(country='MY'):
    conn = sqlite3.connect('data/iocs.db')
    df = pd.read_sql_query("SELECT indicator,type,seen_at,country,asn,isp,score,sources FROM iocs WHERE country = ? ORDER BY seen_at DESC LIMIT 500", conn, params=(country,))
    conn.close()
    return df

st.title("IOC Dashboard — Malaysia")
df = load_data('MY')
st.dataframe(df)
st.metric("Total IOCs (MY)", len(df))
# add charts, maps (st.map), filtering, auto-refresh via st.experimental_rerun with interval
