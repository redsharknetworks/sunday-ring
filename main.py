from flask import Flask, render_template, jsonify
import sqlite3
import pandas as pd
import folium
import io
import base64
import plotly.graph_objs as go
from datetime import datetime, timedelta

app = Flask(__name__)

DB_PATH = 'data.db'  # Adjust to your SQLite DB path

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def generate_heatmap():
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT ip, latitude, longitude, risk_score FROM threats WHERE latitude IS NOT NULL AND longitude IS NOT NULL", conn)
    conn.close()

    m = folium.Map(location=[0, 0], zoom_start=2, tiles="CartoDB dark_matter")
    for _, row in df.iterrows():
        folium.CircleMarker(
            location=[row['latitude'], row['longitude']],
            radius=5,
            color='red' if row['risk_score'] > 5 else 'orange',
            fill=True,
            fill_opacity=0.7,
        ).add_to(m)

    return m._repr_html_()

def generate_trend_chart():
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT date(created_at) as day, COUNT(*) as count FROM threats GROUP BY day ORDER BY day ASC", conn)
    conn.close()

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df['day'],
        y=df['count'],
        mode='lines+markers',
        line=dict(color='orange', width=4),
        marker=dict(size=8)
    ))
    fig.update_layout(
        title='Daily Threat Trend',
        xaxis_title='Date',
        yaxis_title='Count',
        plot_bgcolor='#1b1b1b',
        paper_bgcolor='#1b1b1b',
        font=dict(color='#f1f1f1')
    )
    return fig.to_json()

def get_top(table, col):
    conn = get_db_connection()
    week_ago = datetime.utcnow() - timedelta(days=7)
    query = f"""
        SELECT {col}, risk_score, COUNT(*) as c
        FROM {table}
        WHERE created_at >= ?
        GROUP BY {col}, risk_score
        ORDER BY c DESC
        LIMIT 10
    """
    res = conn.execute(query, (week_ago.isoformat(),)).fetchall()
    conn.close()
    return res

@app.route('/')
def dashboard():
    heatmap_html = generate_heatmap()
    trend_chart_json = generate_trend_chart()
    top_ips = get_top('threats', 'ip')
    top_domains = get_top('threats', 'domain')
    top_hashes = get_top('threats', 'hash')

    return render_template(
        'dashboard.html',
        heatmap_html=heatmap_html,
        trend_chart=trend_chart_json,
        top_ips=top_ips,
        top_domains=top_domains,
        top_hashes=top_hashes
    )

@app.route('/report/json')
def json_report():
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT * FROM threats ORDER BY created_at DESC LIMIT 100", conn)
    conn.close()
    return df.to_json(orient='records')

@app.route('/report/csv')
def csv_report():
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT * FROM threats ORDER BY created_at DESC LIMIT 100", conn)
    conn.close()
    return df.to_csv(index=False)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=True)
