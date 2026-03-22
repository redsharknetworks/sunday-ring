from flask import Flask
import threading, time

app = Flask(__name__)

def engine():
    while True:
        # Safe: run after server starts
        time.sleep(600)

@app.before_first_request
def start_engine():
    threading.Thread(target=engine, daemon=True).start()

@app.route("/")
def home():
    return "✅ Render-safe SOC"

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)