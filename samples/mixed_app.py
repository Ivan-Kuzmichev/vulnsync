"""Третий демо-сценарий: несовпадение сигналов кода и логов.

В коде есть SSRF (CWE-918) и небезопасная десериализация (CWE-502),
но логи показывают только активный XSS-сканер по неуязвимым обработчикам
/comment и /search. Сценарий иллюстрирует асимметричную логику принятия
решений из 3.5.2:
  - SSRF/Deserialization → "плановое исправление" (есть в коде, нет в логах)
  - XSS-сканер           → "расследование в SIEM" (есть в логах, нет в коде)
"""

import pickle
import sqlite3
import urllib.request

from flask import Flask, request

app = Flask(__name__)


@app.route("/webhook")
def webhook():
    # CWE-918: SSRF — приложение скачивает URL из пользовательского ввода
    target = request.args.get("url", "")
    response = urllib.request.urlopen(target)
    return {"body": response.read().decode()}


@app.route("/import")
def import_session():
    # CWE-502: небезопасная десериализация pickle с пользовательскими данными
    blob = request.args.get("session", "")
    obj = pickle.loads(blob.encode())
    return {"loaded": str(obj)}


@app.route("/profile")
def profile():
    # Безопасно — параметризованный запрос
    user_id = request.args.get("id", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT name, email FROM users WHERE id = ?", (user_id,))
    return {"user": cur.fetchone()}


@app.route("/search")
def search():
    # Безопасно — нет рендеринга, чистый JSON
    q = request.args.get("q", "")
    return {"query": q, "results": []}
