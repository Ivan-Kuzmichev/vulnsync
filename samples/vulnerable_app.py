"""Демонстрационное Flask-приложение с намеренно внедренными уязвимостями.

Используется для иллюстрации работы интегрированной методики.
Каждая уязвимость соответствует записи (записям) в access.log,
что позволяет наблюдать кросс-верификацию между двумя компонентами.
"""

import os
import sqlite3
import subprocess

from flask import Flask, render_template_string, request, send_file

app = Flask(__name__)


@app.route("/search")
def search():
    # CWE-89: SQL injection — динамическая склейка с request.args
    query = request.args.get("query", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, title FROM products WHERE title LIKE '%" + query + "%'")
    rows = cursor.fetchall()
    return {"results": rows}


@app.route("/comment")
def comment():
    # CWE-79: XSS — render_template_string с пользовательскими данными
    text = request.args.get("text", "")
    return render_template_string("<div class='comment'>" + text + "</div>")


@app.route("/download")
def download():
    # CWE-22: Path traversal — путь из пользовательского ввода без проверки
    name = request.args.get("name", "")
    return send_file(open("/var/data/" + name, "rb"))


@app.route("/ping")
def ping():
    # CWE-78: OS command injection — shell=True с пользовательским вводом
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.check_output("ping -c 1 " + host, shell=True)
    return {"output": result.decode()}


@app.route("/render")
def render():
    # CWE-94: code injection — eval с пользовательским вводом
    expr = request.args.get("expr", "1+1")
    return {"value": eval(expr)}


@app.route("/healthz")
def healthz():
    # Безопасный обработчик — параметризованный запрос
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM products WHERE active = ?", (True,))
    return {"status": "ok", "count": cursor.fetchone()[0]}


if __name__ == "__main__":
    app.run(port=5000)
