"""Контрольный пример: то же приложение с устраненными уязвимостями.

Используется для иллюстрации сценария, когда обе компонента системы
подтверждают отсутствие угроз — Risk Score близок к нулю.
"""

import os
import sqlite3
from pathlib import Path

from flask import Flask, escape, render_template, request

app = Flask(__name__)

ALLOWED_FILES = {"report.pdf", "manual.pdf", "logo.png"}


@app.route("/search")
def search():
    # Параметризованный запрос — без SQL инъекции
    query = request.args.get("query", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, title FROM products WHERE title LIKE ?",
        ("%" + query + "%",),
    )
    return {"results": cursor.fetchall()}


@app.route("/comment")
def comment():
    # Экранирование — без XSS
    text = escape(request.args.get("text", ""))
    return render_template("comment.html", text=text)


@app.route("/download")
def download():
    # Белый список — без path traversal
    name = request.args.get("name", "")
    if name not in ALLOWED_FILES:
        return {"error": "forbidden"}, 403
    path = Path("/var/data") / name
    return {"path": str(path)}


@app.route("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(port=5000)
