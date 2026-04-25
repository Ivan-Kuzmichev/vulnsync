"""Четвертый демо-сценарий: частичная эксплуатация.

В админке четыре реальных уязвимости (SQLi, Cmd injection, XSS, Path Traversal),
но в логах активно атакуют только SQLi на /admin/search. Сценарий иллюстрирует
обоснованную приоритизацию из 3.1.2 и 4.6:
  - CWE-89   → критическое (есть в коде, активно эксплуатируется)
  - остальные → плановое исправление (есть в коде, нет признаков атаки)
"""

import os
import sqlite3
import subprocess

from flask import Flask, render_template_string, request, send_file

app = Flask(__name__)


@app.route("/admin/search")
def admin_search():
    # CWE-89: SQL injection — активно эксплуатируется в логах
    keyword = request.args.get("q", "")
    conn = sqlite3.connect("admin.db")
    cur = conn.cursor()
    cur.execute("SELECT id, login, role FROM users WHERE login LIKE '%" + keyword + "%'")
    return {"matches": cur.fetchall()}


@app.route("/admin/run")
def admin_run():
    # CWE-78: command injection — присутствует, но НЕ атакуется в логах
    job = request.args.get("job", "status")
    output = subprocess.check_output("/usr/local/bin/job-runner " + job, shell=True)
    return {"output": output.decode()}


@app.route("/admin/preview")
def admin_preview():
    # CWE-79: stored XSS через render_template_string — НЕ атакуется
    snippet = request.args.get("html", "")
    return render_template_string("<div class='preview'>" + snippet + "</div>")


@app.route("/admin/export")
def admin_export():
    # CWE-22: path traversal — НЕ атакуется
    report = request.args.get("file", "")
    path = "/var/reports/" + report
    return send_file(open(path, "rb"))


@app.route("/admin/users/<int:uid>")
def admin_user(uid: int):
    # Безопасно — параметризованный запрос
    conn = sqlite3.connect("admin.db")
    cur = conn.cursor()
    cur.execute("SELECT login, role FROM users WHERE id = ?", (uid,))
    return {"user": cur.fetchone()}
