"""Synthetic Python training data generator.

Produces vulnerable / safe code pairs for each CWE supported by the
prototype's pattern detector. Used as supervised data for fine-tuning
the GraphCodeBERT classification head.
"""

from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass
class Sample:
    code: str
    label: int  # 0 = benign, 1 = vulnerable
    cwe: str    # "BENIGN" for label=0
    source: str = "synthetic-py"


_NAMES = ["query", "name", "user_id", "filter", "key", "title", "search", "tag", "page", "session"]
_TABLES = ["users", "products", "orders", "sessions", "items", "logs", "comments"]
_HOSTS = ["api.example.com", "internal-svc", "metrics.local", "auth.test"]


def _rnd_name(rng: random.Random) -> str:
    return rng.choice(_NAMES)


def _vuln_sqli(rng: random.Random) -> Sample:
    var = _rnd_name(rng)
    table = rng.choice(_TABLES)
    column = rng.choice(["id", "title", "name", "email"])
    method = rng.choice(["execute", "executemany"])
    code = f"""def handler():
    {var} = request.args.get("{var}", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.{method}("SELECT * FROM {table} WHERE {column} = '" + {var} + "'")
    return cur.fetchall()
"""
    return Sample(code=code, label=1, cwe="CWE-89")


def _safe_sqli(rng: random.Random) -> Sample:
    var = _rnd_name(rng)
    table = rng.choice(_TABLES)
    column = rng.choice(["id", "title", "name", "email"])
    code = f"""def handler():
    {var} = request.args.get("{var}", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM {table} WHERE {column} = ?", ({var},))
    return cur.fetchall()
"""
    return Sample(code=code, label=0, cwe="BENIGN")


def _vuln_xss(rng: random.Random) -> Sample:
    var = _rnd_name(rng)
    code = f"""def handler():
    {var} = request.args.get("{var}", "")
    return render_template_string("<div>" + {var} + "</div>")
"""
    return Sample(code=code, label=1, cwe="CWE-79")


def _safe_xss(rng: random.Random) -> Sample:
    var = _rnd_name(rng)
    code = f"""def handler():
    {var} = escape(request.args.get("{var}", ""))
    return render_template("page.html", value={var})
"""
    return Sample(code=code, label=0, cwe="BENIGN")


def _vuln_cmd(rng: random.Random) -> Sample:
    var = _rnd_name(rng)
    binary = rng.choice(["ping", "traceroute", "nslookup", "curl"])
    style = rng.randint(0, 1)
    if style == 0:
        code = f"""def handler():
    {var} = request.args.get("{var}", "")
    out = os.system("{binary} " + {var})
    return {{"output": out}}
"""
    else:
        code = f"""def handler():
    {var} = request.args.get("{var}", "")
    out = subprocess.check_output("{binary} " + {var}, shell=True)
    return {{"output": out.decode()}}
"""
    return Sample(code=code, label=1, cwe="CWE-78")


def _safe_cmd(rng: random.Random) -> Sample:
    var = _rnd_name(rng)
    binary = rng.choice(["ping", "traceroute"])
    code = f"""def handler():
    {var} = request.args.get("{var}", "")
    if not re.match(r"^[a-zA-Z0-9.-]+$", {var}):
        return {{"error": "invalid"}}
    out = subprocess.check_output(["{binary}", "-c", "1", {var}])
    return {{"output": out.decode()}}
"""
    return Sample(code=code, label=0, cwe="BENIGN")


def _vuln_traversal(rng: random.Random) -> Sample:
    var = _rnd_name(rng)
    base = rng.choice(["/var/data", "/srv/files", "/opt/uploads"])
    code = f"""def handler():
    {var} = request.args.get("{var}", "")
    return send_file(open("{base}/" + {var}, "rb"))
"""
    return Sample(code=code, label=1, cwe="CWE-22")


def _safe_traversal(rng: random.Random) -> Sample:
    var = _rnd_name(rng)
    code = f"""def handler():
    {var} = request.args.get("{var}", "")
    if {var} not in ALLOWED_FILES:
        return {{"error": "forbidden"}}, 403
    return send_from_directory("/var/data", {var})
"""
    return Sample(code=code, label=0, cwe="BENIGN")


def _vuln_eval(rng: random.Random) -> Sample:
    var = _rnd_name(rng)
    func = rng.choice(["eval", "exec"])
    code = f"""def handler():
    {var} = request.args.get("{var}", "1+1")
    result = {func}({var})
    return {{"value": result}}
"""
    return Sample(code=code, label=1, cwe="CWE-94")


def _safe_eval(rng: random.Random) -> Sample:
    var = _rnd_name(rng)
    code = f"""def handler():
    {var} = request.args.get("{var}", "0")
    try:
        result = int({var})
    except ValueError:
        return {{"error": "invalid"}}, 400
    return {{"value": result}}
"""
    return Sample(code=code, label=0, cwe="BENIGN")


def _vuln_pickle(rng: random.Random) -> Sample:
    var = _rnd_name(rng)
    func = rng.choice(["pickle.loads", "yaml.load", "marshal.loads"])
    code = f"""def handler():
    {var} = request.args.get("{var}", "")
    obj = {func}({var}.encode())
    return {{"loaded": str(obj)}}
"""
    return Sample(code=code, label=1, cwe="CWE-502")


def _safe_pickle(rng: random.Random) -> Sample:
    var = _rnd_name(rng)
    code = f"""def handler():
    {var} = request.args.get("{var}", "")
    try:
        obj = json.loads({var})
    except json.JSONDecodeError:
        return {{"error": "invalid json"}}, 400
    return {{"loaded": obj}}
"""
    return Sample(code=code, label=0, cwe="BENIGN")


def _vuln_ssrf(rng: random.Random) -> Sample:
    var = _rnd_name(rng)
    func = rng.choice(["urllib.request.urlopen", "requests.get"])
    code = f"""def handler():
    {var} = request.args.get("{var}", "")
    response = {func}({var})
    return {{"body": response.read().decode()}}
"""
    return Sample(code=code, label=1, cwe="CWE-918")


def _safe_ssrf(rng: random.Random) -> Sample:
    var = _rnd_name(rng)
    host = rng.choice(_HOSTS)
    code = f"""def handler():
    {var} = request.args.get("{var}", "")
    parsed = urllib.parse.urlparse({var})
    if parsed.hostname != "{host}":
        return {{"error": "forbidden host"}}, 400
    response = requests.get({var}, timeout=5)
    return {{"body": response.text}}
"""
    return Sample(code=code, label=0, cwe="BENIGN")


VULN_GENERATORS = [
    _vuln_sqli,
    _vuln_xss,
    _vuln_cmd,
    _vuln_traversal,
    _vuln_eval,
    _vuln_pickle,
    _vuln_ssrf,
]
SAFE_GENERATORS = [
    _safe_sqli,
    _safe_xss,
    _safe_cmd,
    _safe_traversal,
    _safe_eval,
    _safe_pickle,
    _safe_ssrf,
]


def generate(samples_per_class: int = 80, seed: int = 42) -> list[Sample]:
    """Generate a balanced synthetic dataset.

    `samples_per_class` examples for each generator (vulnerable + safe).
    Total = 2 * samples_per_class * len(VULN_GENERATORS).
    """
    rng = random.Random(seed)
    out: list[Sample] = []
    for gen in VULN_GENERATORS:
        for _ in range(samples_per_class):
            out.append(gen(rng))
    for gen in SAFE_GENERATORS:
        for _ in range(samples_per_class):
            out.append(gen(rng))
    rng.shuffle(out)
    return out
