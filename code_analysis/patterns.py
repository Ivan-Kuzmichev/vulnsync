"""CWE patterns and severity scores derived from CVSS base metrics."""

CWE_DESCRIPTIONS = {
    "CWE-89": "SQL-инъекция",
    "CWE-79": "Межсайтовый скриптинг (XSS)",
    "CWE-78": "Инъекция команд ОС",
    "CWE-22": "Обход директорий (Path Traversal)",
    "CWE-94": "Внедрение кода (eval/exec)",
    "CWE-502": "Небезопасная десериализация",
    "CWE-918": "SSRF (подделка серверных запросов)",
    "CWE-352": "CSRF (подделка межсайтовых запросов)",
    "CWE-307": "Неограниченные попытки аутентификации (Brute Force)",
}

CWE_SEVERITY = {
    "CWE-89": 0.95,
    "CWE-94": 0.95,
    "CWE-502": 0.92,
    "CWE-78": 0.90,
    "CWE-918": 0.80,
    "CWE-22": 0.78,
    "CWE-79": 0.72,
    "CWE-307": 0.65,
    "CWE-352": 0.60,
}

DANGEROUS_FUNCTIONS = {
    "eval": "CWE-94",
    "exec": "CWE-94",
    "compile": "CWE-94",
    "pickle.loads": "CWE-502",
    "yaml.load": "CWE-502",
    "marshal.loads": "CWE-502",
    "os.system": "CWE-78",
    "os.popen": "CWE-78",
    "subprocess.call": "CWE-78",
    "subprocess.Popen": "CWE-78",
    "subprocess.run": "CWE-78",
    "subprocess.check_output": "CWE-78",
}

SQL_METHODS = {"execute", "executemany", "executescript", "raw"}

RENDER_METHODS = {"render_template_string", "Markup", "HTML"}

FILE_OPS = {"open", "read", "send_file", "send_from_directory"}

URL_OPS = {"urlopen", "get", "post", "request"}
