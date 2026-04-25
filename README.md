# Прототип интегрированной методики выявления уязвимостей

Демонстрационная реализация методики из диссертационной работы.
Объединяет три компонента в соответствии с Главой 3:

- **Анализ исходного кода** (`code_analysis/`) — AST-детектор, выявляющий уязвимости CWE-89, CWE-79, CWE-78, CWE-22, CWE-94, CWE-918 в Python-коде на основе taint-анализа с источниками `request.args`, `request.form` и т.д.
- **Анализ логов** (`log_analysis/`) — ансамбль из трех детекторов (статистические пороги по Таблице 3.1, Isolation Forest, MLP-автоэнкодер как замена LSTM) + классификатор атак на градиентном бустинге.
- **Интеграционный слой** (`integration/`) — реализация формул из 3.5.2:
  - `Risk = 0.30·P_code + 0.30·S_anomaly + 0.20·Severity(CWE) + 0.20·Agreement`
  - `Confidence = √(C_code · C_log) · (1 + 0.5·Agreement)`
  - Продукционные правила принятия решений.

## Запуск

### Локально (Python)

```bash
cd app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m app.main
```

### Docker (локальная сборка)

```bash
cd app
docker build -t vuln-analyzer:local .
docker run --rm -p 8000:8000 vuln-analyzer:local
```

### Docker Compose (готовый образ из GHCR)

Из корня репозитория:

```bash
cp .env.example .env
# В .env замените IMAGE на ghcr.io/<your-username>/<repo-name>:latest
docker compose up -d
docker compose logs -f
```

Затем откройте http://127.0.0.1:8000 в браузере.

### GitHub Actions

Воркфлоу `.github/workflows/build-image.yml` срабатывает на push в `main` и теги `v*`:

1. **smoke-test**: ставит зависимости, прогоняет E2E проверку конвейера на демо-данных (vulnerable + clean) с проверкой инвариантов (риск ≥ 0.7 на vulnerable, == 0 на clean).
2. **build-and-push**: собирает мульти-архитектурный образ (linux/amd64 + linux/arm64), пушит в GHCR с тегами `latest`, `sha-<short>`, semver-тегами при релизах. Использует GitHub Actions cache для Docker layer cache.

Образ публикуется в `ghcr.io/<owner>/<repo>`. Для приватных репозиториев нужен `docker login ghcr.io` с personal access token (scope `read:packages`).

## Демо-сценарии

Кнопки в UI:

- **Загрузить уязвимый пример** — Flask-приложение с пятью внедренными уязвимостями + лог с реальными атаками (sqlmap, ZAP, brute force, path traversal). Ожидаемый результат: высокий Risk Score, кросс-верификация по CWE между кодом и логами.
- **Загрузить чистый пример** — то же приложение с устраненными уязвимостями + нормальный трафик. Ожидаемый результат: Risk Score ≈ 0, отсутствие findings.

## Структура

```
app/
├── code_analysis/      # компонент анализа кода (AST + taint)
├── log_analysis/       # компонент анализа логов (ансамбль)
├── integration/        # интеграционный слой
├── web/                # FastAPI + HTML/JS UI
├── samples/            # демо-данные
├── main.py
└── requirements.txt
```

## Соответствие диссертации

| Раздел работы | Реализация |
|---|---|
| 3.3.1 Представление кода | `code_analysis/ast_detector.py` — AST-парсинг |
| 3.3.2 Выбор модели | `code_analysis/patterns.py` — паттерны CWE (упрощение GraphCodeBERT для демо) |
| 3.4.1 Источники данных | `log_analysis/parser.py` — Combined Log Format |
| 3.4.2 Модель аномалий | `log_analysis/{statistical,isolation,autoencoder}.py` |
| 3.4.3 Классификация атак | `log_analysis/classifier.py` — Gradient Boosting (sklearn) |
| 3.5.1 Входы интеграции | `integration/integrator.py` |
| 3.5.2 Расчет Risk Score | `integration/integrator.py` (формулы и веса буквально) |
| 3.5.3 Evidence aggregation | `web/templates/index.html` — визуализация |

## Ограничения прототипа

- GraphCodeBERT в прототипе заменен AST-детектором с правилами taint-анализа. Это снижает обобщающую способность на новые паттерны, но обеспечивает запуск без 500 МБ модели и 30 секунд инициализации.
- LSTM-автоэнкодер заменен MLP-автоэнкодером (sklearn) — концептуально эквивалентен (anomaly detection через reconstruction error), но без зависимости от PyTorch.
- Классификатор атак обучен на синтетическом датасете, сгенерированном из канонических сигнатур. В производстве — CSIC 2010, CICIDS 2017 и собственные honeypot-данные (см. 4.5).
