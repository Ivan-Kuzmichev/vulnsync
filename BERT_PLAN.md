# План интеграции GraphCodeBERT (вариант D)

Полная реализация ML-компонента анализа кода: предобученный GraphCodeBERT
+ обученный на наших данных classification head. Ниже шаги, которые ты
запускаешь поэтапно.

---

## Архитектура

```
input code
    │
    ├──► AST-детектор (как сейчас)              ─┐
    │       └─► [CWE, line, P_ast]               ├──► Ансамбль:
    │                                             │   P_code = max(P_ast, P_bert)
    └──► GraphCodeBERT encoder (frozen)           │   + cross-evidence
            └─► [CLS] embedding (768d)            │
                  └─► Trained head               ─┘
                        ↓
                    P_vulnerable + per-CWE softmax
```

`WITH_BERT=1` — переключатель. По умолчанию работает только AST.

---

## Этапы

Все команды — из директории `app/`.

### 0. Виртуальное окружение

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 1. Установить BERT-зависимости (~700 МБ)

```bash
pip install -r requirements.txt
pip install -r requirements-bert.txt
```

Проверка: `python -c "import torch; print(torch.__version__, torch.backends.mps.is_available())"`
На M-серии Mac должно показать `True` — будем использовать MPS-ускорение.

### 2. Подготовить датасет (~5 мин)

```bash
python -m code_analysis.prepare_data
```

Что делает:
- Скачивает Devign из HuggingFace `code_x_glue_cc_defect_detection` (~30 МБ, кэш в `~/.cache/huggingface`).
- Генерирует ~600 синтетических Python-примеров (по 80-100 на каждую из 7 CWE из наших патернов, плюс безопасные варианты).
- Сохраняет в `data/dataset.jsonl` (один JSON на строке: `{code, label, source}`).

Артефакт: `data/dataset.jsonl` (~1600 примеров).

### 3. Скачать GraphCodeBERT и посчитать эмбеддинги (~10–15 мин на MPS)

```bash
python -m code_analysis.embed_dataset
```

Что делает:
- Скачивает `microsoft/graphcodebert-base` (~500 МБ) в `~/.cache/huggingface`.
- Прогоняет каждую функцию через encoder, берёт `[CLS]`-эмбеддинг.
- Сохраняет матрицу эмбеддингов + метки в `data/embeddings.pt`.

Артефакт: `data/embeddings.pt` (~5 МБ).

> Этот шаг — самый долгий. Запускай и иди пить чай. После него обучать
> голову можно сколько угодно раз без перерасчёта эмбеддингов.

### 4. Обучить classification head (~1–2 мин)

```bash
python -m code_analysis.train_head
```

Что делает:
- Загружает `data/embeddings.pt`.
- Обучает `Linear(768, 256) → tanh → Dropout(0.3) → Linear(256, 2)` бинарный head.
- 5 эпох, AdamW с lr=1e-3, batch=32, weighted CE для дисбаланса.
- Печатает train/val accuracy, precision, recall, F1.
- Сохраняет веса в `models/vuln_head.pt` (~2 КБ).

Ожидаемые метрики на валидации: F1 ≈ 0.78–0.85.

### 5. Smoke-test инференса

```bash
python -m code_analysis.test_bert
```

Прогоняет BERT-скоринг на `samples/vulnerable_app.py` и `samples/clean_app.py`,
печатает per-функцию вероятности. На уязвимом коде ожидается P_vuln > 0.7
для большинства функций; на чистом — P_vuln < 0.3.

### 6. Запустить сервер с BERT

```bash
WITH_BERT=1 python main.py
```

Открыть `http://127.0.0.1:8000`, нажать «Уязвимый пример» → «Анализировать».
В findings появится строка `BERT_score=0.XX` рядом с `P_ast`. Risk и
confidence пересчитаются с учётом нового сигнала.

### 7. Собрать Docker-образ с BERT

```bash
docker build -f Dockerfile.bert -t vuln-analyzer:bert .
docker run --rm -p 8000:8000 -e WITH_BERT=1 vuln-analyzer:bert
```

В этот образ запекаются модель GraphCodeBERT и обученный head, поэтому
размер ~2.5 ГБ. Запуск контейнера — мгновенный, без скачивания.

### 8. CI: матрица сборки `:latest` и `:bert`

После пуша в `main` workflow `build-image.yml` соберёт **два образа**:
- `ghcr.io/<owner>/<repo>:latest` — без BERT, ~500 МБ
- `ghcr.io/<owner>/<repo>:bert` — с BERT, ~2.5 ГБ

В docker-compose можно переключаться через `IMAGE` env var.

---

## Файлы, которые добавятся

```
app/
├── BERT_PLAN.md                       ← этот файл
├── requirements-bert.txt              ← torch, transformers, datasets
├── Dockerfile.bert                    ← образ с моделью
├── code_analysis/
│   ├── prepare_data.py                ← Devign + синтетика
│   ├── synthetic.py                   ← генератор Python-примеров
│   ├── embed_dataset.py               ← одноразовое вычисление эмбеддингов
│   ├── train_head.py                  ← обучение головы
│   ├── bert_scorer.py                 ← инференс
│   ├── test_bert.py                   ← smoke-test
│   └── analyzer.py                    ← обновлён: ансамбль AST + BERT
├── data/                              ← датасет + эмбеддинги (.gitignore)
│   ├── dataset.jsonl
│   └── embeddings.pt
├── models/
│   └── vuln_head.pt                   ← дообученные веса (коммитим)
└── .github/workflows/build-image.yml  ← обновлён под матрицу
```

---

## Что коммитить, а что нет

В `.gitignore`:
```
data/
~/.cache/huggingface/
```

Коммитим только:
- Код (`*.py`)
- `models/vuln_head.pt` (~2 КБ — обученная голова)
- `requirements-bert.txt`, `Dockerfile.bert`

GraphCodeBERT (500 МБ) **не** в репо — он скачивается из HuggingFace при сборке Docker-образа или при первом локальном запуске.
