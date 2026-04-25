"""Entry point. Run with: python -m app.main

Starts the FastAPI demonstration server on http://127.0.0.1:8000
"""

from __future__ import annotations

import uvicorn


def main() -> None:
    uvicorn.run("app.web.app:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
