# NodeGuard

Локален security scanner toolbox — Django backend, HTMX + Alpine.js + Tailwind frontend, SQLite.

Планиране на sprint-овете: [docs/planning](docs/planning).

## Стартиране (Docker, препоръчано)

```bash
docker compose up --build
```

Отваря на http://localhost:8000

## Стартиране (локално, venv)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cd NodeGuard
python manage.py migrate
python manage.py runserver
```

Отваря на http://127.0.0.1:8000

## Lint

```bash
ruff check NodeGuard
black --check NodeGuard
```

## Забележка за frontend-а

Tailwind е закачен през Play CDN (`cdn.tailwindcss.com`) — нулев build step, добро за local dev/MVP. За production ще трябва compile-нат CSS (standalone Tailwind CLI), виж backlog.
