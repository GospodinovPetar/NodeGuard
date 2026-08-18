# Baseline Plan — NodeGuard

Соло план за Петър, преди първия push в GitHub. Не се дели на 3 задачи — това е фундаментът, върху който Sprint 1 се качва.

## Цел

Празен, но напълно работещ Django skeleton: стартира локално и през Docker, минава CI (lint + test + docker build), готов за отваряне на браузър и виждане на нещо реално.

## Definition of Done

- [x] Django проект + 3 apps (`scanners`, `catalog`, `dashboard`) създадени и регистрирани в `INSTALLED_APPS`
- [x] SQLite работи (`python manage.py migrate` минава чисто)
- [x] Base template с HTMX + Alpine.js + Tailwind (CDN, без build pipeline) в `templates/base.html`
- [x] Dashboard начална страница (`/`) рендерва base template-а
- [x] `Dockerfile` + `docker-compose.yml` — `docker compose up --build` вдига сайта на `localhost:8000`
- [x] GitHub Actions workflow (`.github/workflows/ci.yml`): lint (ruff+black) → test (`manage.py test`) → docker build, ubuntu-latest runner
- [x] `.gitignore` покрива `.venv/`, `__pycache__/`, `db.sqlite3`, `staticfiles/`, `.env`
- [x] `README.md` с install/run инструкции (venv вариант + docker вариант)
- [x] Scanner plugin registry (`BaseScanner` + `@register_scanner`) + demo scanner proof-of-concept
- [x] Async task queue (Huey/SQLite) с отделен `worker` docker service, `Scan`/`Finding` models
- [x] `/scanners/` страница с trigger + HTMX live polling
- [ ] Push в GitHub → отваря се Sprint 1 за екипа

## Технически бележки за екипа (Радо/Денис ще виждат това при клонинг)

- **Frontend**: няма React, няма npm/webpack. Tailwind е закачен през Play CDN script tag — нулев build step, добро за local dev. За production compile трябва standalone Tailwind CLI (виж `04_BACKLOG.md`).
- **HTMX + Alpine**: закачени през CDN в `templates/base.html`. Ще се ползват от Sprint 1 нататък за partial updates (напр. live scan progress) без пълен page reload.
- **Apps структура**: `scanners` (BaseScanner + конкретните tool wrappers), `catalog` (App Store toggle + tool registry), `dashboard` (начална страница, графики, PDF export). Моделите (`Scan`, `ScanResult`, `Target`, `Vulnerability`) идват в Sprint 1/2, не в baseline.
- **Docker**: `docker-compose.yml` bind-mount-ва `./NodeGuard` в контейнера — код промените се отразяват без rebuild, `db.sqlite3` живее на host-а (gitignored).
- **CI**: `docker-build` job-ът само проверява че image-ът се build-ва успешно (без push към registry за момента).

## Scalable архитектура (добавено след първоначалния baseline)

Основен принцип: **общ plugin registry + async task queue**, така че добавянето на нов scanner в Sprint 1+ не пипа core dispatch/execution код.

- **`scanners/base.py`** — `BaseScanner` ABC (`build_command`, `parse_output`, `is_available` през `shutil.which`) + `Finding`/`Severity` — SARIF-shaped intermediate representation, еднаква за всички tools (вкл. бъдещи custom SARIF tools от каталога).
- **`scanners/registry.py`** — `@register_scanner("name")` decorator + `get_scanner`/`list_scanners`. Нов tool = нов файл със subclass + decorator, нищо друго не се пипа.
- **`scanners/demo_scanner.py`** — proof-of-concept scanner (не реален security tool, ползва `sys.executable`), доказва че registry+async+parsing работят end-to-end без nmap/gobuster инсталирани. Sprint 1 копира тази форма за `NmapScanner`/`GobusterScanner`.
- **Async execution: Huey (SqliteHuey, без Redis)** — `scanners/tasks.py::run_scan` е `@db_task()`. Scan-ове могат да текат минути (nmap/gobuster) без да блокират Django request-response цикъла. `docker-compose.yml` има отделен `worker` service (`manage.py run_huey`); в тестове `HUEY["immediate"]=True` за синхронно изпълнение.
- **`Scan`/`Finding` models** — `Scan.status` (pending/running/done/failed) + `Finding` (severity/message/raw, FK към Scan). `Target` като отделен модел е Sprint 1 refinement, не blocking сега.
- **`/scanners/` страница** — trigger бутон + HTMX polling (`hx-trigger="every 2s"`) на partial view, доказва live async update без page reload и без websockets/SSE инфраструктура.

Sprint 1 бележка: Rado/Petar вече не пишат `BaseScanner`/registry от нулата — те implement-ват `NmapScanner`/`GobusterScanner` върху вече установения pattern (по-фокусирано learning: parsing + subprocess за конкретен tool, не design на plumbing-а).

## Проверено локално

- `python manage.py migrate` — чисто, без грешки
- `python manage.py runserver` → `GET /` връща 200, base template + dashboard/index.html рендерват правилно
- `python manage.py test scanners` — 3/3 минават (registry, availability, async run produces Finding)
- `ruff check NodeGuard` + `black --check NodeGuard` — чисто
- `docker build .` — успешен build
- `docker compose up --build` (web + worker) → `GET http://localhost:8000/scanners/` връща 200; demo scan enqueued от web, executed от отделен `worker` container (потвърдено в logs), status минава pending → running → done, finding се появява в HTMX partial
