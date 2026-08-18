# NodeGuard

Локален security scanner toolbox — Django backend, HTMX + Alpine.js + Tailwind frontend, SQLite.

Планиране на sprint-овете: [docs/planning](docs/planning).

## Стартиране (Docker, препоръчано)

```bash
docker compose up --build
```

Отваря на http://localhost:8000. Docker image-ът вече идва с **nmap** и **gobuster** предварително инсталирани — нулев ръчен setup.

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

При локален (не-Docker) run scanner tool-овете (nmap, gobuster, ...) трябва да са инсталирани сами от теб и достъпни в `PATH` — приложението ги детектва runtime (`shutil.which`) и просто disable-ва бутона за липсващ tool, не крашва. Официални install инструкции:

- nmap: https://nmap.org/download.html (или `brew install nmap` / `apt install nmap` / `winget install Insecure.Nmap`)
- gobuster: https://github.com/OJ/gobuster#installation

## Добавяне на нов scanner tool (Docker)

Tools се bake-ват директно в `Dockerfile`, не се инсталират ръчно от потребителя. За да добавиш нов tool (напр. Nikto за Sprint 3):

1. **Инсталирай binary-то в `Dockerfile`.** Ако има apt package, най-просто:

   ```dockerfile
   RUN apt-get update && apt-get install -y --no-install-recommends \
           nmap nikto curl ca-certificates \
       && ...
   ```

   Ако няма apt package (както gobuster) — свали prebuilt binary от GitHub releases на tool-а, виж как е направено в `Dockerfile` за gobuster (`curl` + `tar -xzf ... -C /usr/local/bin`).

2. **Напиши `BaseScanner` subclass** в `NodeGuard/scanners/<tool>_scanner.py` — копирай формата от [gobuster_scanner.py](NodeGuard/scanners/gobuster_scanner.py) или [demo_scanner.py](NodeGuard/scanners/demo_scanner.py): `binary_name`, `build_command(target)`, `parse_output(raw_output)`.

3. **Регистрирай го** — добави `from . import <tool>_scanner` в `NodeGuard/scanners/apps.py::ready()` (decorator-ът `@register_scanner("name")` в самия файл прави останалото).

4. `docker compose up --build` — новият tool се появява автоматично в scan-trigger dropdown-а (или disabled, ако забравиш стъпка 1 и binary-то липсва).

Не пипаш core dispatch/execution код (`registry.py`, `tasks.py`) — точно затова е plugin архитектурата.

## Lint

```bash
ruff check NodeGuard
black --check NodeGuard
```

## Забележка за frontend-а

Tailwind е закачен през Play CDN (`cdn.tailwindcss.com`) — нулев build step, добро за local dev/MVP. За production ще трябва compile-нат CSS (standalone Tailwind CLI), виж backlog.
