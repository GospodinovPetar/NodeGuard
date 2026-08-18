# Backlog — неразпланирано

Идеи извън Sprint 1-3, без гарантиран ред. Взимат се, когато има капацитет/желание.

- **Още scanners** (nuclei, sqlmap wrapper, ffuf) — pattern-ът е установен: apt/binary bake в `Dockerfile` (виж [README.md](../../README.md), раздел "Добавяне на нов scanner tool") + `BaseScanner` subclass + register в `apps.py`
- **Периодични/scheduled scans** — Huey вече поддържа `periodic_task` (cron-style decorator) нативно, не трябва нова опашка/Celery миграция
- **Multi-target batch scanning** — един trigger → N targets наведнъж
- **Multi-user/auth support** — в момента приложението е single-user (local tool), няма Django auth wiring
- **CSV/JSON export** алонгсайд PDF export-а от Sprint 2
- **Scan diffing** — регресионно сравнение между два scan-а на същия target (нови/изчезнали findings)
- **Slack/email notification** при critical finding
- **Nikto като sidecar container** — ако Perl dependency-то се окаже неудобно да живее в основния `web`/`worker` image (виж Sprint 3), изолирай го в отделен container с малък HTTP wrapper вместо да го bake-ваш directly
- **Compiled Tailwind** (standalone CLI) вместо Play CDN — CDN версията е добра за local dev/MVP (виж baseline doc), но не е production-ready (runtime JIT compile, no purge)
- **Dark/light theme toggle** — в момента dark-only
- **Rate limiting / concurrency cap** на едновременни scans — в момента нищо не пречи на потребител да опашка 50 scan-а наведнъж
