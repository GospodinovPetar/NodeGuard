# Sprint 1 — Core scanning engine

2 седмици. Стъпва върху plugin registry + async task queue, вече вкарани в baseline (виж [00_BASELINE_PLAN.md](00_BASELINE_PLAN.md)) — никой тук не пише `BaseScanner`/registry от нулата, всеки implement-ва/юзва вече установения pattern.

## Sprint Goal

Реален target-driven flow: потребител въвежда target, избира scanner, вижда резултата live — с 2 работещи реални tool-а (gobuster + nmap) плюс UI, което не се чупи ако tool-ът липсва.

## Definition of Done

- [x] `Target` model + FK от `Scan` (нормализирано)
- [x] Реална scan-trigger форма (target input + scanner dropdown), disabled option ако tool-ът липсва
- [x] `GobusterScanner` implementиран, регистриран, тестван (parse_output + build_command), verified с реален scan
- [x] nmap+gobuster bake-нати в Docker image-а (замества per-OS install scripts — виж baseline doc)
- [x] `NmapScanner` implementиран (Rado)
- [ ] Catalog on/off toggle UI + scan-options dropdown research (Denis)
- [ ] Custom wordlist upload за gobuster (Denis) — fallback към bundled `common.txt` ако няма upload

## Архитектурна бележка: options за scanners

`BaseScanner.build_command(target)` в момента взима само target — gobuster wordlist-ът и nmap флаговете (`-sV`/`-A`) са hardcoded. За да не се превърне всеки нов option в one-off промяна на сигнатурата, `build_command` трябва да стане `build_command(target, options: dict)` — общ механизъм за всички tools (wordlist за gobuster, флагове за nmap, и т.н. занапред). Това е малка промяна в `scanners/base.py`/`tasks.py` (Петър/Рado координират, засяга и двата scanner-а), върху която се качва Денис-овата UI работа по-долу.

## Задачи

### Петър — models + trigger glue + tool installation ✅ done

- `Target`/`Scan` модели (FK нормализация) — [scanners/models.py](../../NodeGuard/scanners/models.py)
- Реална scan-trigger форма + view с валидация (празен target / непознат scanner / tool не е инсталиран → error message, не crash) — [scanners/views.py](../../NodeGuard/scanners/views.py)
- **Learning nugget**: `GobusterScanner` (subclass на `BaseScanner`) — build_command (dir mode + bundled wordlist), regex parse_output, severity heuristic (200→low, друго→info)
- Tool installation: първи опит беше `setup.ps1` (Windows-only, winget) — отхвърлен като идея, защото не scale-ва per-OS/per-tool (виж baseline doc, раздел "Tool installation"). Вместо това: nmap+gobuster bake-нати директно в `Dockerfile` — `docker compose up` = zero setup.
- 12 unit теста + **реален (не canned) end-to-end тест**: вдигнат tiny HTTP server, реален `gobuster dir` scan през docker worker container-а намери всички 3 real файла (`admin`/`login`/`backup`, status 200) — доказва пълния pipeline с истински binary
- ruff+black чисто

### Радо — `NmapScanner` ✅ done

- `NmapScanner(BaseScanner)` — [scanners/nmap_scanner.py](../../NodeGuard/scanners/nmap_scanner.py): build_command (`nmap -sV -oX - <target>`), parse_output през stdlib `xml.etree.ElementTree` (не `python-nmap` — той spawn-ва nmap сам, което би заобиколило единствения execution path през `scanners/tasks.py`)
- Severity heuristic за отворени портове: cleartext/legacy services (telnet, rlogin, VNC → `HIGH`; FTP, SMB, MySQL/Postgres/Mongo/Redis → `MEDIUM`) се flag-ват като `nmap/insecure-service`; всичко останало отворено е `INFO` `nmap/open-port` (стъпка към Sprint 2 класификацията, не финална)
- **Learning nugget / security hardening**: `BaseScanner.validate_target()` — argv listата спира shell injection, но не argument injection (target `-oN /etc/crontab` иначе се чете от nmap като flag); прилага се преди `build_command` за всеки scanner, не само nmap
- `ToolStatus`/`tool_status()` в [scanners/registry.py](../../NodeGuard/scanners/registry.py) — availability layer върху `shutil.which`, консумиран от Денис-овата catalog toggle UI
- Тества се по same pattern като `GobusterScannerTests`: canned XML fixture ([scanners/fixtures/nmap_localhost.xml](../../NodeGuard/scanners/fixtures/nmap_localhost.xml), включва closed/filtered портове за да пинне "само open" правилото) → findings, без нужда от реален nmap install
- Допълнителен **live** тест (`NmapLiveTests`, gated с `@skipUnless(shutil.which("nmap"))`) — verified с реален `docker build` + `docker run` след като Петър bake-на nmap в image-а: истинският бинар и парсерът работят end-to-end, не само срещу fixture-а
- Fix: CI-то е стартирало `manage.py test` от repo root-а вместо от `NodeGuard/`, което тихо е discover-вало 0 теста — оправено в `.github/workflows/ci.yml` с `working-directory`
- Fix: `test_unavailable_scanner_creates_no_scan` (Петъровия TriggerScanViewTests) е бил environment-dependent — приемал е, че gobuster никога не е инсталиран; счупил се веднага щом Петър го bake-на в Docker image-а. Разделен на два детерминистични теста: unregistered-scanner (истинско "непознат scanner" branch-а) и uninstalled-scanner (мокнат `is_available() → False`, не зависи от кои tools реално стоят на машината)
- ruff+black чисто

### Денис — catalog toggle UI + scan-options research

- Frontend: catalog on/off страница, показваща `list_scanners()` + `is_available()` за всеки — реюзва вече наличния pattern от scan-trigger dropdown-а (disabled + "не е инсталиран")
- Scan-trigger UI подобрение: dropdown/checkboxes за scan-type флагове (nmap `-sV`/`-A`) вместо hardcoded defaults в `build_command`
- **Custom wordlist upload за gobuster**: file upload поле в scan-trigger формата — ако потребителят качи `.txt`, той се ползва вместо bundled `common.txt`. Съхранение: `FileField` на `Scan` (или отделен upload → temp path, подаден през `options` dict от архитектурната бележка по-горе). Validation: разумен size limit (напр. 1-2 MB), plain text.
- **Learning nugget**: research на Nmap/Gobuster flags → превръща се в конкретните UI опции по-горе
