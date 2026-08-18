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
- [x] Catalog on/off toggle UI + scan-options dropdown (Денис — виж бележката по-долу)
- [x] Custom wordlist upload за gobuster (Денис — виж бележката по-долу) — fallback към bundled `common.txt` ако няма upload

## Архитектурна бележка: options за scanners ✅ done

`BaseScanner.build_command(target)` взимаше само target — gobuster wordlist-ът и nmap флаговете (`-sV`/`-A`) бяха hardcoded. Вместо one-off промяна на сигнатурата при всеки нов option, `build_command` стана `build_command(target, options: dict | None = None)` — общ механизъм за всички tools ([scanners/base.py](../../NodeGuard/scanners/base.py)).

Направено от Радо (не Петър, както бележката първоначално очакваше — Петър беше зает с `feat/target_scan`, а промяната стана директна зависимост на Денис-овия тикет по-долу, така че Радо я взе заедно с него):

- `NmapScanner`/`GobusterScanner`/`DemoScanner` всички приемат `options`, с backward-compatible default (`options=None` → същото поведение като преди)
- `Scan.options` (`JSONField`, default `{}`) пази избраните nmap флагове/gobuster wordlist между HTTP request-а и async execution-а — `tasks.run_scan` не взима нищо друго освен `scan_id`, затова options трябва да се материализират на `Scan` модела, не да се подават директно през заявка
- `scanners/tasks.py::run_scan` реконструира `options` dict от `scan.options` + `scan.wordlist.path` (ако има upload) преди `build_command`
- Verified с реален pipeline (не само unit тестове) — виж бележката в Радо/Денис секциите по-долу

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

### Денис — catalog toggle UI + scan-options research ⚠️ built by Rado to unblock, Денис still owns the review + learning nugget

Тикетът беше блокиращ за екипа, затова Радо го implementира изцяло вместо да чака — **но research nugget-ът (Nmap/Gobuster flag semantics) не е свършен от Денис**, само UI-то което тези флагове задвижват. Денис трябва да прегледа diff-а, разбере защо е направено така, и да довърши reasoning частта, иначе learning целта на тикета отпада.

- Frontend: catalog on/off страница ([templates/catalog/index.html](../../NodeGuard/templates/catalog/index.html), [catalog/views.py](../../NodeGuard/catalog/views.py)), показваща `list_scanners()` + `is_available()` за всеки — реюзва pattern-а от scan-trigger dropdown-а (disabled + "не е инсталиран"); нов `catalog` app URL (`/catalog/`) + nav линк в `base.html`
- Scan-trigger UI: Alpine `x-show` toggle-ва nmap `-sV`/`-A` checkboxes или gobuster wordlist upload според избрания scanner ([templates/scanners/scan_list.html](../../NodeGuard/templates/scanners/scan_list.html)) — вместо hardcoded defaults в `build_command`
- **Архитектурната промяна от бележката по-горе е направена**: `BaseScanner.build_command(target, options: dict | None = None)` — всеки scanner (`demo`/`nmap`/`gobuster`) приема options; `Scan.options` (`JSONField`) пази избраните nmap флагове между HTTP request-а и async execution-а през huey worker-а
- **Custom wordlist upload за gobuster**: `Scan.wordlist` `FileField` (`MEDIA_ROOT`/`MEDIA_URL` добавени в settings), validation във view-то (`.txt` extension, ≤2MB) преди `Scan` да се създаде — reject → error message, не crash, same pattern като target/scanner валидацията
- **Verified с реален pipeline** (не само unit тестове): вдигнат tiny HTTP server в worker container-а с маркер файл, качен custom 2-word wordlist през браузъра (истински `<input type=file>`, не mock) → real gobuster scan намери точно маркера, пропусна decoy-а — доказва че upload-натият wordlist наистина стига до binary-я, не bundled `common.txt`-то. Аналогично `nmap -A` (без `-sV`) откри service banner (`SimpleHTTPServer 0.6`) — потвърждава че checkbox-ите наистина местят флаговете.
- 12 нови теста (`CollectScanOptionsTests`, `CatalogIndexViewTests`, upload accept/reject cases) + `ruff`/`black` чисто, зелено и на bare host, и в Docker image-а
- **Learning nugget — все още за Денис**: research-ът зад защо `-sV` vs `-A` и gobuster wordlist size trade-offs все още не е направен от него — UI-то само ги показва като опции
