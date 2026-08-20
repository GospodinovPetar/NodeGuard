# Sprint 2 — Dashboard, Analytics, Reporting

2 седмици. Стъпва върху Sprint 1 (`Target`/`Scan`/`Finding` models, `NmapScanner`+`GobusterScanner`, async pipeline). Findings вече се пишат в DB и се виждат live на `/scanners/` — Sprint 2 ги превръща в реален dashboard: severity breakdown, история, PDF export, готови presets вместо ръчно писане на target+scanner всеки път.

## Sprint Goal

`/` (dashboard) спира да е статична страница — показва агрегирани данни (severity counts, scan history) с графики. Потребителят може да избере готов "Quick Scan" preset вместо да помни кой scanner с какви флагове да пусне.

## Definition of Done

- [x] ~~**Prerequisite (Rado)**: `BaseScanner.build_command(target)` → `build_command(target, options: dict)`~~ — **вече направено в Sprint 1**, не в Sprint 2. Стана блокиращо за Денис-овия Sprint 1 тикет (scan-options UI), затова се качи там заедно с него. Виж архитектурната бележка в [01_SPRINT_1.md](01_SPRINT_1.md), която е маркирана done.
- [x] Severity classification — центрирана/tunable, вместо hardcoded per-scanner (виж бележката по-долу)
- [x] `SecurityProfile` model (Quick Scan / Deep Web Scan presets)
- [x] Dashboard aggregation view на `/` — **target-centric** (виж бележката по-долу), не плосък scan feed
- [x] Target detail страница — scan история per asset + overall severity
- [x] **≥80% test coverage**, enforced в CI (реално 100%; прагът е под, не цел)
- [ ] Severity pie chart + trend-over-time line chart (Chart.js) — Денис
- [ ] PDF export (weasyprint) — Денис, **per target**, не per scan
- [ ] Security Profile picker UI — Денис

## Архитектурна промяна: dashboard-ът е target-centric, не scan-centric

Първата версия на dashboard-а показваше глобални броячи + плосък "Recent scans" feed. Проблемът: **scan-ът не е това, което интересува потребителя** — активът е. Никой не пита "какво намери scan #47", пита "сигурен ли е `example.com`". Scan-ът е *доказателство за* даден asset. Така са устроени и реалните инструменти (Nessus/Qualys/DefectDojo).

Моделът вече го поддържаше — `Target` FK от `Scan` (Петровата Sprint 1 нормализация) съществува точно за това, но UI-ят не ползваше измерението. Плюс: самият Sprint 2 тикет на Петър казваше "исторически изглед **per target**", което се загуби при имплементацията.

Затова:

- `/` показва **targets, подредени по риск** (най-опасният отгоре), не последните scan-ове
- `/scanners/targets/<pk>/` — всичко за един asset: текущ risk + пълна scan история
- PDF export-ът на Денис става **per target** (доклад за актив, комбиниращ nmap+gobuster доказателства), не per scan — така е и много по-полезен документ

### Правилото за "overall severity" (важно, има капан)

Наивното `max(severity на всички findings)` е **грешно**: оправяш telnet, пускаш нов scan, а target-ът завинаги си остава HIGH, защото старият finding стои в таблицата. Но и "само последният scan" е грешно — ако последно си пуснал gobuster, мълчаливо губиш всички nmap резултати.

Правилото е: **последният завършил scan за всеки scanner поотделно**, обединени. nmap и gobuster отговарят на различни въпроси, така че искаш най-новия отговор от всеки. Старите scan-ове остават видими като история, маркирани `superseded`.

Това съзнателно **не** е finding-level dedup (open/fixed/reopened state) — това е Sprint 3 територия заедно със SARIF.

## Бележка: severity ruleset — ✅ направено

Severity беше hardcoded вътре във всеки scanner поотделно: `GobusterScanner` (200→low, друго→info) и `NmapScanner` (`_RISKY_SERVICES` dict) — работеше, но правилата не се виждаха от едно място и всеки нов scanner ги преоткриваше. Сега политиката живее в [scanners/severity_rules.py](../../NodeGuard/scanners/severity_rules.py); моделът не е пипан (`Finding.severity` си остава string).

## Задачи

### Петър — severity ruleset + coverage gate ✅ done (dashboard частта е презаписана от Радо)

- ✅ Dashboard aggregation queries — Петър ги написа, но първата версия беше scan-centric; Радо ги преработи на target-centric (виж архитектурната промяна по-горе). Stat cards / status breakdown / tools панелите му остават.
- ✅ ~~Scan history list/detail страници~~ — направено от Радо като **target detail** страница, което тикетът вече казваше ("исторически изглед per target"), но не беше имплементирано така
- ✅ **Learning nugget: централизиран severity ruleset** — [scanners/severity_rules.py](../../NodeGuard/scanners/severity_rules.py). `parse_output()` вече не решава сам колко сериозен е даден finding; пита ruleset-а за `Rule` (severity + rule_id). Радо беше добавил само наредбата (`Severity.rank`/`worst()`) — самите класификационни правила бяха останалите.
  - **nmap**: правилата се преместиха as-is (без промяна на поведение), но разделени по *причина* — `_CLEARTEXT_SERVICES` (telnet/rlogin/rsh/rexec/vnc/ftp — креденшълите минават в чист текст) срещу `_EXPOSED_INFRA_SERVICES` (SMB/RDP/MySQL/Postgres/Mongo/Redis — datastores, които не бива да гледат навън). Причината, не само стойността.
  - **gobuster**: старото правило беше `200 → LOW, друго → INFO` с TODO коментар. Проблемът: третира `/images` и `/.env` еднакво, а те не са едно и също. Новото правило гледа **какво** е изложено: readable secret material (`.env`, `id_rsa`, `.htpasswd`, `credentials`) → **CRITICAL**; source/диагностика (`.git`, `backup`, `phpinfo.php`, `server-status`) → **HIGH**; admin интерфейси (`admin`, `wp-admin`, `phpmyadmin`, `console`) → **MEDIUM**; всичко друго сервирано → **LOW**.
  - Ескалира се само 2xx: `.env`, който връща 403, е **обратното** на finding — пътят съществува, но не дава нищо. Редиректи/401/403 остават INFO.
  - Verified с реален binary, не само fixture: вдигнат тестов сайт с `.env`/`.git`/`admin`/`images`, реален `gobuster dir` през worker container-а → `CRITICAL gobuster/exposed-secret .env`, `HIGH .git`, `MEDIUM admin`, `LOW images`. Dashboard-ът вече показва истински severity spread, вместо всичко да е INFO/LOW — което е и предусловие Денисовата pie chart да не излезе едноцветна.
- ✅ **Coverage gate**: `coverage` в `requirements-dev.txt`, настройки в [NodeGuard/.coveragerc](../../NodeGuard/.coveragerc) (за да се държи еднакво локално и в CI), `coverage run` + `coverage report` стъпки в [ci.yml](../../.github/workflows/ci.yml). Прагът е `fail_under = 80` — **под, не цел**; реалното покритие е **100%** (86 теста). Проверено, че gate-ът реално чупи build при по-нисък процент, не просто минава.

> ⚠️ Намерен pre-existing бъг (не в scope на този тикет, за Радо): `GobusterScanner` не override-ва `validate_target()`, така че base валидацията (host/IP/CIDR) отхвърля всеки target с порт или схема — `example.com:8080` и `http://example.com` дават `refusing to scan target`, въпреки че placeholder-ът във формата рекламира `http://host` и `build_command` умее да сглобява схема. Docstring-ът на `BaseScanner.validate_target` дори казва „Override in scanners whose targets aren't hosts (e.g. gobuster takes a URL)" — просто не е направено.

### Радо — options generalization + Security Profiles

- ~~`BaseScanner.build_command` generalization~~ — **направено в Sprint 1** (виж DoD по-горе); не остана работа тук
- ✅ `SecurityProfile` model — именувани presets = bundle от scanner_name + options ([scanners/models.py](../../NodeGuard/scanners/models.py))
  - `Quick Scan` (nmap `-sV`) и `Deep Web Scan` (gobuster + bundled wordlist) се seed-ват през data migration `0005_builtin_security_profiles`, не hardcoded в кода — екипът може да ги редактира/добавя от admin-а без deploy
  - `profile.create_scan(target)` материализира preset-а в `Scan` ред (копие на options, за да не пренаписва история при по-късна редакция на профила)
  - Регистриран в Django admin, за да е използваем преди Денис-овия picker UI
- **Security nugget**: `BaseScanner.profile_options` allowlist. `build_command()` слага option стойности директно в argv, а `SecurityProfile.options` е свободен `JSONField` — без allowlist профил с `{"wordlist_path": "/etc/passwd"}` кара gobuster да чете произволен файл и да връща съвпадащите редове като findings. Всеки scanner трябва явно да opt-in-не кои ключове приема (nmap: `service_detection`/`aggressive`; gobuster: нищо — wordlist-ът идва per-scan от валидиран upload). `save()` вика `full_clean()`, за да не може невалиден профил да влезе в базата и програмно.
  - Verified с реален pipeline: seeded `Quick Scan` профил пусна истински nmap в контейнера и откри работещия dev server (`localhost:8000/tcp open — http (WSGIServer 0.2)`); опитите за `wordlist_path` и за нерегистриран scanner бяха отхвърлени
- ✅ **Target-centric dashboard + target detail страница** (поето от Петровия тикет, за да не блокира — виж архитектурната промяна по-горе)
  - `Severity.rank`/`parse()`/`worst()` в [scanners/base.py](../../NodeGuard/scanners/base.py) — наредбата живее с enum-а, вместо да се преоткрива като list във всеки view (`dashboard/views.py` имаше собствено `_SEVERITY_ORDER`)
  - `Target.latest_scans()` / `current_findings()` / `current_severity()` — правилото "последен scan per scanner"
  - `/` подрежда targets worst-first; `/scanners/targets/<pk>/` показва current findings + пълна история с `current`/`superseded` маркери
  - Бонус fix намерен при реален преглед в браузъра: "Findings by severity" панелът броеше **всички** findings някога, така че dashboard-ът показваше `High: 1`, докато нито един target не беше High. Сега брои само current findings — иначе Денисовата pie chart щеше да наследи същата грешка.
- ⏳ Ревю на Петровия severity ruleset — **отблокирано**, [scanners/severity_rules.py](../../NodeGuard/scanners/severity_rules.py) е готов. Конкретно за ревю: (1) `.env`/`id_rsa` като CRITICAL прекалено ли е, или е точно; (2) Redis/MongoDB стоят MEDIUM — по подразбиране са без auth, аргумент за HIGH има; (3) списъците с пътища са малки и вързани към bundled `common.txt` — при по-голям wordlist ще искат разширяване или pattern matching (`*.sql`, `*.bak`) вместо точно съвпадение.

### Денис — PDF export + charts + profile picker

> Бележка след target-centric промяната: PDF-ът вече е **per target** — бутон на `/scanners/targets/<pk>/`, който сглобява доклад от `target.current_findings()` (текущо състояние) + `target.scans` (историята зад него). Chart.js графиките също вземат данни от target-centric context-а, не от глобален scan feed.

- PDF export през weasyprint (HTML/CSS report template — реално frontend работа)
- Severity pie chart + trend line (Chart.js) на dashboard-а
- Security Profile picker UI (замества/допълва raw scanner dropdown-а от `/scanners/`)
- **Learning nugget**: research какво трябва да съдържа професионален security report (executive summary структура, severity цветови конвенции) → оформя report template-а по-горе
