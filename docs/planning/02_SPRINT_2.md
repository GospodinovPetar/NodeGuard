# Sprint 2 — Dashboard, Analytics, Reporting

2 седмици. Стъпва върху Sprint 1 (`Target`/`Scan`/`Finding` models, `NmapScanner`+`GobusterScanner`, async pipeline). Findings вече се пишат в DB и се виждат live на `/scanners/` — Sprint 2 ги превръща в реален dashboard: severity breakdown, история, PDF export, готови presets вместо ръчно писане на target+scanner всеки път.

## Sprint Goal

`/` (dashboard) спира да е статична страница — показва агрегирани данни (severity counts, scan history) с графики. Потребителят може да избере готов "Quick Scan" preset вместо да помни кой scanner с какви флагове да пусне.

## Definition of Done

- [x] ~~**Prerequisite (Rado)**: `BaseScanner.build_command(target)` → `build_command(target, options: dict)`~~ — **вече направено в Sprint 1**, не в Sprint 2. Стана блокиращо за Денис-овия Sprint 1 тикет (scan-options UI), затова се качи там заедно с него. Виж архитектурната бележка в [01_SPRINT_1.md](01_SPRINT_1.md), която е маркирана done.
- [ ] Severity classification — центрирана/tunable, вместо hardcoded per-scanner (виж бележката по-долу)
- [x] `SecurityProfile` model (Quick Scan / Deep Web Scan presets)
- [ ] Dashboard aggregation view на `/` (severity counts, scan counts)
- [ ] Severity pie chart + trend-over-time line chart (Chart.js)
- [ ] PDF export (weasyprint)
- [ ] Scan history list/detail страници

## Бележка: severity вече не е "някой ден" проблем

Severity в момента е hardcoded вътре във всеки scanner поотделно: `GobusterScanner` (200→low, друго→info) и `NmapScanner` (`_RISKY_SERVICES` dict → high/medium, друго→info) — работи, но правилата не се виждат/тunват от едно място и всеки нов scanner ги преоткрива. Не сменяме модела (`Finding.severity` си остава), но извличаме класификацията в общо място, което Sprint 2 може да прегледа/подобри без да пипа parse_output-ите.

## Задачи

### Петър — dashboard queries + severity ruleset

- Dashboard aggregation queries (severity counts, scan counts по status) — рендерва се на `/`
- Scan history list/detail страници (различно от live `/scanners/` таблицата — исторически изглед per target)
- **Learning nugget**: изважда severity логиката от `GobusterScanner`/`NmapScanner` в общ, ревюирано от Радо ruleset (напр. shared mapping/function) — принуждава го да разсъждава кое прави finding severe, не просто да го копира

### Радо — options generalization + Security Profiles

- ~~`BaseScanner.build_command` generalization~~ — **направено в Sprint 1** (виж DoD по-горе); не остана работа тук
- ✅ `SecurityProfile` model — именувани presets = bundle от scanner_name + options ([scanners/models.py](../../NodeGuard/scanners/models.py))
  - `Quick Scan` (nmap `-sV`) и `Deep Web Scan` (gobuster + bundled wordlist) се seed-ват през data migration `0005_builtin_security_profiles`, не hardcoded в кода — екипът може да ги редактира/добавя от admin-а без deploy
  - `profile.create_scan(target)` материализира preset-а в `Scan` ред (копие на options, за да не пренаписва история при по-късна редакция на профила)
  - Регистриран в Django admin, за да е използваем преди Денис-овия picker UI
- **Security nugget**: `BaseScanner.profile_options` allowlist. `build_command()` слага option стойности директно в argv, а `SecurityProfile.options` е свободен `JSONField` — без allowlist профил с `{"wordlist_path": "/etc/passwd"}` кара gobuster да чете произволен файл и да връща съвпадащите редове като findings. Всеки scanner трябва явно да opt-in-не кои ключове приема (nmap: `service_detection`/`aggressive`; gobuster: нищо — wordlist-ът идва per-scan от валидиран upload). `save()` вика `full_clean()`, за да не може невалиден профил да влезе в базата и програмно.
  - Verified с реален pipeline: seeded `Quick Scan` профил пусна истински nmap в контейнера и откри работещия dev server (`localhost:8000/tcp open — http (WSGIServer 0.2)`); опитите за `wordlist_path` и за нерегистриран scanner бяха отхвърлени
- ⏳ Ревю на Петровия severity ruleset — блокирано, Петър още не го е написал

### Денис — PDF export + charts + profile picker

- PDF export през weasyprint (HTML/CSS report template — реално frontend работа)
- Severity pie chart + trend line (Chart.js) на dashboard-а
- Security Profile picker UI (замества/допълва raw scanner dropdown-а от `/scanners/`)
- **Learning nugget**: research какво трябва да съдържа професионален security report (executive summary структура, severity цветови конвенции) → оформя report template-а по-горе
