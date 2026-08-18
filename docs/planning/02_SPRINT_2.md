# Sprint 2 — Dashboard, Analytics, Reporting

2 седмици. Стъпва върху Sprint 1 (`Target`/`Scan`/`Finding` models, `NmapScanner`+`GobusterScanner`, async pipeline). Findings вече се пишат в DB и се виждат live на `/scanners/` — Sprint 2 ги превръща в реален dashboard: severity breakdown, история, PDF export, готови presets вместо ръчно писане на target+scanner всеки път.

## Sprint Goal

`/` (dashboard) спира да е статична страница — показва агрегирани данни (severity counts, scan history) с графики. Потребителят може да избере готов "Quick Scan" preset вместо да помни кой scanner с какви флагове да пусне.

## Definition of Done

- [ ] **Prerequisite (Rado)**: `BaseScanner.build_command(target)` → `build_command(target, options: dict)` — генерализацията, отбелязана в [01_SPRINT_1.md](01_SPRINT_1.md) като архитектурна бележка, но не имплементирана. Security Profiles не могат да съществуват чисто без нея (profile = target + scanner + options bundle).
- [ ] Severity classification — центрирана/tunable, вместо hardcoded per-scanner (виж бележката по-долу)
- [ ] `SecurityProfile` model (Quick Scan / Deep Web Scan presets)
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

- `BaseScanner.build_command` generalization (target + options dict) — блокиращо за всичко останало в този sprint
- `SecurityProfile` model — именувани presets (`Quick Scan`, `Deep Web Scan`) = bundle от scanner_name + options
- Ревю на Петровия severity ruleset

### Денис — PDF export + charts + profile picker

- PDF export през weasyprint (HTML/CSS report template — реално frontend работа)
- Severity pie chart + trend line (Chart.js) на dashboard-а
- Security Profile picker UI (замества/допълва raw scanner dropdown-а от `/scanners/`)
- **Learning nugget**: research какво трябва да съдържа професионален security report (executive summary структура, severity цветови конвенции) → оформя report template-а по-горе
