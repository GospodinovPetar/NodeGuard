# Sprint 3 — SARIF, Catalog extensibility, Nikto

2 седмици. Стъпва върху Sprint 1+2 (async pipeline, dashboard, Security Profiles). Каталогът (`catalog` app) е още празен Django stub — този sprint го прави реален: on/off toggle UI, 3-ти вграден scanner (Nikto), и вратичка за custom tools през SARIF, без да пипаме core dispatch кода.

## Sprint Goal

Non-technical потребител вижда кои tools са налични/липсващи в един каталог изглед (не само dropdown), може да качи резултат от свой SARIF-съвместим tool, и Nikto работи като трети вграден scanner.

## Definition of Done

- [ ] `NiktoScanner` implementиран + baked в `Dockerfile` (Perl dependency, същия pattern като nmap/gobuster)
- [ ] `catalog` app реален: on/off toggle страница
- [ ] SARIF parser/importer → normalизира в `Finding`
- [ ] Backend за custom-tool registration/SARIF upload
- [ ] Denis-ов custom SARIF scanner като end-to-end proof

## Бележка: catalog infra вече частично готова

`scanners/registry.py` вече има `tool_status()` и `available_scanners()` (Радо ги добави в Sprint 1 за validate_target работата) — връщат кой registered tool е инсталиран (`shutil.which` под капака). Каталог UI-ът не тръгва от нулата, директно ги ползва вместо да преоткрива detection логиката.

## Задачи

### Петър — Nikto + custom-tool backend

- `NiktoScanner(BaseScanner)` — build_command/parse_output по установения pattern (Gobuster/Nmap), baked в `Dockerfile` (apt package `nikto`, налична в Debian repos)
- Backend за custom-tool registration/upload — form + model за качен SARIF-emitting external tool (метаданни + upload path)
- **Learning nugget**: 3-ти scanner (продължение на Gobuster от Sprint 1) — Perl dependency detection през същия `is_available()`/`shutil.which` механизъм

### Радо — SARIF parser + dynamic registry

- SARIF parser/importer — SARIF е JSON, `Finding` вече е "SARIF-shaped" по дизайн (виж [00_BASELINE_PLAN.md](00_BASELINE_PLAN.md)), така че mapping-ът е директен: SARIF `results[]` → `Finding` редове
- Разширява registry-то за dynamic/DB-driven registration (не само `@register_scanner` decorator при import) — custom tools от каталога се регистрират runtime, не в код

### Денис — catalog UI + custom SARIF scanner

- `catalog` app UI — on/off toggle страница, ползва `tool_status()`/`available_scanners()` от registry-то
- SARIF upload форма (за custom tools)
- Overall dashboard UX polish pass
- **Learning nugget**: строи собствен tiny custom SARIF-emitting scanner (напр. проверка за липсващи HTTP security headers през `requests`) — end-to-end тества catalog feature-а, който сам гради; първи негов реален security tool, start to finish
