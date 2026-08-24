"""SARIF 2.1.0 → NodeGuard Finding normalization.

`Finding` is SARIF-shaped by design (see 00_BASELINE_PLAN.md), so importing a
SARIF document is a direct mapping: each run's `results[]` become findings,
keyed by `ruleId`. Severity is taken from the GitHub-style numeric
`security-severity` property when present, and falls back to the SARIF `level`.

Used by both the custom HTTP-headers scanner (which emits SARIF on stdout) and
the catalog's SARIF upload/import form, so any SARIF-compatible tool can feed
NodeGuard without touching the core dispatch code.
"""

from __future__ import annotations

import dataclasses
import json

from .base import Finding, Severity


class SarifParseError(ValueError):
    """The text wasn't SARIF we could read (bad JSON or wrong shape)."""


# SARIF result.level, used when there's no numeric security-severity score.
_LEVEL_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


@dataclasses.dataclass
class SarifReport:
    tool_name: str
    findings: list[Finding]


def parse(text: str) -> SarifReport:
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
        raise SarifParseError(f"not valid JSON: {exc}") from exc

    if not isinstance(doc, dict) or "runs" not in doc:
        raise SarifParseError("missing top-level 'runs' — is this SARIF?")

    tool_names: list[str] = []
    findings: list[Finding] = []
    for run in doc.get("runs") or []:
        driver = (((run or {}).get("tool") or {}).get("driver")) or {}
        tool_names.append(driver.get("name") or "unknown")
        rules = _rules_by_id(driver)
        for result in run.get("results") or []:
            findings.append(_finding(result or {}, rules))

    # dict.fromkeys keeps the tools in order without duplicates.
    tool_name = ", ".join(dict.fromkeys(tool_names)) or "unknown"
    return SarifReport(tool_name=tool_name, findings=findings)


def _rules_by_id(driver: dict) -> dict:
    return {
        rule["id"]: rule
        for rule in driver.get("rules") or []
        if isinstance(rule, dict) and rule.get("id")
    }


def _finding(result: dict, rules: dict) -> Finding:
    rule_id = str(result.get("ruleId") or "unknown")
    message = ((result.get("message") or {}).get("text")) or rule_id
    return Finding(
        rule_id=rule_id[:100],  # Finding.rule_id is CharField(100)
        message=message,
        severity=_severity(result, rules.get(rule_id) or {}),
        raw=json.dumps(result, ensure_ascii=False)[:4000],
    )


def _severity(result: dict, rule: dict) -> Severity:
    score = _security_severity(result)
    if score is None:
        score = _security_severity(rule)
    if score is not None:
        return _severity_from_score(score)
    level = str(result.get("level") or "warning").lower()
    return _LEVEL_SEVERITY.get(level, Severity.MEDIUM)


def _security_severity(node: dict) -> float | None:
    raw = (node.get("properties") or {}).get("security-severity")
    try:
        return float(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _severity_from_score(score: float) -> Severity:
    # GitHub code-scanning buckets for the CVSS-like security-severity score.
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO
