"""Denis's custom SARIF-emitting scanner: flags missing HTTP security response
headers on a target URL.

Run as a subprocess by HttpHeadersScanner (``python http_headers.py <url>``); it
writes a SARIF 2.1.0 document to stdout, which the shared ``scanners.sarif``
parser turns into Findings. Kept standalone (stdlib + requests only, no Django
imports) and with the checking logic factored into pure functions so it can be
unit-tested without the network.
"""

from __future__ import annotations

import json
import sys

TOOL_NAME = "nodeguard-http-headers"

# response header (lowercase) -> (SARIF level, why its absence matters)
SECURITY_HEADERS: dict[str, tuple[str, str]] = {
    "content-security-policy": (
        "error",
        "Missing Content-Security-Policy — no defense-in-depth against XSS/injection.",
    ),
    "strict-transport-security": (
        "error",
        "Missing Strict-Transport-Security (HSTS) — connections can be downgraded to HTTP.",
    ),
    "x-frame-options": (
        "warning",
        "Missing X-Frame-Options — the page can be framed (clickjacking).",
    ),
    "x-content-type-options": (
        "warning",
        "Missing X-Content-Type-Options — browsers may MIME-sniff responses.",
    ),
    "referrer-policy": (
        "note",
        "Missing Referrer-Policy — full URLs may leak to third parties via Referer.",
    ),
    "permissions-policy": (
        "note",
        "Missing Permissions-Policy — powerful browser features aren't restricted.",
    ),
}


def evaluate(headers) -> list[dict]:
    """Pure: given response headers (any case-insensitive mapping of header
    names to values), return one SARIF result per missing security header."""
    present = {name.lower() for name in headers}
    results = []
    for header, (level, text) in SECURITY_HEADERS.items():
        if header not in present:
            results.append(
                {
                    "ruleId": f"http-headers/missing-{header}",
                    "level": level,
                    "message": {"text": text},
                }
            )
    return results


def to_sarif(results: list[dict]) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": TOOL_NAME}}, "results": results}],
    }


def scan(url: str) -> dict:  # pragma: no cover - performs real network I/O
    import requests

    response = requests.get(url, timeout=15)
    return to_sarif(evaluate(response.headers))


def main() -> None:  # pragma: no cover - subprocess entry point
    url = sys.argv[1] if len(sys.argv) > 1 else ""
    json.dump(scan(url), sys.stdout)


if __name__ == "__main__":  # pragma: no cover
    main()
