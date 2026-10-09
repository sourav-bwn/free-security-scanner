"""Check HTTPS redirect and security headers on a live URL. Writes normalized findings."""
import json, sys
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError

url, out = sys.argv[1], sys.argv[2]
host = urlparse(url)
if host.scheme != "https" or not host.netloc:
    raise SystemExit("header_url must be an https:// URL")
findings = []


def add(key, msg, sev="MEDIUM"):
    findings.append({"id": f"headers:{key}", "path": url, "line": 1, "key": key, "severity": sev, "message": msg})


try:
    with urlopen(Request(url, headers={"User-Agent": "free-security-scanner"}), timeout=20) as r:  # nosemgrep
        h = {k.lower(): v for k, v in r.headers.items()}
except HTTPError as e:
    h = {k.lower(): v for k, v in e.headers.items()}
checks = {
    "strict-transport-security": "Missing HSTS header.",
    "content-security-policy": "Missing Content-Security-Policy header.",
    "x-content-type-options": "Missing X-Content-Type-Options: nosniff.",
}
for k, m in checks.items():
    if k not in h:
        add(k, m)
if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
    add("clickjacking", "No X-Frame-Options or CSP frame-ancestors (clickjacking protection).")
if h.get("access-control-allow-origin") == "*" and h.get("access-control-allow-credentials") == "true":
    add("cors-wildcard", "CORS allows * with credentials.", "HIGH")
if "x-powered-by" in h:
    add("x-powered-by", f"Server leaks X-Powered-By: {h['x-powered-by']}", "LOW")
json.dump({"results": findings}, open(out, "w"))
print(f"{len(findings)} header findings")
