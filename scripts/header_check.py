"""Check security headers on an HTTPS URL; findings are review leads."""
import json
import re
import sys
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError


def check_headers(url, headers, final_url=None):
    h = {k.lower(): v.strip() for k, v in headers.items()}
    findings = []

    def add(key, message, severity="MEDIUM"):
        findings.append({"id": f"headers:{key}", "path": url, "line": 1,
                         "key": key, "severity": severity, "message": message})

    # Names alone are not protection: max-age=0 explicitly disables HSTS.
    hsts = h.get("strict-transport-security", "")
    age = re.search(r'(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?:;|$)', hsts, re.I)
    if not age or int(age.group(1)) == 0:
        add("strict-transport-security", "Missing or inactive HSTS max-age.")
    csp = h.get("content-security-policy", "")
    if not csp:
        add("content-security-policy", "Missing Content-Security-Policy header.")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        add("x-content-type-options", "Missing or invalid X-Content-Type-Options: nosniff.")

    directives = [part.strip().split() for part in csp.split(";")]
    ancestors = next((part[1:] for part in directives if part and part[0].lower() == "frame-ancestors"), [])
    # A wildcard ancestor allows any site to frame the page. A mention inside
    # another directive (such as report-uri) is not a frame-ancestors policy.
    frame_policy = bool(ancestors) and "*" not in ancestors
    xfo = h.get("x-frame-options", "").upper() in {"DENY", "SAMEORIGIN"}
    if not xfo and not frame_policy:
        add("clickjacking", "No restrictive X-Frame-Options or CSP frame-ancestors; review framing protection.")
    if h.get("access-control-allow-origin") == "*" and h.get("access-control-allow-credentials", "").lower() == "true":
        add("cors-wildcard", "CORS allows * with credentials.", "HIGH")
    if "x-powered-by" in h:
        add("x-powered-by", f"Server leaks X-Powered-By: {h['x-powered-by']}", "LOW")
    if final_url and urlparse(final_url).scheme != "https":
        add("https-downgrade", "HTTPS URL redirects to a non-HTTPS destination.", "HIGH")
    return findings


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: header_check.py https://url output.json")
    url, out = sys.argv[1:]
    host = urlparse(url)
    if host.scheme != "https" or not host.netloc:
        raise SystemExit("header_url must be an https:// URL")
    try:
        with urlopen(Request(url, headers={"User-Agent": "free-security-scanner"}), timeout=20) as response:  # nosemgrep
            findings = check_headers(url, response.headers, response.geturl())
    except HTTPError as error:
        try:
            findings = check_headers(url, error.headers, error.geturl())
        finally:
            error.close()
    with open(out, "w", encoding="utf-8") as report:
        json.dump({"results": findings}, report)
    print(f"{len(findings)} header findings")


if __name__ == "__main__":
    main()
