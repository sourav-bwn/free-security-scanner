"""Cheap static checks for checklist items Semgrep misses. Writes normalized findings."""
import json, os, re, subprocess, sys

OUT = sys.argv[1]
SKIP = {"node_modules", ".git", ".scanner-tools"}
findings = []


def add(i, path, msg, sev="MEDIUM"):
    findings.append({"id": i, "path": path, "line": 1, "key": i, "severity": sev, "message": msg})


tracked = subprocess.run(["git", "ls-files"], capture_output=True, text=True).stdout.split("\n")
for f in tracked:
    base = os.path.basename(f)
    if re.fullmatch(r"\.env(\.[\w.-]+)?", base) and not base.endswith((".example", ".sample", ".template")):
        add("hygiene:env-committed", f, "An .env file is committed. Remove it from git, add it to .gitignore, and rotate every key inside.", "HIGH")
    if base.endswith((".pem", ".p12", ".pfx")) or base in ("id_rsa", "id_ed25519"):
        add("hygiene:private-key-file", f, "A private key or certificate file is committed. Remove it and rotate it.", "HIGH")

if os.path.exists("package.json"):
    gi = open(".gitignore").read() if os.path.exists(".gitignore") else ""
    if ".env" not in gi:
        add("hygiene:gitignore-env", ".gitignore", ".env is not listed in .gitignore.")
    pkg = json.load(open("package.json"))
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    if "express" in deps:
        for lib, i, m in (("helmet", "hygiene:no-helmet", "Express app does not use helmet (CSP, HSTS, X-Frame-Options, X-Content-Type-Options headers)."),
                          ("express-rate-limit", "hygiene:no-rate-limit", "No rate limiting package found (express-rate-limit or similar). Login and OTP endpoints need rate limits."),
                          ("cors", "hygiene:no-cors-config", "No cors package found; make sure CORS is locked to real origins.")):
            if lib not in deps and not (lib == "express-rate-limit" and any("rate-limit" in d or "limiter" in d for d in deps)):
                add(i, "package.json", m)

if os.path.exists("Dockerfile"):
    if not re.search(r"^USER\s+(?!root)", open("Dockerfile").read(), re.M):
        add("hygiene:docker-root", "Dockerfile", "Container runs as root; add a non-root USER.")

json.dump({"results": findings}, open(OUT, "w"))
print(f"{len(findings)} hygiene findings")
