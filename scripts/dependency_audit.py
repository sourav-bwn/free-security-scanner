"""Audit npm and Python dependencies; write normalized findings (free tools only)."""
import json, os, subprocess, sys

OUT = sys.argv[1]
SKIP = {"node_modules", ".git", ".scanner-tools", "venv", ".venv"}
findings = []


def run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def walk(names):
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for n in names:
            if n in files:
                yield root, n


for root, _ in walk(["package-lock.json"]):
    r = run(["npm", "audit", "--json", "--omit=dev"], root)
    try:
        data = json.loads(r.stdout or "{}")
    except ValueError:
        continue
    for name, v in (data.get("vulnerabilities") or {}).items():
        sev = (v.get("severity") or "unknown").upper()
        if sev not in ("HIGH", "CRITICAL"):
            continue
        via = [x.get("title") for x in v.get("via", []) if isinstance(x, dict)]
        findings.append({
            "id": f"npm-audit:{name}", "path": os.path.join(root, "package-lock.json").lstrip("./"),
            "key": f"{name}:{sev}", "line": 1, "severity": sev,
            "message": f"Vulnerable npm package {name} ({sev}). {'; '.join(t for t in via if t)[:400]} Fix available: {v.get('fixAvailable') not in (False, None)}."})

reqs = [os.path.join(r_, n) for r_, n in walk(["requirements.txt"])]
if reqs:
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "pip-audit"], capture_output=True)
for req in reqs:
    r = run([sys.executable, "-m", "pip_audit", "-r", req, "-f", "json", "--progress-spinner", "off"], ".")
    try:
        data = json.loads(r.stdout or "{}")
    except ValueError:
        continue
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            findings.append({
                "id": f"pip-audit:{dep['name']}", "path": req.lstrip("./"), "line": 1,
                "key": f"{dep['name']}:{vuln['id']}", "severity": "HIGH",
                "message": f"{dep['name']} {dep.get('version')} has {vuln['id']}. Fixed in: {', '.join(vuln.get('fix_versions') or ['no fix yet'])}."})

json.dump({"results": findings}, open(OUT, "w"))
print(f"{len(findings)} dependency findings")
