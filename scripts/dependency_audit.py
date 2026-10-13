"""Audit npm and Python dependencies; fail closed on incomplete audit output."""
import json
import os
import subprocess
import sys

SKIP = {"node_modules", ".git", ".scanner-tools", "venv", ".venv"}


def run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def walk(names):
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for name in names:
            if name in files:
                yield root, name


def audit_json(result, field, source):
    try:
        data = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise RuntimeError(f"{source}: audit did not return valid JSON") from exc
    expected = dict if field == "vulnerabilities" else list
    if (result.returncode not in (0, 1) or not isinstance(data, dict)
            or data.get("error") or data.get("errors")
            or not isinstance(data.get(field), expected)):
        raise RuntimeError(f"{source}: audit failed or returned incomplete results")
    return data[field]


def audit():
    findings = []
    for root, _ in walk(["package-lock.json"]):
        path = os.path.normpath(os.path.join(root, "package-lock.json"))
        result = run(["npm", "audit", "--json", "--omit=dev"], root)
        vulnerabilities = audit_json(result, "vulnerabilities", path)
        for name, value in vulnerabilities.items():
            sev = (value.get("severity") or "unknown").upper()
            if sev not in ("HIGH", "CRITICAL"):
                continue
            via = [x.get("title") for x in value.get("via", []) if isinstance(x, dict)]
            findings.append({
                "id": f"npm-audit:{name}", "path": path, "key": f"{name}:{sev}",
                "line": 1, "severity": sev,
                "message": f"Vulnerable npm package {name} ({sev}). {'; '.join(t for t in via if t)[:400]} Fix available: {value.get('fixAvailable') not in (False, None)}."})

    reqs = [os.path.normpath(os.path.join(root, name)) for root, name in walk(["requirements.txt"])]
    if reqs:
        install = run([sys.executable, "-m", "pip", "install", "-q", "pip-audit"], ".")
        if install.returncode:
            raise RuntimeError("pip-audit installation failed; dependency scan incomplete")
    for req in reqs:
        result = run([sys.executable, "-m", "pip_audit", "-r", req, "-f", "json", "--progress-spinner", "off"], ".")
        for dep in audit_json(result, "dependencies", req):
            if dep.get("skip_reason"):
                raise RuntimeError(f"{req}: a dependency could not be audited")
            for vuln in dep.get("vulns", []):
                findings.append({
                    "id": f"pip-audit:{dep['name']}", "path": req, "line": 1,
                    "key": f"{dep['name']}:{vuln['id']}", "severity": "HIGH",
                    "message": f"{dep['name']} {dep.get('version')} has {vuln['id']}. Fixed in: {', '.join(vuln.get('fix_versions') or ['no fix yet'])}."})
    return findings


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: dependency_audit.py output.json")
    # Remove a prior report so failure cannot leave stale successful output.
    out = sys.argv[1]
    if os.path.exists(out):
        os.remove(out)
    findings = audit()
    with open(out, "w", encoding="utf-8") as report:
        json.dump({"results": findings}, report)
    print(f"{len(findings)} dependency findings")


if __name__ == "__main__":
    main()
