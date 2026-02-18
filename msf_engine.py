#!/usr/bin/env python3
"""
Metasploit Framework Integration Engine
Automates Metasploit modules based on discovered services and vulnerabilities.

Uses msfconsole -x (command mode) or resource scripts for automation.
References: github.com/douglashyde/metasploit-framework (bundled as submodule)
"""

import os
import re
import shutil
import subprocess
import tempfile
import time

TOOLS_DIR = os.environ.get("TOOLS_DIR", "/opt/hackingtool-arsenal")
MSF_DIR = os.path.join(os.path.dirname(__file__), "metasploit-framework")


def msf_available():
    """Check if msfconsole is available (system or submodule)."""
    if shutil.which("msfconsole"):
        return True
    if os.path.isfile(os.path.join(MSF_DIR, "msfconsole")):
        return True
    return False


def _msfconsole():
    """Get path to msfconsole."""
    sys_msf = shutil.which("msfconsole")
    if sys_msf:
        return sys_msf
    local = os.path.join(MSF_DIR, "msfconsole")
    if os.path.isfile(local):
        return local
    return "msfconsole"


def _run_msf(commands, timeout=300):
    """Run msfconsole with inline commands and return output."""
    # Join commands with semicolons for -x mode
    cmd_str = "; ".join(commands) + "; exit"
    try:
        proc = subprocess.run(
            [_msfconsole(), "-q", "-x", cmd_str],
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "TERM": "xterm"},
        )
        return proc.stdout + proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return f"Metasploit timed out after {timeout}s", -1
    except FileNotFoundError:
        return "msfconsole not found", -1
    except Exception as e:
        return str(e), -1


def _run_msf_resource(script_content, timeout=300):
    """Run msfconsole with a resource script."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False) as f:
        f.write(script_content + "\nexit\n")
        rc_path = f.name
    try:
        proc = subprocess.run(
            [_msfconsole(), "-q", "-r", rc_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "TERM": "xterm"},
        )
        return proc.stdout + proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return f"Metasploit timed out after {timeout}s", -1
    except Exception as e:
        return str(e), -1
    finally:
        try:
            os.unlink(rc_path)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# Service-based module selection
# ══════════════════════════════════════════════════════════════════════════════

# Maps (port, service_hint) -> list of metasploit modules to run
SERVICE_MODULES = {
    "smb": [
        {
            "name": "EternalBlue MS17-010 Check",
            "module": "auxiliary/scanner/smb/smb_ms17_010",
            "options": {"THREADS": "4"},
            "critical": True,
        },
        {
            "name": "SMB Version Detection",
            "module": "auxiliary/scanner/smb/smb_version",
            "options": {"THREADS": "4"},
        },
        {
            "name": "SMB Share Enumeration",
            "module": "auxiliary/scanner/smb/smb_enumshares",
            "options": {"THREADS": "4"},
        },
        {
            "name": "SMB Login Check",
            "module": "auxiliary/scanner/smb/smb_login",
            "options": {"THREADS": "2", "BLANK_PASSWORDS": "true", "USER_AS_PASS": "true",
                        "USERNAME": "administrator"},
        },
    ],
    "ssh": [
        {
            "name": "SSH Version Detection",
            "module": "auxiliary/scanner/ssh/ssh_version",
            "options": {"THREADS": "4"},
        },
        {
            "name": "SSH User Enumeration",
            "module": "auxiliary/scanner/ssh/ssh_enumusers",
            "options": {"THREADS": "2", "USERNAME": "root"},
        },
    ],
    "ftp": [
        {
            "name": "FTP Version Detection",
            "module": "auxiliary/scanner/ftp/ftp_version",
            "options": {"THREADS": "4"},
        },
        {
            "name": "FTP Anonymous Login",
            "module": "auxiliary/scanner/ftp/anonymous",
            "options": {"THREADS": "4"},
        },
    ],
    "http": [
        {
            "name": "HTTP Version Detection",
            "module": "auxiliary/scanner/http/http_version",
            "options": {"THREADS": "4"},
        },
        {
            "name": "HTTP Directory Scanner",
            "module": "auxiliary/scanner/http/dir_scanner",
            "options": {"THREADS": "4"},
        },
        {
            "name": "HTTP Title Grabber",
            "module": "auxiliary/scanner/http/title",
            "options": {"THREADS": "4"},
        },
    ],
    "ssl": [
        {
            "name": "Heartbleed Check",
            "module": "auxiliary/scanner/ssl/openssl_heartbleed",
            "options": {"THREADS": "4"},
            "critical": True,
        },
        {
            "name": "SSL Version Detection",
            "module": "auxiliary/scanner/ssl/ssl_version",
            "options": {"THREADS": "4"},
        },
    ],
    "mysql": [
        {
            "name": "MySQL Version Detection",
            "module": "auxiliary/scanner/mysql/mysql_version",
            "options": {"THREADS": "4"},
        },
        {
            "name": "MySQL Login Check",
            "module": "auxiliary/scanner/mysql/mysql_login",
            "options": {"THREADS": "2", "BLANK_PASSWORDS": "true", "USERNAME": "root"},
        },
    ],
    "postgresql": [
        {
            "name": "PostgreSQL Login Check",
            "module": "auxiliary/scanner/postgres/postgres_login",
            "options": {"THREADS": "2", "USERNAME": "postgres"},
        },
    ],
    "rdp": [
        {
            "name": "RDP BlueKeep Check (CVE-2019-0708)",
            "module": "auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
            "options": {},
            "critical": True,
        },
    ],
    "vnc": [
        {
            "name": "VNC No-Auth Check",
            "module": "auxiliary/scanner/vnc/vnc_none_auth",
            "options": {"THREADS": "4"},
        },
    ],
    "telnet": [
        {
            "name": "Telnet Version Detection",
            "module": "auxiliary/scanner/telnet/telnet_version",
            "options": {"THREADS": "4"},
        },
    ],
    "redis": [
        {
            "name": "Redis No-Auth Check",
            "module": "auxiliary/scanner/redis/redis_server",
            "options": {},
        },
    ],
    "mongodb": [
        {
            "name": "MongoDB No-Auth Check",
            "module": "auxiliary/scanner/mongodb/mongodb_login",
            "options": {},
        },
    ],
    "mssql": [
        {
            "name": "MSSQL Login Check",
            "module": "auxiliary/scanner/mssql/mssql_login",
            "options": {"THREADS": "2", "USERNAME": "sa"},
        },
    ],
}

# Port to service mapping
PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    80: "http", 110: "pop3", 143: "imap", 443: "ssl",
    445: "smb", 993: "ssl", 1433: "mssql", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http", 8443: "ssl", 27017: "mongodb",
}


def get_modules_for_findings(findings):
    """Given scan findings, determine which Metasploit modules to run."""
    modules_to_run = []
    seen = set()

    for f in findings:
        title_lower = f.get("title", "").lower()
        detail_lower = f.get("detail", "").lower()

        # Extract port numbers from findings
        port_match = re.search(r"port\s*(\d+)", title_lower)
        if port_match:
            port = int(port_match.group(1))
            service = PORT_SERVICE.get(port)
            if service and service in SERVICE_MODULES:
                for mod in SERVICE_MODULES[service]:
                    key = mod["module"]
                    if key not in seen:
                        seen.add(key)
                        modules_to_run.append({**mod, "port": port})

        # Match by service keywords
        for service, mods in SERVICE_MODULES.items():
            if service in title_lower or service in detail_lower:
                for mod in mods:
                    key = mod["module"]
                    if key not in seen:
                        seen.add(key)
                        modules_to_run.append(mod)

        # CVE-specific modules
        for cve in re.findall(r"(CVE-\d{4}-\d+)", f.get("title", "") + f.get("detail", "")):
            cve_mod = _cve_to_module(cve)
            if cve_mod and cve_mod["module"] not in seen:
                seen.add(cve_mod["module"])
                modules_to_run.append(cve_mod)

    return modules_to_run


def _cve_to_module(cve):
    """Map known CVEs to Metasploit modules."""
    cve_map = {
        "CVE-2017-0144": {"name": "EternalBlue Exploit", "module": "exploit/windows/smb/ms17_010_eternalblue",
                          "options": {}, "critical": True, "check_only": True},
        "CVE-2019-0708": {"name": "BlueKeep Exploit", "module": "auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
                          "options": {}, "critical": True},
        "CVE-2014-0160": {"name": "Heartbleed", "module": "auxiliary/scanner/ssl/openssl_heartbleed",
                          "options": {}, "critical": True},
        "CVE-2014-6271": {"name": "Shellshock", "module": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
                          "options": {}, "critical": True, "check_only": True},
        "CVE-2021-44228": {"name": "Log4Shell", "module": "exploit/multi/http/log4shell_header_injection",
                           "options": {}, "critical": True, "check_only": True},
    }
    return cve_map.get(cve)


# ══════════════════════════════════════════════════════════════════════════════
# Module Execution
# ══════════════════════════════════════════════════════════════════════════════

def run_module(host, module_info):
    """Run a single Metasploit module and return results."""
    mod_path = module_info["module"]
    options = module_info.get("options", {})
    check_only = module_info.get("check_only", False)
    port = module_info.get("port")

    # Build resource script for reliable execution
    script_lines = [
        f"use {mod_path}",
        f"set RHOSTS {host}",
    ]
    if port:
        script_lines.append(f"set RPORT {port}")
    for k, v in options.items():
        script_lines.append(f"set {k} {v}")

    if check_only:
        script_lines.append("check")
    else:
        script_lines.append("run")

    script = "\n".join(script_lines)
    output, rc = _run_msf_resource(script, timeout=180)

    # Parse results
    result = {
        "module": mod_path,
        "name": module_info["name"],
        "output": output,
        "exit_code": rc,
        "findings": [],
        "vulnerable": False,
    }

    out_lower = output.lower()

    # Check for vulnerability confirmation
    if any(w in out_lower for w in ["vulnerable", "is vulnerable", "host is vulnerable"]):
        result["vulnerable"] = True
        result["findings"].append({
            "severity": "critical",
            "title": f"MSF: {module_info['name']} - VULNERABLE",
            "detail": f"Metasploit confirmed vulnerability via {mod_path}",
            "evidence": _extract_evidence(output),
            "module": "Metasploit",
        })

    # Check for successful login / access
    if any(w in out_lower for w in ["login successful", "success", "authenticated"]):
        result["vulnerable"] = True
        creds = re.findall(r"(\S+):(\S+)\s+.*(?:success|login)", output, re.I)
        for user, passwd in creds:
            result["findings"].append({
                "severity": "critical",
                "title": f"MSF: Valid credentials {user}:{passwd}",
                "detail": f"Metasploit {mod_path} found valid credentials",
                "evidence": f"{user}:{passwd}",
                "module": "Metasploit",
            })

    # Extract version info
    for m in re.finditer(r"(?:version|running)\s*[:\s]+(.+?)(?:\n|$)", output, re.I):
        result["findings"].append({
            "severity": "info",
            "title": f"MSF: {m.group(1).strip()[:80]}",
            "detail": f"Detected by {mod_path}",
            "module": "Metasploit",
        })

    # Extract shares
    for m in re.finditer(r"(\S+)\s+-\s+(Disk|Printer|IPC)", output):
        result["findings"].append({
            "severity": "medium",
            "title": f"MSF: SMB Share - {m.group(1)}",
            "detail": f"Type: {m.group(2)}",
            "module": "Metasploit",
        })

    return result


def run_scan(host, findings, max_modules=10, callback=None):
    """Run all applicable Metasploit modules for a host based on findings.

    Args:
        host: Target host/IP
        findings: List of scan findings to determine which modules to run
        max_modules: Maximum modules to execute
        callback: Optional callback(module_name, status, result) for progress

    Returns:
        List of module results
    """
    if not msf_available():
        return []

    modules = get_modules_for_findings(findings)[:max_modules]
    results = []

    for mod in modules:
        if callback:
            callback(mod["name"], "running", None)

        result = run_module(host, mod)
        results.append(result)

        if callback:
            status = "vulnerable" if result["vulnerable"] else "completed"
            callback(mod["name"], status, result)

    return results


def generate_attack_commands(host, findings):
    """Generate Metasploit commands for manual execution (for attack cards)."""
    commands = []
    modules = get_modules_for_findings(findings)

    for mod in modules:
        opts = " ".join(f"{k}={v}" for k, v in mod.get("options", {}).items())
        port_str = f" RPORT={mod['port']}" if mod.get("port") else ""
        cmd = f"msfconsole -q -x 'use {mod['module']}; set RHOSTS {host};{port_str} {opts}; run; exit'"

        commands.append({
            "name": f"MSF: {mod['name']}",
            "description": f"Metasploit {mod['module']}",
            "command": cmd,
            "risk": "critical" if mod.get("critical") else "high",
            "category": "exploitation",
            "context": f"Runs Metasploit module {mod['module']} against the target. "
                       f"This is an automated vulnerability check/exploit from the Metasploit Framework.",
            "look_for": "Look for '[+]' lines indicating success, '[*]' for info, and '[-]' for failures. "
                        "'VULNERABLE' confirms the target is exploitable.",
        })

    return commands


def _extract_evidence(output, max_len=500):
    """Extract the most relevant lines from Metasploit output."""
    important = []
    for line in output.split("\n"):
        stripped = line.strip()
        if stripped.startswith("[+]") or stripped.startswith("[!]"):
            important.append(stripped)
        elif "vulnerable" in stripped.lower() or "success" in stripped.lower():
            important.append(stripped)
    return "\n".join(important[:10])[:max_len] if important else output[:max_len]
