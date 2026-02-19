#!/usr/bin/env python3
"""
AI Orchestration Engine — Kimi-K2 (MoonshotAI)
Analyzes scan results, selects tools intelligently, and generates pentest reports.

Supports:
  - MoonshotAI direct API (api.moonshot.ai) — default
  - OpenRouter (free tier: moonshotai/kimi-k2:free)
  - Any OpenAI-compatible endpoint (Together.ai, self-hosted vLLM, etc.)

Set KIMI_API_KEY (or OPENROUTER_API_KEY) env var to enable AI features.
Without an API key, the engine falls back to rule-based analysis.
"""

import json
import os
import re
import time
from datetime import datetime, timezone

try:
    import requests as _req
except ImportError:
    _req = None

# ── Configuration ────────────────────────────────────────────────────────────
# Supports both KIMI_API_KEY (Moonshot direct) and OPENROUTER_API_KEY (OpenRouter)
_KIMI_KEY = os.environ.get("KIMI_API_KEY", "")
_OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY", "")

if _KIMI_KEY:
    OPENROUTER_API_KEY = _KIMI_KEY
    AI_BASE_URL = os.environ.get("AI_BASE_URL", "https://api.moonshot.ai/v1")
    AI_MODEL = os.environ.get("AI_MODEL", "kimi-k2-0711-preview")
elif _OPENROUTER_KEY:
    OPENROUTER_API_KEY = _OPENROUTER_KEY
    AI_BASE_URL = os.environ.get("AI_BASE_URL", "https://openrouter.ai/api/v1")
    AI_MODEL = os.environ.get("AI_MODEL", "moonshotai/kimi-k2:free")
else:
    OPENROUTER_API_KEY = ""
    AI_BASE_URL = os.environ.get("AI_BASE_URL", "https://api.moonshot.ai/v1")
    AI_MODEL = os.environ.get("AI_MODEL", "kimi-k2-0711-preview")


def ai_available():
    """Check if AI engine is configured."""
    return bool(OPENROUTER_API_KEY and _req)


def _ai_call(messages, temperature=0.6, max_tokens=4096):
    """Call Kimi-K2 via OpenRouter (OpenAI-compatible API)."""
    if not ai_available():
        return None
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/douglashyde/hackingtool",
        "X-Title": "HackingTool Red Team Platform",
    }
    payload = {
        "model": AI_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    try:
        resp = _req.post(
            f"{AI_BASE_URL}/chat/completions",
            headers=headers,
            json=payload,
            timeout=180,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        return None
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# Attack Selection — AI decides which attacks to auto-execute
# ══════════════════════════════════════════════════════════════════════════════

def select_attacks(target, target_type, findings, attacks):
    """Use AI to select which attacks to auto-execute, or fall back to rules."""
    if ai_available() and attacks:
        ai_result = _ai_select_attacks(target, findings, attacks)
        if ai_result is not None:
            return ai_result
    return _rule_select_attacks(attacks)


def _ai_select_attacks(target, findings, attacks):
    """AI-powered attack selection via Kimi-K2."""
    findings_text = "\n".join(
        f"[{f['severity'].upper()}] {f['title']}: {f['detail']}"
        for f in findings[:80]
    )
    attacks_json = json.dumps(
        [
            {
                "index": i,
                "name": a["name"],
                "risk": a["risk"],
                "category": a["category"],
                "command": a["command"],
            }
            for i, a in enumerate(attacks)
        ],
        indent=2,
    )
    messages = [
        {
            "role": "system",
            "content": (
                "You are a penetration testing AI. Given scan findings and available attacks, "
                "select attacks to auto-execute. Prioritize:\n"
                "1. Vulnerability verification (confirm exploitability)\n"
                "2. Information gathering from discovered services\n"
                "3. Credential attacks against discovered login pages\n"
                "4. Service-specific exploits for confirmed vulnerabilities\n"
                "Return ONLY a JSON array of attack indices in priority order. Example: [0,3,7,12,15]\n"
                "Include ALL viable attacks — no limit. Run everything that could yield results. No other text."
            ),
        },
        {
            "role": "user",
            "content": f"Target: {target}\n\nFINDINGS:\n{findings_text}\n\n"
            f"ATTACKS:\n{attacks_json}\n\nSelect attacks (JSON array of indices):",
        },
    ]
    result = _ai_call(messages, temperature=0.3, max_tokens=500)
    if result:
        try:
            match = re.search(r"\[[\d,\s]+\]", result)
            if match:
                indices = json.loads(match.group())
                return [i for i in indices if 0 <= i < len(attacks)]
        except Exception:
            pass
    return None


def _rule_select_attacks(attacks):
    """Rule-based fallback: select ALL executable attacks, prioritized by risk."""
    selected = []
    for i, a in enumerate(attacks):
        if a["risk"] in ("critical", "high"):
            selected.append(i)
    for i, a in enumerate(attacks):
        if i not in selected and a["risk"] == "medium":
            selected.append(i)
    for i, a in enumerate(attacks):
        if i not in selected:
            selected.append(i)
    return selected


# ══════════════════════════════════════════════════════════════════════════════
# Result Analysis — AI analyzes attack output
# ══════════════════════════════════════════════════════════════════════════════

def analyze_attack_result(attack_name, command, output, exit_code):
    """Analyze a single attack result and extract key findings."""
    if not ai_available():
        return _rule_analyze_result(attack_name, command, output, exit_code)
    messages = [
        {
            "role": "system",
            "content": (
                "You are a pentesting expert analyzing tool output. Provide a brief JSON response:\n"
                '{"success": true/false, "summary": "1-2 sentence summary", '
                '"credentials": ["user:pass",...] or [], "vulns_confirmed": ["vuln name",...] or [], '
                '"access_gained": "description or null", "severity": "critical/high/medium/low/info"}\n'
                "Return ONLY the JSON object."
            ),
        },
        {
            "role": "user",
            "content": f"Attack: {attack_name}\nCommand: {command}\n"
            f"Exit code: {exit_code}\nOutput:\n{output[:3000]}",
        },
    ]
    result = _ai_call(messages, temperature=0.2, max_tokens=500)
    if result:
        try:
            match = re.search(r"\{.*\}", result, re.DOTALL)
            if match:
                return json.loads(match.group())
        except Exception:
            pass
    return _rule_analyze_result(attack_name, command, output, exit_code)


def _rule_analyze_result(attack_name, command, output, exit_code):
    """Rule-based analysis of attack output."""
    out_lower = output.lower()
    result = {
        "success": False,
        "summary": "",
        "credentials": [],
        "vulns_confirmed": [],
        "access_gained": None,
        "severity": "info",
    }

    # Check for successful exploitation indicators
    success_indicators = [
        "vulnerable", "injection", "injectable", "valid combination",
        "login:", "password:", "session opened", "command shell",
        "meterpreter", "uid=", "root@", "nt authority\\system",
    ]
    fail_indicators = [
        "not vulnerable", "no injection", "0 valid", "failed",
        "connection refused", "timeout", "no results",
    ]

    has_success = any(ind in out_lower for ind in success_indicators)
    has_fail = any(ind in out_lower for ind in fail_indicators)

    if has_success and not has_fail:
        result["success"] = True
        result["severity"] = "critical" if any(
            w in out_lower for w in ["shell", "meterpreter", "root", "system", "uid=0"]
        ) else "high"

    # Extract credentials
    cred_patterns = [
        r"login:\s*(\S+)\s+password:\s*(\S+)",
        r"Username:\s*(\S+),?\s*Password:\s*(\S+)",
        r"\[[\d]+\]\[\S+\]\s+host:\s*\S+\s+login:\s*(\S+)\s+password:\s*(\S+)",
    ]
    for pattern in cred_patterns:
        for m in re.finditer(pattern, output, re.I):
            cred = f"{m.group(1)}:{m.group(2)}"
            if cred not in result["credentials"]:
                result["credentials"].append(cred)

    if result["credentials"]:
        result["success"] = True
        result["severity"] = "critical"
        result["summary"] = f"Found {len(result['credentials'])} credential(s)"
        result["access_gained"] = f"Valid credentials: {', '.join(result['credentials'][:5])}"
    elif result["success"]:
        result["summary"] = "Attack indicates target is vulnerable"
    elif exit_code == 0:
        result["summary"] = "Command completed but no clear exploitation"
        result["severity"] = "info"
    else:
        result["summary"] = f"Command exited with code {exit_code}"
        result["severity"] = "info"

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Full Assessment — AI generates comprehensive security assessment
# ══════════════════════════════════════════════════════════════════════════════

def generate_assessment(target, target_type, findings, attacks, attack_results):
    """Generate full security assessment using AI or rule-based fallback."""
    if ai_available():
        ai_result = _ai_assessment(target, target_type, findings, attacks, attack_results)
        if ai_result:
            return ai_result
    return _rule_assessment(target, target_type, findings, attacks, attack_results)


def _ai_assessment(target, target_type, findings, attacks, attack_results):
    """AI-powered full security assessment."""
    findings_text = "\n".join(
        f"[{f['severity'].upper()}] {f['title']}: {f['detail']} (Module: {f['module']})"
        + (f"\n  Evidence: {f['evidence']}" if f.get('evidence') else "")
        for f in findings[:200]
    )
    results_text = "\n".join(
        f"--- {r['attack_name']} (exit:{r['exit_code']}) ---\n"
        f"Command: {r['command']}\n"
        f"Success: {r.get('analysis', {}).get('success', '?')}\n"
        f"Summary: {r.get('analysis', {}).get('summary', 'N/A')}\n"
        f"Credentials: {r.get('analysis', {}).get('credentials', [])}\n"
        f"Vulns confirmed: {r.get('analysis', {}).get('vulns_confirmed', [])}\n"
        f"Access gained: {r.get('analysis', {}).get('access_gained', 'None')}\n"
        f"Output excerpt: {r['output'][:2000]}\n"
        for r in attack_results[:30]
    )
    messages = [
        {
            "role": "system",
            "content": (
                "You are a senior penetration tester writing a comprehensive professional security assessment report. "
                "Analyze ALL findings and ALL attack results thoroughly. Be SPECIFIC — reference actual URLs, paths, "
                "ports, usernames, response codes, and tool output. Structure your response EXACTLY as:\n\n"
                "## Executive Summary\n[3-5 sentences with specific numbers and key findings]\n\n"
                "## Risk Rating: [CRITICAL/HIGH/MEDIUM/LOW]\n[Detailed justification with evidence]\n\n"
                "## Critical Findings\n[Numbered list of ALL severe issues with exact evidence, paths, URLs]\n\n"
                "## Discovered Admin & Login Pages\n[List every admin/login page found with exact URLs and what was discovered]\n\n"
                "## Exposed Usernames & Accounts\n[List EVERY username found, how it was found, and what service it applies to]\n\n"
                "## Successful Attacks\n[Detail EVERY attack that succeeded with full output analysis]\n\n"
                "## Attack Surface Analysis\n[Every open port, service, version, and potential attack vector]\n\n"
                "## Credentials Discovered\n[List ALL found credentials and exactly where they work]\n\n"
                "## Web Application Vulnerabilities\n[XSS, SQLi, CORS, missing headers, etc. with evidence]\n\n"
                "## Infrastructure Vulnerabilities\n[Outdated software, misconfigurations, exposed services]\n\n"
                "## Remediation Priorities\n[Numbered list, most urgent first, with specific actions]\n\n"
                "## Detailed Technical Findings\n[Full technical details for EVERY finding, organized by severity]\n\n"
                "## Next Steps for Further Testing\n[Specific next actions with exact commands to run]\n\n"
                "Be extremely specific. Reference actual data from the results. Show exact paths, ports, "
                "usernames, and evidence. Use markdown formatting. Do NOT be vague."
            ),
        },
        {
            "role": "user",
            "content": f"Target: {target} (Type: {target_type})\n"
            f"Scan Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\n"
            f"=== FINDINGS ({len(findings)} total) ===\n{findings_text}\n\n"
            f"=== ATTACK RESULTS ({len(attack_results)} executed) ===\n{results_text}\n\n"
            f"Generate the full security assessment report.",
        },
    ]
    return _ai_call(messages, temperature=0.4, max_tokens=8000)


def _rule_assessment(target, target_type, findings, attacks, attack_results):
    """Rule-based fallback assessment when AI is unavailable."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Count severities
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1

    # Determine risk rating
    if sev_counts["critical"] > 0:
        risk = "CRITICAL"
    elif sev_counts["high"] > 3:
        risk = "HIGH"
    elif sev_counts["high"] > 0:
        risk = "HIGH"
    elif sev_counts["medium"] > 3:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    # Successful attacks
    successful = [r for r in attack_results if r.get("analysis", {}).get("success")]
    creds = []
    for r in attack_results:
        creds.extend(r.get("analysis", {}).get("credentials", []))

    # Build report
    lines = []
    lines.append(f"## Executive Summary\n")
    lines.append(
        f"Security assessment of **{target}** performed on {now}. "
        f"Discovered {len(findings)} findings across {sev_counts['critical']} critical, "
        f"{sev_counts['high']} high, {sev_counts['medium']} medium severity issues. "
        f"{len(successful)} of {len(attack_results)} automated attacks succeeded."
    )

    lines.append(f"\n\n## Risk Rating: {risk}\n")
    if risk == "CRITICAL":
        lines.append("Critical vulnerabilities were confirmed and exploited successfully.")
    elif risk == "HIGH":
        lines.append("Multiple high-severity vulnerabilities present significant risk.")
    else:
        lines.append("Moderate security posture with areas for improvement.")

    lines.append("\n\n## Critical Findings\n")
    crits = [f for f in findings if f["severity"] in ("critical", "high")]
    if crits:
        for i, f in enumerate(crits[:15], 1):
            lines.append(f"{i}. **[{f['severity'].upper()}]** {f['title']} - {f['detail']} _(Module: {f['module']})_")
    else:
        lines.append("No critical or high-severity findings.")

    lines.append("\n\n## Successful Attacks\n")
    if successful:
        for r in successful:
            analysis = r.get("analysis", {})
            lines.append(f"- **{r['attack_name']}**: {analysis.get('summary', 'Succeeded')}")
            if analysis.get("access_gained"):
                lines.append(f"  - Access gained: {analysis['access_gained']}")
            if analysis.get("credentials"):
                lines.append(f"  - Credentials: {', '.join(analysis['credentials'][:5])}")
    else:
        lines.append("No attacks resulted in confirmed exploitation.")

    if creds:
        lines.append("\n\n## Credentials Discovered\n")
        for c in set(creds):
            lines.append(f"- `{c}`")

    lines.append("\n\n## Attack Surface Analysis\n")
    ports = [f for f in findings if "Port" in f["title"] or "open" in f.get("detail", "").lower()]
    services = [f for f in findings if f["module"] in ("NMAP", "Masscan", "PortScan")]
    if services:
        lines.append(f"- {len(services)} network services discovered")
    logins = [f for f in findings if "Login" in f["title"] or "Admin" in f["title"]]
    if logins:
        lines.append(f"- {len(logins)} login/admin pages found")
    users = [f for f in findings if "User" in f["title"] or "username" in f["title"].lower()]
    if users:
        lines.append(f"- {len(users)} usernames enumerated")

    lines.append("\n\n## Remediation Priorities\n")
    remediation = []
    if sev_counts["critical"] > 0:
        remediation.append("Patch all critical vulnerabilities immediately")
    if creds:
        remediation.append("Reset all compromised credentials and enforce strong password policy")
    if any("SSL" in f["title"] or "TLS" in f["title"] for f in findings if f["severity"] in ("high", "critical")):
        remediation.append("Update SSL/TLS configuration - disable weak protocols and ciphers")
    if any("exposed" in f["title"].lower() for f in findings if f["severity"] in ("high", "critical")):
        remediation.append("Restrict access to exposed services using firewall rules")
    if any("Missing" in f["title"] for f in findings):
        remediation.append("Implement missing security headers (HSTS, CSP, X-Frame-Options)")
    if any("outdated" in f["title"].lower() or "old" in f["title"].lower() for f in findings):
        remediation.append("Update all outdated software to latest versions")
    remediation.append("Conduct a thorough code review for injection vulnerabilities")
    remediation.append("Implement network segmentation and monitoring")
    for i, r in enumerate(remediation[:8], 1):
        lines.append(f"{i}. {r}")

    lines.append("\n\n## Detailed Technical Findings\n")
    for sev in ("critical", "high", "medium", "low"):
        sev_findings = [f for f in findings if f["severity"] == sev]
        if sev_findings:
            lines.append(f"\n### {sev.upper()} ({len(sev_findings)})\n")
            for f in sev_findings[:20]:
                lines.append(f"- **{f['title']}**: {f['detail']} _{f['module']}_")

    lines.append("\n\n## All Attack Results\n")
    for r in attack_results:
        analysis = r.get("analysis", {})
        status = "SUCCESS" if analysis.get("success") else "NO EXPLOIT"
        lines.append(f"\n### {r['attack_name']} [{status}]\n")
        lines.append(f"```\n$ {r['command']}\n{r['output'][:2000]}\n```")
        if analysis.get("summary"):
            lines.append(f"\n**Analysis:** {analysis['summary']}")

    lines.append("\n\n## Next Steps\n")
    lines.append("1. Validate and triage all critical findings")
    lines.append("2. Attempt lateral movement from any compromised accounts")
    lines.append("3. Test for privilege escalation on accessed systems")
    lines.append("4. Perform deeper application-layer testing")
    lines.append("5. Review source code for vulnerabilities not detectable by scanning")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# HTML Report Generation
# ══════════════════════════════════════════════════════════════════════════════

def generate_report_html(target, target_type, scan_data, assessment_md):
    """Generate a standalone downloadable HTML pentest report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    findings = scan_data.get("findings", [])
    attack_results = scan_data.get("attack_results", [])
    summary = scan_data.get("summary", {})

    # Convert markdown assessment to HTML (basic conversion)
    assessment_html = _md_to_html(assessment_md) if assessment_md else "<p>No assessment available.</p>"

    successful = [r for r in attack_results if r.get("analysis", {}).get("success")]
    creds = []
    for r in attack_results:
        creds.extend(r.get("analysis", {}).get("credentials", []))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Penetration Test Report — {_esc(target)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0a0f;color:#e0e0e0;padding:2rem;max-width:1100px;margin:0 auto;line-height:1.6}}
h1{{color:#7B61FF;font-size:2rem;margin-bottom:.5rem}}
h2{{color:#00e5ff;font-size:1.4rem;margin:2rem 0 .8rem;padding-bottom:.4rem;border-bottom:1px solid #222}}
h3{{color:#ff8a40;font-size:1.1rem;margin:1.5rem 0 .5rem}}
p{{margin-bottom:.8rem}}
code{{background:#12121a;padding:2px 6px;border-radius:4px;font-size:.9em;color:#00ff88}}
pre{{background:#12121a;padding:1rem;border-radius:8px;overflow-x:auto;font-size:.82rem;color:#00ff88;margin:1rem 0;border:1px solid #222;white-space:pre-wrap}}
table{{width:100%;border-collapse:collapse;margin:1rem 0}}
th{{background:#12121a;color:#7B61FF;text-align:left;padding:.6rem .8rem;font-size:.8rem;text-transform:uppercase;letter-spacing:1px}}
td{{padding:.5rem .8rem;border-bottom:1px solid #1a1a2e;font-size:.85rem}}
tr:hover{{background:#12121a}}
.header{{text-align:center;padding:2rem;border-bottom:2px solid #7B61FF;margin-bottom:2rem}}
.header .subtitle{{color:#888;font-size:1rem}}
.summary-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin:1.5rem 0}}
.summary-card{{background:#12121a;border:1px solid #222;border-radius:8px;padding:1rem;text-align:center}}
.summary-card .num{{font-size:2rem;font-weight:800}}
.summary-card .label{{font-size:.7rem;text-transform:uppercase;color:#888;margin-top:.2rem}}
.critical .num{{color:#ff4060}}.high .num{{color:#ff8a40}}.medium .num{{color:#ffd740}}.low .num{{color:#00e5ff}}.info .num{{color:#888}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:700;text-transform:uppercase}}
.badge-critical{{background:rgba(255,64,96,.15);color:#ff4060}}.badge-high{{background:rgba(255,138,64,.15);color:#ff8a40}}
.badge-medium{{background:rgba(255,215,64,.15);color:#ffd740}}.badge-low{{background:rgba(0,229,255,.15);color:#00e5ff}}.badge-info{{background:rgba(136,136,136,.15);color:#888}}
.success{{color:#00ff88;font-weight:700}}.failed{{color:#888}}
.cred{{background:rgba(255,64,96,.1);border:1px solid rgba(255,64,96,.3);padding:.3rem .6rem;border-radius:4px;font-family:monospace;display:inline-block;margin:.2rem}}
ul,ol{{margin:.5rem 0 .5rem 1.5rem}} li{{margin:.3rem 0}}
strong{{color:#fff}}
.footer{{text-align:center;margin-top:3rem;padding:1.5rem;border-top:1px solid #222;color:#555;font-size:.8rem}}
.assessment{{background:#12121a;border:1px solid #222;border-radius:8px;padding:1.5rem 2rem;margin:1.5rem 0}}
@media print{{body{{background:#fff;color:#000}}h1,h2,h3{{color:#333}}pre,code{{background:#f5f5f5;color:#333}}}}
</style>
</head>
<body>
<div class="header">
  <h1>PENETRATION TEST REPORT</h1>
  <p class="subtitle">{_esc(target)} ({_esc(target_type)}) &mdash; {now}</p>
  <p class="subtitle">Generated by HackingTool Red Team Platform + Kimi-K2 AI</p>
</div>

<div class="summary-grid">
  <div class="summary-card critical"><div class="num">{summary.get('critical',0)}</div><div class="label">Critical</div></div>
  <div class="summary-card high"><div class="num">{summary.get('high',0)}</div><div class="label">High</div></div>
  <div class="summary-card medium"><div class="num">{summary.get('medium',0)}</div><div class="label">Medium</div></div>
  <div class="summary-card low"><div class="num">{summary.get('low',0)}</div><div class="label">Low</div></div>
  <div class="summary-card info"><div class="num">{summary.get('info',0)}</div><div class="label">Info</div></div>
</div>

<h2>Quick Stats</h2>
<table>
  <tr><td><strong>Total Findings</strong></td><td>{len(findings)}</td></tr>
  <tr><td><strong>Attacks Executed</strong></td><td>{len(attack_results)}</td></tr>
  <tr><td><strong>Successful Exploits</strong></td><td class="{'success' if successful else ''}">{len(successful)}</td></tr>
  <tr><td><strong>Credentials Found</strong></td><td>{len(set(creds))}</td></tr>
  <tr><td><strong>AI Analysis</strong></td><td>{'Kimi-K2 via OpenRouter' if ai_available() else 'Rule-based (set OPENROUTER_API_KEY for AI)'}</td></tr>
</table>

{f'<h2>Credentials Discovered</h2><div>' + ''.join(f'<span class="cred">{_esc(c)}</span>' for c in set(creds)) + '</div>' if creds else ''}

<h2>Full Assessment</h2>
<div class="assessment">
{assessment_html}
</div>

<h2>All Findings</h2>
<table>
<tr><th>Severity</th><th>Finding</th><th>Detail</th><th>Module</th></tr>
{''.join(f'<tr><td><span class="badge badge-{f["severity"]}">{f["severity"]}</span></td><td><strong>{_esc(f["title"])}</strong></td><td>{_esc(f["detail"])}</td><td>{_esc(f["module"])}</td></tr>' for f in sorted(findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x["severity"],5)))}
</table>

<h2>Attack Execution Log</h2>
{''.join(_render_attack_result_html(r) for r in attack_results) if attack_results else '<p>No attacks were auto-executed.</p>'}

<div class="footer">
  HackingTool Red Team Platform &mdash; AI-Powered by Kimi-K2 (MoonshotAI) via OpenRouter<br>
  Metasploit Framework integration: github.com/douglashyde/metasploit-framework<br>
  Report generated {now}
</div>
</body>
</html>"""


def _render_attack_result_html(r):
    """Render a single attack result for the HTML report."""
    analysis = r.get("analysis", {})
    status_class = "success" if analysis.get("success") else "failed"
    status_text = "EXPLOITED" if analysis.get("success") else "NO EXPLOIT"
    return f"""
<h3>{_esc(r['attack_name'])} <span class="{status_class}">[{status_text}]</span></h3>
<pre>$ {_esc(r['command'])}
{_esc(r['output'][:3000])}</pre>
<p><strong>Analysis:</strong> {_esc(analysis.get('summary', 'N/A'))}</p>
{'<p><strong>Credentials:</strong> ' + ', '.join(f'<span class="cred">{_esc(c)}</span>' for c in analysis.get("credentials", [])) + '</p>' if analysis.get("credentials") else ''}
"""


def _esc(s):
    """HTML-escape a string."""
    return (
        str(s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _md_to_html(md):
    """Basic markdown to HTML conversion."""
    lines = md.split("\n")
    html = []
    in_code = False
    in_list = False
    for line in lines:
        if line.strip().startswith("```"):
            if in_code:
                html.append("</pre>")
                in_code = False
            else:
                html.append("<pre>")
                in_code = True
            continue
        if in_code:
            html.append(_esc(line))
            continue
        # Headers
        if line.startswith("### "):
            html.append(f"<h3>{_format_inline(line[4:])}</h3>")
        elif line.startswith("## "):
            html.append(f"<h2>{_format_inline(line[3:])}</h2>")
        elif line.startswith("# "):
            html.append(f"<h1>{_format_inline(line[2:])}</h1>")
        elif line.strip().startswith("- "):
            if not in_list:
                html.append("<ul>")
                in_list = True
            html.append(f"<li>{_format_inline(line.strip()[2:])}</li>")
        elif re.match(r"^\d+\.\s", line.strip()):
            if not in_list:
                html.append("<ol>")
                in_list = True
            content = re.sub(r"^\d+\.\s", "", line.strip())
            html.append(f"<li>{_format_inline(content)}</li>")
        else:
            if in_list:
                html.append("</ul>" if html[-2].startswith("<ul") or "<li>" in html[-1] else "</ol>")
                in_list = False
            if line.strip():
                html.append(f"<p>{_format_inline(line)}</p>")
    if in_code:
        html.append("</pre>")
    if in_list:
        html.append("</ul>")
    return "\n".join(html)


def _format_inline(text):
    """Convert inline markdown formatting."""
    text = _esc(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    text = re.sub(r"_(.+?)_", r"<em>\1</em>", text)
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    return text
