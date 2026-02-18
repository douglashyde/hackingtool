#!/usr/bin/env python3
"""
HackingTool — Red Team Platform
Web interface with automated scanning, reporting, and attack suggestions.
"""

import json
import os
import subprocess
import threading
import time
import uuid
from flask import Flask, render_template, jsonify, request

# ── Import all tool collections ──────────────────────────────────────────────
from core import HackingTool, HackingToolsCollection
from tools.anonsurf import AnonSurfTools
from tools.ddos import DDOSTools
from tools.exploit_frameworks import ExploitFrameworkTools
from tools.forensic_tools import ForensicTools
from tools.information_gathering_tools import InformationGatheringTools
from tools.other_tools import OtherTools
from tools.payload_creator import PayloadCreatorTools
from tools.phising_attack import PhishingAttackTools
from tools.post_exploitation import PostExploitationTools
from tools.remote_administration import RemoteAdministrationTools
from tools.reverse_engineering import ReverseEngineeringTools
from tools.sql_tools import SqlInjectionTools
from tools.steganography import SteganographyTools
from tools.tool_manager import ToolManager
from tools.webattack import WebAttackTools
from tools.wireless_attack_tools import WirelessAttackTools
from tools.wordlist_generator import WordlistGeneratorTools
from tools.xss_attack import XSSAttackTools

# ── Import scanner engine ────────────────────────────────────────────────────
import scanner

app = Flask(__name__)

# ── Tools directory (where install_all_tools.sh clones repos) ───────────
TOOLS_DIR = os.environ.get("TOOLS_DIR", "/opt/hackingtool-arsenal")

# ── Category metadata ────────────────────────────────────────────────────────
CATEGORIES = [
    {"icon": "\U0001f6e1\ufe0f", "name": "Anonymously Hiding Tools",       "collection": AnonSurfTools()},
    {"icon": "\U0001f50d",       "name": "Information Gathering Tools",     "collection": InformationGatheringTools()},
    {"icon": "\U0001f4da",       "name": "Wordlist Generator",             "collection": WordlistGeneratorTools()},
    {"icon": "\U0001f4f6",       "name": "Wireless Attack Tools",          "collection": WirelessAttackTools()},
    {"icon": "\U0001f9e9",       "name": "SQL Injection Tools",            "collection": SqlInjectionTools()},
    {"icon": "\U0001f3a3",       "name": "Phishing Attack Tools",          "collection": PhishingAttackTools()},
    {"icon": "\U0001f310",       "name": "Web Attack Tools",               "collection": WebAttackTools()},
    {"icon": "\U0001f527",       "name": "Post Exploitation Tools",        "collection": PostExploitationTools()},
    {"icon": "\U0001f575\ufe0f", "name": "Forensic Tools",                 "collection": ForensicTools()},
    {"icon": "\U0001f4e6",       "name": "Payload Creator Tools",          "collection": PayloadCreatorTools()},
    {"icon": "\U0001f9f0",       "name": "Exploit Frameworks",             "collection": ExploitFrameworkTools()},
    {"icon": "\U0001f501",       "name": "Reverse Engineering Tools",      "collection": ReverseEngineeringTools()},
    {"icon": "\u26a1",           "name": "DDOS Attack Tools",              "collection": DDOSTools()},
    {"icon": "\U0001f5a5\ufe0f", "name": "Remote Administration Tools",    "collection": RemoteAdministrationTools()},
    {"icon": "\U0001f4a5",       "name": "XSS Attack Tools",               "collection": XSSAttackTools()},
    {"icon": "\U0001f5bc\ufe0f", "name": "Steganography Tools",            "collection": SteganographyTools()},
    {"icon": "\u2728",           "name": "Other Tools",                    "collection": OtherTools()},
]

# ── Task storage for async command execution ─────────────────────────────────
tasks = {}


def _get_attr(obj, *names, default=""):
    for n in names:
        v = getattr(obj, n, None)
        if v is not None:
            return v
    return default


def _guess_tool_dir(tool):
    """Check if a tool is installed by looking for its directory in TOOLS_DIR.

    Heuristics (in order):
    1. INSTALLATION_DIR attribute on the tool class
    2. Directory name extracted from the first 'cd <dir>' in RUN_COMMANDS
    3. Repo name extracted from the first 'git clone' in INSTALL_COMMANDS
    4. Check if a system binary exists (e.g. nmap, sqlmap)
    """
    # 1. Explicit dir
    inst_dir = getattr(tool, "INSTALLATION_DIR", "")
    if inst_dir:
        if os.path.isdir(inst_dir):
            return True
        if os.path.isdir(os.path.join(TOOLS_DIR, inst_dir)):
            return True

    # 2. Parse 'cd <dir>' from run commands
    for cmd in (getattr(tool, "RUN_COMMANDS", None) or []):
        if cmd.startswith("cd "):
            dirname = cmd.split("&&")[0].replace("cd ", "").strip()
            if os.path.isdir(os.path.join(TOOLS_DIR, dirname)):
                return True

    # 3. Parse repo name from git clone URL
    for cmd in (getattr(tool, "INSTALL_COMMANDS", None) or []):
        if "git clone" in cmd:
            url = cmd.split()[-1]
            repo_name = url.rstrip("/").rsplit("/", 1)[-1].replace(".git", "")
            if os.path.isdir(os.path.join(TOOLS_DIR, repo_name)):
                return True

    # 4. Check system binary (for tools like nmap, sqlmap installed via apt)
    title = (getattr(tool, "TITLE", "") or "").lower().split("(")[0].strip()
    if title and not getattr(tool, "INSTALL_COMMANDS", None):
        import shutil
        if shutil.which(title):
            return True

    return False


def extract_tools(tool_list):
    results = []
    for tool in tool_list:
        if isinstance(tool, HackingToolsCollection):
            results.append({
                "type": "collection",
                "title": _get_attr(tool, "TITLE", default=tool.__class__.__name__),
                "description": _get_attr(tool, "DESCRIPTION", default=""),
                "tools": extract_tools(tool.TOOLS),
            })
        elif isinstance(tool, HackingTool):
            install_cmds = _get_attr(tool, "INSTALL_COMMANDS", default=[])
            run_cmds = _get_attr(tool, "RUN_COMMANDS", default=[])
            installed = _guess_tool_dir(tool)
            results.append({
                "type": "tool",
                "title": _get_attr(tool, "TITLE", default=tool.__class__.__name__),
                "description": _get_attr(tool, "DESCRIPTION", default=""),
                "project_url": _get_attr(tool, "PROJECT_URL", default=""),
                "installed": installed,
                "installable": bool(install_cmds) and not installed,
                "runnable": bool(run_cmds),
                "install_commands": install_cmds if isinstance(install_cmds, list) else [],
                "run_commands": run_cmds if isinstance(run_cmds, list) else [],
            })
    return results


def build_api_data():
    categories = []
    for cat in CATEGORIES:
        coll = cat["collection"]
        categories.append({
            "icon": cat["icon"],
            "name": cat["name"],
            "description": _get_attr(coll, "DESCRIPTION", default=""),
            "tools": extract_tools(coll.TOOLS),
        })
    return categories


def run_command_async(task_id, commands):
    tasks[task_id] = {"output": "", "running": True, "returncode": None}
    combined_rc = 0
    cwd = TOOLS_DIR if os.path.isdir(TOOLS_DIR) else None
    for cmd in commands:
        tasks[task_id]["output"] += f"$ {cmd}\n"
        try:
            proc = subprocess.Popen(cmd, shell=True, cwd=cwd,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)
            for line in proc.stdout:
                tasks[task_id]["output"] += line
            proc.wait()
            tasks[task_id]["output"] += f"\n[exit code: {proc.returncode}]\n\n"
            if proc.returncode != 0:
                combined_rc = proc.returncode
        except Exception as e:
            tasks[task_id]["output"] += f"\nERROR: {e}\n"
            combined_rc = 1
    tasks[task_id]["running"] = False
    tasks[task_id]["returncode"] = combined_rc


# ══════════════════════════════════════════════════════════════════════════════
# Routes — Pages
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


# ══════════════════════════════════════════════════════════════════════════════
# Routes — Arsenal API (existing tool browser)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/tools")
def api_tools():
    return jsonify(build_api_data())


@app.route("/api/run", methods=["POST"])
def api_run():
    data = request.get_json(force=True)
    commands = data.get("commands", [])
    if not commands:
        return jsonify({"error": "No commands"}), 400
    task_id = str(uuid.uuid4())[:8]
    threading.Thread(target=run_command_async, args=(task_id, commands), daemon=True).start()
    return jsonify({"task_id": task_id})


@app.route("/api/install", methods=["POST"])
def api_install():
    data = request.get_json(force=True)
    commands = data.get("commands", [])
    if not commands:
        return jsonify({"error": "No commands"}), 400
    task_id = str(uuid.uuid4())[:8]
    threading.Thread(target=run_command_async, args=(task_id, commands), daemon=True).start()
    return jsonify({"task_id": task_id})


@app.route("/api/task/<task_id>")
def api_task(task_id):
    task = tasks.get(task_id)
    if not task:
        return jsonify({"error": "Not found"}), 404
    return jsonify(task)


# ══════════════════════════════════════════════════════════════════════════════
# Routes — Scan API (new orchestrated scanning)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/scan", methods=["POST"])
def api_scan_start():
    """Start an orchestrated scan against a target."""
    data = request.get_json(force=True)
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"}), 400
    target_type = data.get("target_type") or None
    scan_id = scanner.start_scan(target, target_type)
    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<scan_id>")
def api_scan_get(scan_id):
    """Get scan status, progress, findings, and attack suggestions."""
    scan = scanner.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)


@app.route("/api/scans")
def api_scan_list():
    """List all scans."""
    return jsonify(scanner.list_scans())


@app.route("/api/scan/<scan_id>/execute", methods=["POST"])
def api_scan_execute_attack(scan_id):
    """Execute an attack command from scan results."""
    data = request.get_json(force=True)
    command = data.get("command", "").strip()
    if not command:
        return jsonify({"error": "No command"}), 400
    task_id = str(uuid.uuid4())[:8]
    threading.Thread(target=run_command_async, args=(task_id, [command]), daemon=True).start()
    return jsonify({"task_id": task_id})


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n\033[1;35m" + "=" * 60)
    print("  HACKINGTOOL — Red Team Platform")
    print("  http://localhost:5000")
    print("=" * 60 + "\033[0m\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
