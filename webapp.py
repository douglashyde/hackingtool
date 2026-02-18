#!/usr/bin/env python3
"""
HackingTool Web Interface
A modern web dashboard that combines all tools into one browser-based UI.
"""

import json
import os
import subprocess
import threading
import time
import uuid
from flask import Flask, render_template, jsonify, request

# ── Import all tool collections (same as hackingtool.py) ────────────────────
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

app = Flask(__name__)

# ── Category metadata matching hackingtool.py ───────────────────────────────
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

# ── Task output storage (for async command execution) ───────────────────────
tasks = {}  # task_id -> {"output": str, "running": bool, "returncode": int|None}


def _get_attr(obj, *names, default=""):
    for n in names:
        v = getattr(obj, n, None)
        if v is not None:
            return v
    return default


def extract_tools(tool_list):
    """Recursively extract tool metadata from a list of HackingTool / HackingToolsCollection."""
    results = []
    for tool in tool_list:
        if isinstance(tool, HackingToolsCollection):
            # Sub-collection: recurse into it
            sub_tools = extract_tools(tool.TOOLS)
            results.append({
                "type": "collection",
                "title": _get_attr(tool, "TITLE", default=tool.__class__.__name__),
                "description": _get_attr(tool, "DESCRIPTION", default=""),
                "tools": sub_tools,
            })
        elif isinstance(tool, HackingTool):
            install_cmds = _get_attr(tool, "INSTALL_COMMANDS", default=[])
            run_cmds = _get_attr(tool, "RUN_COMMANDS", default=[])
            results.append({
                "type": "tool",
                "title": _get_attr(tool, "TITLE", default=tool.__class__.__name__),
                "description": _get_attr(tool, "DESCRIPTION", default=""),
                "project_url": _get_attr(tool, "PROJECT_URL", default=""),
                "installable": bool(install_cmds),
                "runnable": bool(run_cmds),
                "install_commands": install_cmds if isinstance(install_cmds, list) else [],
                "run_commands": run_cmds if isinstance(run_cmds, list) else [],
            })
    return results


def build_api_data():
    """Build the full JSON tree of categories → tools."""
    categories = []
    for cat in CATEGORIES:
        coll = cat["collection"]
        tools = extract_tools(coll.TOOLS)
        categories.append({
            "icon": cat["icon"],
            "name": cat["name"],
            "description": _get_attr(coll, "DESCRIPTION", default=""),
            "tools": tools,
        })
    return categories


def run_command_async(task_id, commands):
    """Run a list of shell commands sequentially, capturing combined output."""
    tasks[task_id] = {"output": "", "running": True, "returncode": None}
    combined_rc = 0
    for cmd in commands:
        tasks[task_id]["output"] += f"$ {cmd}\n"
        try:
            proc = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
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


# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/tools")
def api_tools():
    return jsonify(build_api_data())


@app.route("/api/run", methods=["POST"])
def api_run():
    """Execute a tool's run commands asynchronously."""
    data = request.get_json(force=True)
    commands = data.get("commands", [])
    if not commands:
        return jsonify({"error": "No commands provided"}), 400
    task_id = str(uuid.uuid4())[:8]
    t = threading.Thread(target=run_command_async, args=(task_id, commands), daemon=True)
    t.start()
    return jsonify({"task_id": task_id})


@app.route("/api/install", methods=["POST"])
def api_install():
    """Execute a tool's install commands asynchronously."""
    data = request.get_json(force=True)
    commands = data.get("commands", [])
    if not commands:
        return jsonify({"error": "No commands provided"}), 400
    task_id = str(uuid.uuid4())[:8]
    t = threading.Thread(target=run_command_async, args=(task_id, commands), daemon=True)
    t.start()
    return jsonify({"task_id": task_id})


@app.route("/api/task/<task_id>")
def api_task(task_id):
    """Poll for command output."""
    task = tasks.get(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404
    return jsonify(task)


# ── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n\033[1;35m" + "=" * 60)
    print("  HACKINGTOOL — Web Dashboard")
    print("  Open http://localhost:5000 in your browser")
    print("=" * 60 + "\033[0m\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
