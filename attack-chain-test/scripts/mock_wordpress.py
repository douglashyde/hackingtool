#!/usr/bin/env python3
"""
Mock WordPress Server — Replicates starregistry.com vulnerabilities

This is a lightweight HTTP server that mimics the exact WordPress login
behavior and REST API endpoints found on www.starregistry.com. It exposes
the same three Attack Chain 1 vulnerabilities:

  1. REST API user enumeration (/wp-json/wp/v2/users)
  2. Verbose login error messages (confirms valid/invalid usernames)
  3. No rate limiting on wp-login.php

Usage:
    python3 mock_wordpress.py                    # default port 8080
    python3 mock_wordpress.py --port 9090        # custom port
    python3 mock_wordpress.py --admin-pass admin  # set admin password

Then run the brute-force test:
    python3 bruteforce_test.py --url http://localhost:8080
"""

import argparse
import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Default users (mirroring starregistry.com REST API disclosure)
USERS = [
    {"id": 1, "name": "Test Admin", "slug": "tadmin", "description": "",
     "link": "http://localhost:8080/author/tadmin/",
     "avatar_urls": {"24": "", "48": "", "96": ""}},
    {"id": 2, "name": "Shop Manager", "slug": "shopmanager", "description": "",
     "link": "http://localhost:8080/author/shopmanager/",
     "avatar_urls": {"24": "", "48": "", "96": ""}},
    {"id": 3, "name": "Content Editor", "slug": "editor1", "description": "",
     "link": "http://localhost:8080/author/editor1/",
     "avatar_urls": {"24": "", "48": "", "96": ""}},
]

# Credentials database (username -> password)
CREDENTIALS = {}

# ANSI colors for server log
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"


WP_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en-US">
<head>
    <title>Log In &lsaquo; Star Registry &#8212; WordPress</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif; background: #f0f0f1; }}
        .login {{ width: 320px; margin: 100px auto; padding: 26px 24px; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,.13); }}
        h1 {{ text-align: center; font-size: 20px; margin-bottom: 24px; }}
        label {{ display: block; margin-bottom: 4px; font-weight: 600; }}
        input[type=text], input[type=password] {{ width: 100%; padding: 8px; margin-bottom: 16px; border: 1px solid #8c8f94; box-sizing: border-box; }}
        input[type=submit] {{ width: 100%; padding: 10px; background: #2271b1; color: white; border: none; cursor: pointer; font-size: 14px; }}
        .login_error {{ border-left: 4px solid #d63638; background: #fcf0f1; padding: 12px; margin-bottom: 20px; }}
    </style>
</head>
<body>
<div class="login">
    <h1>Star Registry</h1>
    {error_html}
    <form method="post" action="/wp-login.php">
        <label for="log">Username or Email Address</label>
        <input type="text" name="log" id="log" value="{username}" />
        <label for="pwd">Password</label>
        <input type="password" name="pwd" id="pwd" />
        <input type="submit" name="wp-submit" value="Log In" />
        <input type="hidden" name="redirect_to" value="/wp-admin/" />
        <input type="hidden" name="testcookie" value="1" />
    </form>
</div>
</body>
</html>"""


class WordPressHandler(BaseHTTPRequestHandler):
    """Handles requests mimicking WordPress behavior"""

    def log_message(self, format, *args):
        """Custom colorized logging"""
        msg = format % args
        if "200" in msg or "302" in msg:
            color = GREEN
        elif "404" in msg:
            color = YELLOW
        else:
            color = CYAN
        print(f"  {color}[{self.log_date_time_string()}]{RESET} {msg}")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # REST API: User enumeration endpoint
        if path == "/wp-json/wp/v2/users":
            self._handle_users_api()

        # REST API: Namespace discovery
        elif path == "/wp-json":
            self._handle_api_root()

        # Login page
        elif path == "/wp-login.php" or path == "/wp-login":
            self._serve_login_page()

        # Admin area (requires auth)
        elif path.startswith("/wp-admin"):
            self._send_response(200, "text/html",
                "<h1>WordPress Dashboard</h1><p>You are logged in as admin.</p>")

        # Homepage
        elif path == "" or path == "/":
            self._send_response(200, "text/html",
                "<html><head><title>Star Registry - Test Site</title></head>"
                "<body><h1>Star Registry</h1>"
                "<p>This is a mock WordPress site for Attack Chain 1 testing.</p>"
                "<p><a href='/wp-login.php'>Login</a> | "
                "<a href='/wp-json/wp/v2/users'>REST API Users</a></p>"
                "</body></html>")

        else:
            self._send_response(404, "text/html", "<h1>404 Not Found</h1>")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/wp-login.php" or path == "/wp-login":
            self._handle_login()
        else:
            self._send_response(404, "text/html", "<h1>404 Not Found</h1>")

    def _handle_users_api(self):
        """Vulnerable: Exposes user data via REST API (no authentication required)"""
        response = json.dumps(USERS, indent=2)
        self._send_response(200, "application/json", response)

    def _handle_api_root(self):
        """REST API root — namespace discovery"""
        data = {
            "name": "Star Registry",
            "description": "Test WordPress Site",
            "url": "http://localhost:8080",
            "namespaces": ["wp/v2", "wp-site-health/v1"],
            "authentication": {},
            "routes": {
                "/wp/v2/users": {
                    "namespace": "wp/v2",
                    "methods": ["GET"],
                    "endpoints": [{"methods": ["GET"]}]
                }
            }
        }
        self._send_response(200, "application/json", json.dumps(data, indent=2))

    def _serve_login_page(self, error_html="", username=""):
        """Serve the login form"""
        html = WP_LOGIN_PAGE.format(error_html=error_html, username=username)
        self._send_response(200, "text/html", html)

    def _handle_login(self):
        """
        Vulnerable login handler:
        - Confirms whether username exists (verbose error messages)
        - No rate limiting
        - Redirects to wp-admin on success (302)
        """
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        params = parse_qs(body)

        username = params.get("log", [""])[0]
        password = params.get("pwd", [""])[0]

        # Check if username exists
        valid_usernames = {u["slug"] for u in USERS}

        if username not in valid_usernames:
            # VULNERABILITY: Tells attacker the username doesn't exist
            error = (
                '<div class="login_error"><strong>Error:</strong> '
                f'The username <strong>{username}</strong> is not registered on this site. '
                'If you are unsure of your username, try your email address instead.</div>'
            )
            html = WP_LOGIN_PAGE.format(error_html=error, username=username)
            self._send_response(200, "text/html", html)
            return

        # Username exists — check password
        if username in CREDENTIALS and CREDENTIALS[username] == password:
            # Successful login — redirect to wp-admin (302)
            self.send_response(302)
            self.send_header("Location", "/wp-admin/")
            self.send_header("Set-Cookie",
                f"wordpress_logged_in_test={username}; Path=/")
            self.end_headers()
            print(f"  {RED}{BOLD}[!!!] SUCCESSFUL LOGIN: {username}:{password}{RESET}")
            return

        # VULNERABILITY: Confirms the username IS valid but password is wrong
        error = (
            '<div class="login_error"><strong>Error:</strong> '
            f'The password you entered for the username <strong>{username}</strong> is incorrect. '
            '<a href="/wp-login.php?action=lostpassword">Lost your password?</a></div>'
        )
        html = WP_LOGIN_PAGE.format(error_html=error, username=username)
        self._send_response(200, "text/html", html)

    def _send_response(self, code, content_type, body):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body.encode())))
        # Mimic WordPress headers
        self.send_header("X-Powered-By", "PHP/8.2.0")
        self.send_header("Link", '<http://localhost:8080/wp-json/>; rel="https://api.w.org/"')
        self.end_headers()
        self.wfile.write(body.encode())


def main():
    parser = argparse.ArgumentParser(
        description="Mock WordPress server for Attack Chain 1 testing"
    )
    parser.add_argument("--port", type=int, default=8080,
                        help="Port to listen on (default: 8080)")
    parser.add_argument("--admin-pass", default="admin123",
                        help="Password for 'tadmin' account (default: admin123)")
    args = parser.parse_args()

    # Set up credentials
    CREDENTIALS["tadmin"] = args.admin_pass
    CREDENTIALS["shopmanager"] = "shop2026!"
    CREDENTIALS["editor1"] = "editor_pass"

    print(f"""
{BOLD}{RED}╔══════════════════════════════════════════════════════════════╗
║       MOCK WORDPRESS SERVER — ATTACK CHAIN 1 TEST          ║
║                                                            ║
║  Replicates starregistry.com vulnerabilities:              ║
║    ✗ REST API user enumeration (no auth required)          ║
║    ✗ Verbose login error messages                          ║
║    ✗ No rate limiting on login attempts                    ║
║                                                            ║
║  ⚠  FOR LOCAL TESTING ONLY                                 ║
╚══════════════════════════════════════════════════════════════╝{RESET}

  {CYAN}Server:{RESET}    http://localhost:{args.port}
  {CYAN}Login:{RESET}     http://localhost:{args.port}/wp-login.php
  {CYAN}REST API:{RESET}  http://localhost:{args.port}/wp-json/wp/v2/users

  {YELLOW}Test accounts:{RESET}
    tadmin      / {args.admin_pass}  (admin)
    shopmanager / shop2026!    (shop manager)
    editor1     / editor_pass  (editor)

  {GREEN}Press Ctrl+C to stop the server.{RESET}
""")

    server = HTTPServer(("0.0.0.0", args.port), WordPressHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n  {YELLOW}Server stopped.{RESET}")
        server.server_close()


if __name__ == "__main__":
    main()
