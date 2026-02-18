# Attack Chain 1: Admin Account Takeover — Test Environment

This directory contains a self-contained test environment that demonstrates
**Attack Chain 1** from the starregistry.com penetration test report.

It proves that the three WordPress vulnerabilities found on the live site
can be chained together for a full admin account takeover.

## Vulnerabilities Replicated

| # | Vulnerability | Severity |
|---|--------------|----------|
| 1 | REST API user enumeration (`/wp-json/wp/v2/users`) | Critical |
| 2 | Verbose login error messages (confirms valid usernames) | High |
| 3 | No rate limiting on `wp-login.php` | Critical |

## Quick Start (One Command)

```bash
cd attack-chain-test/scripts
bash setup-vulnerable-wp.sh
```

This starts the mock server, runs the full brute-force test, and stops the server.

## Manual Usage

### Step 1: Start the mock WordPress server

```bash
python3 scripts/mock_wordpress.py --port 8080 --admin-pass admin123
```

The server runs at `http://localhost:8080` with three test accounts:

| Username | Password | Role |
|----------|----------|------|
| tadmin | admin123 | Admin |
| shopmanager | shop2026! | Shop Manager |
| editor1 | editor_pass | Editor |

### Step 2: Run the brute-force test (in another terminal)

```bash
# Full attack chain (enumerate + confirm + brute-force)
python3 scripts/bruteforce_test.py --url http://localhost:8080

# Only run reconnaissance phases (skip brute-force)
python3 scripts/bruteforce_test.py --url http://localhost:8080 --skip-bruteforce

# Target a specific username
python3 scripts/bruteforce_test.py --url http://localhost:8080 --username shopmanager

# Use a custom wordlist
python3 scripts/bruteforce_test.py --url http://localhost:8080 --wordlist /path/to/passwords.txt
```

### Step 3: Stop the server

Press `Ctrl+C` in the terminal running `mock_wordpress.py`.

## What the Attack Chain Does

```
Phase 1: REST API Enumeration
   GET /wp-json/wp/v2/users
   → Discovers usernames (tadmin, shopmanager, editor1)

Phase 2: Username Confirmation
   POST /wp-login.php (with wrong password)
   → Error says "password for tadmin is incorrect" (confirms user exists)

Phase 2.5: Rate Limit Check
   POST /wp-login.php × 10 rapid attempts
   → No rate limiting, no lockout, no CAPTCHA

Phase 3: Dictionary Brute-Force
   POST /wp-login.php with each password from wordlist
   → HTTP 302 redirect to /wp-admin/ = password found
```

## Files

| File | Description |
|------|-------------|
| `scripts/mock_wordpress.py` | Mock WordPress server replicating vulnerabilities |
| `scripts/bruteforce_test.py` | Full Attack Chain 1 brute-force testing script |
| `scripts/setup-vulnerable-wp.sh` | One-command quick start script |
| `docker-compose.yml` | Optional: Full WordPress + MySQL via Docker |

## Docker Alternative (Optional)

If you have Docker available and want to test against a **real** WordPress instance:

```bash
docker compose up -d
# Wait ~30 seconds for WordPress to initialize
# Visit http://localhost:8080 to complete WordPress setup
# Then run the brute-force test
python3 scripts/bruteforce_test.py --url http://localhost:8080
```

## Recommended Fixes for Production

1. **Disable REST API user enumeration** — Add to `functions.php`:
   ```php
   add_filter('rest_endpoints', function($endpoints) {
       if (isset($endpoints['/wp/v2/users'])) {
           unset($endpoints['/wp/v2/users']);
       }
       return $endpoints;
   });
   ```

2. **Genericize login errors** — Add to `functions.php`:
   ```php
   add_filter('login_errors', function() {
       return 'Invalid username or password.';
   });
   ```

3. **Add rate limiting** — Install a plugin like Wordfence or Limit Login Attempts Reloaded

4. **Enable 2FA** — Use a plugin like WP 2FA or Google Authenticator

5. **Strong passwords** — Enforce 20+ character passwords for admin accounts
