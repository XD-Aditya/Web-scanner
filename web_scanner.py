import requests
import socket
import urllib3
import re
from urllib.parse import urlparse, parse_qs, urlencode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("""
=================================
        web scanner PYTHON3
   Simple Web Vulnerability Tool
=================================
""")

target = input("Enter target URL (example: https://example.com): ").strip()

headers = {"User-Agent": "Mozilla/5.0"}

parsed = urlparse(target)
domain = parsed.netloc


# --------------------------------
# Site Status
# --------------------------------
def check_site():

    try:
        r = requests.get(target, headers=headers, timeout=10, verify=False)

        print("\n[+] Site is UP")
        print("Status Code:", r.status_code)

    except:
        print("\n[-] Site unreachable")
        exit()


# --------------------------------
# Header Security Check
# --------------------------------
def header_check():

    print("\n[+] Checking Security Headers")

    try:

        r = requests.get(target, headers=headers, timeout=10, verify=False)

        important = [
            "X-Frame-Options",
            "Content-Security-Policy",
            "X-XSS-Protection",
            "Strict-Transport-Security"
        ]

        for h in important:

            if h in r.headers:
                print("[SAFE]", h, "found")

            else:
                print("[WARNING]", h, "missing")

    except:
        print("[WARNING] Header check failed")


# --------------------------------
# Technology Detection
# --------------------------------
def tech_detect():

    print("\n[+] Detecting Technologies")

    try:

        r = requests.get(target, headers=headers, timeout=10, verify=False)

        html = r.text.lower()
        cookies = r.cookies.get_dict()

        server = r.headers.get("Server")
        powered = r.headers.get("X-Powered-By")

        if server:
            print("[INFO] Server:", server)

        if powered:
            print("[INFO] Powered By:", powered)

        for cookie in cookies:

            c = cookie.lower()

            if "phpsessid" in c:
                print("[FOUND] PHP detected")

            if "laravel_session" in c:
                print("[FOUND] Laravel detected")

            if "csrftoken" in c:
                print("[FOUND] Django detected")

            if "jsessionid" in c:
                print("[FOUND] Java / JSP detected")

        if "wp-content" in html:
            print("[FOUND] WordPress detected")

        if "react" in html:
            print("[FOUND] ReactJS detected")

        if "angular" in html:
            print("[FOUND] Angular detected")

        if "vue" in html:
            print("[FOUND] VueJS detected")

        if "jquery" in html:
            print("[INFO] jQuery detected")

        if "bootstrap" in html:
            print("[INFO] Bootstrap detected")

    except:
        print("[WARNING] Technology detection failed")


# --------------------------------
# XSS Scan
# --------------------------------
def xss_scan():

    print("\n[+] Starting XSS Scan")

    payload = "<script>alert(1)</script>"

    params = parse_qs(parsed.query)

    if not params:
        print("[INFO] No parameters found in URL")
        return

    try:

        for p in params:
            params[p] = payload

        query = urlencode(params, doseq=True)

        test_url = parsed.scheme + "://" + parsed.netloc + parsed.path + "?" + query

        r = requests.get(test_url, headers=headers, verify=False)

        if payload in r.text:
            print("[!] Possible XSS vulnerability detected")

        else:
            print("[SAFE] No XSS detected")

    except:
        print("[WARNING] XSS scan failed")


# --------------------------------
# SQL Injection Scan
# --------------------------------
def sqli_scan():

    print("\n[+] Starting SQL Injection Scan")

    payload = "'"

    params = parse_qs(parsed.query)

    if not params:
        print("[INFO] No parameters found in URL")
        return

    try:

        for p in params:
            params[p] = payload

        query = urlencode(params, doseq=True)

        test_url = parsed.scheme + "://" + parsed.netloc + parsed.path + "?" + query

        r = requests.get(test_url, headers=headers, verify=False)

        errors = ["sql syntax","mysql","syntax error","database error"]

        for err in errors:

            if err in r.text.lower():
                print("[!] Possible SQL Injection vulnerability detected")
                return

        print("[SAFE] No SQL Injection detected")

    except:
        print("[WARNING] SQL scan failed")


# --------------------------------
# Admin Panel Finder (Accurate)
# --------------------------------
def admin_scan():

    print("\n[+] Starting Admin Panel Scan")

    paths = [
        "admin",
        "administrator",
        "login",
        "panel",
        "cpanel",
        "dashboard"
    ]

    extensions = ["",".php",".html",".asp",".aspx",".jsp"]

    login_keywords = ["password","username","login","signin"]

    try:
        fake = requests.get(target.rstrip("/") + "/random_admin_test",
                            headers=headers,
                            timeout=5,
                            verify=False)

        baseline_length = len(fake.text)

    except:
        baseline_length = 0


    for p in paths:

        for ext in extensions:

            url = target.rstrip("/") + "/" + p + ext

            try:

                r = requests.get(url,
                                 headers=headers,
                                 timeout=5,
                                 verify=False)

                page = r.text.lower()

                if r.status_code in [200,301,302]:

                    if abs(len(r.text) - baseline_length) > 120:

                        if any(word in page for word in login_keywords):

                            print("[FOUND] Admin Panel:", url)

            except:
                pass


# --------------------------------
# Directory Scan
# --------------------------------
def directory_scan():

    print("\n[+] Starting Directory Scan")

    dirs = ["backup","uploads","config","private","logs","data","api"]

    try:
        fake = requests.get(target+"/random_test",
                            headers=headers,
                            verify=False)

        base_len = len(fake.text)

    except:
        base_len = 0

    for d in dirs:

        url = target.rstrip("/") + "/" + d

        try:

            r = requests.get(url,
                             headers=headers,
                             timeout=5,
                             verify=False)

            if abs(len(r.text) - base_len) > 100:
                print("[FOUND] Directory:", url)

        except:
            pass


# --------------------------------
# Robots.txt
# --------------------------------
def robots_scan():

    print("\n[+] Checking robots.txt")

    try:

        r = requests.get(target.rstrip("/")+"/robots.txt",
                         headers=headers,
                         verify=False)

        if r.status_code == 200:

            print("[FOUND] robots.txt")

            for line in r.text.split("\n"):

                if "Disallow" in line:
                    print("[INFO]", line.strip())

        else:
            print("[SAFE] robots.txt not found")

    except:
        pass


# --------------------------------
# Email Extractor
# --------------------------------
def email_scan():

    print("\n[+] Extracting Emails")

    try:

        r = requests.get(target, headers=headers, verify=False)

        emails = re.findall(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            r.text
        )

        if emails:

            for e in set(emails):
                print("[FOUND] Email:", e)

        else:
            print("[SAFE] No emails found")

    except:
        print("[WARNING] Email scan failed")


# --------------------------------
# Port Scan
# --------------------------------
def port_scan():

    print("\n[+] Starting Port Scan")

    ports = [21,22,23,25,53,80,110,139,143,443,3306,8080]

    for port in ports:

        try:

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((domain, port))

            if result == 0:
                print("[OPEN] Port", port)

            sock.close()

        except:
            pass


# --------------------------------
# Subdomain Scan
# --------------------------------
def subdomain_scan():

    print("\n[+] Starting Subdomain Scan")

    subs = ["www","mail","ftp","admin","blog","test","dev","api","portal"]

    for s in subs:

        url = f"https://{s}.{domain}"

        try:

            requests.get(url, timeout=3, verify=False)

            print("[FOUND]", url)

        except:
            pass


# --------------------------------
# Run Scanner
# --------------------------------
check_site()
header_check()
tech_detect()
xss_scan()
sqli_scan()
admin_scan()
directory_scan()
robots_scan()
email_scan()
port_scan()
subdomain_scan()

print("\nScan Completed")
