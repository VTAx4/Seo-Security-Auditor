import requests
from bs4 import BeautifulSoup
import re

def analyze_website(url):
    """
    The main analysis engine. It takes a URL, runs all checks,
    and returns the results and scores.
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        return f"Error: Could not fetch the website. {e}", 0, 0

    soup = BeautifulSoup(response.content, 'html.parser')
    
    # --- Scoring ---
    security_score = 0
    seo_score = 0
    
    # --- Run Security Checks ---
    security_results = []
    
    https_res, https_pts = check_https(url)
    security_results.append(https_res)
    security_score += https_pts
    
    headers_res, headers_pts = check_security_headers(response)
    security_results.append(headers_res)
    security_score += headers_pts

    server_res, server_pts = check_server_version(response)
    security_results.append(server_res)
    security_score += server_pts

    robots_res, robots_pts = check_robots_txt(url)
    security_results.append(robots_res)
    security_score += robots_pts
    
    js_res, js_pts = check_js_libraries(soup)
    security_results.append(js_res)
    security_score += js_pts

    files_res, files_pts = check_sensitive_files(url)
    security_results.append(files_res)
    security_score += files_pts
    
    subdomain_res, _ = check_subdomains(url) # No points for subdomains, just info
    security_results.append(subdomain_res)

    # --- Run SEO Checks ---
    seo_results = []

    title_res, title_pts = check_title_tag(soup)
    seo_results.append(title_res)
    seo_score += title_pts

    h1_res, h1_pts = check_h1_tag(soup)
    seo_results.append(h1_res)
    seo_score += h1_pts

    # --- Combine Results ---
    final_report = "--- Security Checks ---\n" + "\n".join(security_results)
    final_report += "\n\n--- SEO Checks ---\n" + "\n".join(seo_results)
    
    return final_report, security_score, seo_score

# --- Check Functions (Now return result string AND score) ---
def check_https(url):
    if url.startswith("https://"):
        return "✅ OK: Website uses HTTPS.", 25
    else:
        return "❌ FAIL: Website does not use HTTPS.", 0

def check_security_headers(response):
    missing_headers = [h for h in ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options'] if h not in response.headers]
    if not missing_headers:
        return "✅ OK: Important security headers are present.", 20
    else:
        return f"❌ WARN: Missing security headers: {', '.join(missing_headers)}.", 5

def check_server_version(response):
    server_header = response.headers.get('Server')
    if not server_header or not any(char.isdigit() for char in server_header):
        return "✅ OK: Server version is not exposed.", 10
    else:
        return f"❌ WARN: Server version is exposed: \"{server_header}\".", 0

def check_robots_txt(url):
    base_url = '/'.join(url.split('/')[:3])
    try:
        response = requests.get(f"{base_url}/robots.txt", timeout=5)
        if response.status_code == 200:
            sensitive_keywords = ['admin', 'login', 'wp-admin', 'private', 'backup']
            found_paths = [line.split(':', 1)[1].strip() for line in response.text.splitlines() if line.lower().startswith('disallow:') and any(keyword in line.lower() for keyword in sensitive_keywords)]
            if found_paths:
                return f"❌ WARN: Potentially sensitive paths in robots.txt: {', '.join(found_paths)}.", 5
            return "✅ OK: robots.txt found, no sensitive paths detected.", 10
        return "✅ OK: No robots.txt file found.", 10
    except requests.RequestException:
        return "ℹ️ INFO: Could not check for robots.txt file.", 5

def check_js_libraries(soup):
    vulnerable_libs = {'jquery-1.12.4': 'XSS vulnerability'}
    found_vulnerable = [f"{lib} ({reason})" for script in soup.find_all('script', src=True) for lib, reason in vulnerable_libs.items() if lib in script['src']]
    if found_vulnerable:
        return f"❌ CRITICAL: Found vulnerable JS libraries: {', '.join(found_vulnerable)}.", 0
    return "✅ OK: No known vulnerable JavaScript libraries detected.", 15

def check_sensitive_files(url):
    base_url = '/'.join(url.split('/')[:3])
    sensitive_files = ['.env', '.git/config', '.git/HEAD']
    found_files = []
    for filename in sensitive_files:
        try:
            response = requests.get(f"{base_url}/{filename}", timeout=3)
            if response.status_code == 200 and len(response.text) > 0:
                found_files.append(filename)
        except requests.RequestException:
            continue
    if found_files:
        return f"❌ CRITICAL: Found exposed sensitive files: {', '.join(found_files)}.", 0
    return "✅ OK: No common sensitive files were found.", 15

def check_subdomains(url):
    domain = url.split('//')[-1].split('/')[0].replace('www.', '')
    common_subdomains = ['dev', 'test', 'staging', 'api', 'blog']
    found_subdomains = []
    for sub in common_subdomains:
        try:
            requests.get(f"https://{sub}.{domain}", timeout=3)
            found_subdomains.append(f"{sub}.{domain}")
        except requests.RequestException:
            continue
    if found_subdomains:
        return f"ℹ️ INFO: Discovered public subdomains: {', '.join(found_subdomains)}.", 0
    return "✅ OK: No common subdomains discovered.", 0

def check_title_tag(soup):
    title_tag = soup.find('title')
    if title_tag and title_tag.string:
        if 50 <= len(title_tag.string) <= 60:
            return f"✅ OK: Title tag found with good length.", 50
        return f"✅ OK: Title tag found but length is suboptimal.", 30
    return "❌ FAIL: No <title> tag found.", 0

def check_h1_tag(soup):
    h1_tags = soup.find_all('h1')
    if len(h1_tags) == 1:
        return "✅ OK: Exactly one <h1> tag found.", 50
    elif len(h1_tags) > 1:
        return f"❌ FAIL: Found {len(h1_tags)} <h1> tags. There should only be one.", 10
    return "❌ FAIL: No <h1> tag found.", 0