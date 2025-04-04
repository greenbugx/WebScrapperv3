from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import requests
import os
import re
import json
import hashlib
import time
import random
import urllib
from urllib.parse import urljoin, urlparse
import logging
from concurrent.futures import ThreadPoolExecutor

# Colors for UI
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Configure logging
logging.basicConfig(filename="scraper.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def show_ascii_art():
    art = f"""{GREEN}
                                                     
                            █████████                                            
                          █████████████                                          
                        █████   █   █████                                        
                      ███████      ██████                                        
                      ████         ██████                                        
                     ██████        ████                                          
                    ████            ████                                         
                    ██████            ███                                        
                    ███████                                                      
                     ████████                                                    
                      ██████████                                                 
                     █████████████   ███                                         
                     ██████████████████ ████                                     
                  ███ ████████████████████ ███                                   
                █████████ ████████████     ██ █████████                          
               ██     ███ ██████████████████  █████████████                      
               █    ███████   ████████████████████ ███████████                   
              ██   ███   ███ ██  ███████████████      █████████                  
              █    ██     █████████████████████       █ ████████                 
                  ██     ████████████ █████ ████      █████ █████                
                   █     ████          ███   █          ████  ███                
                   █     ██████████                      ████  ██                
                          ██████████                       ███ ██                
                          ████████████                                           
                          ███████████████                                        
                            ██████   ██████                                      
                              ███████                                            
                                   ██████                                        
                                                                                 
         ██████   ██████    █████   ██████    ███████  ███    ████    ███   ███ ██       ██  ███████              
        ████████ ████████ █████████ ████████ █████████ ███  ████████ █████ ████ ████    ███ █████████             
        ████ ███ ███  ███ ████ ████ ████ ███ ████  ███ ███  ███  ███ ██████████ ████    ███       ████            
        ████     ███   ██ ████ ████ ████ ███ ████  ███ ███  ███  ███ ██████████  ████  ███       ████             
        ███████  ███      ████ ████ ████████ █████████ ███  ███  ███ ██████████   ███████   █████████             
            ████ ███      ████ ████ ██████   ████████  ███  ███  ███ ██████████    █████    ████████             
        ████ ███ ███  ███ ████ ████ ███   ██ ███       ███  ███  ███ ████ █████    █████         █████            
        ████████ ████████ █████████ ███   ██ ███       ███  ████████ ████  ████     ███    ██████████             
         ██████   ██████    █████   ███    ██ ███      ███   ██████   ███   ███     ███    █████████    
               
{RESET}
    """
    print(art)
    print(f"{GREEN}                                                                                          GreenBugX{RESET}\n")

def scan_for_xss(url, html_content, headers):
    vulnerable_inputs = []
    
    # Look for input fields that might be vulnerable to XSS
    soup = BeautifulSoup(html_content, "html.parser")
    inputs = soup.find_all(['input', 'textarea'])
    forms = soup.find_all('form')
    
    # Check for missing XSS protections in inputs
    for input_field in inputs:
        input_type = input_field.get('type', '')
        input_name = input_field.get('name', 'unnamed')
        
        if input_type.lower() in ['text', 'search', 'url', 'email', ''] or not input_type:
            # Check if input has proper validation attributes
            if not any([input_field.has_attr('pattern'), 
                        input_field.has_attr('maxlength')]):
                vulnerable_inputs.append({
                    'element': str(input_field)[:100],
                    'name': input_name,
                    'issue': 'Potentially vulnerable to XSS - missing validation'
                })
    
    # Check if the page reflects URL parameters
    parsed_url = urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    for param, value in query_params.items():
        if value and value[0] in html_content:
            vulnerable_inputs.append({
                'parameter': param,
                'value': value[0],
                'issue': 'Parameter reflected in page content - potential XSS'
            })
    
    return vulnerable_inputs

def scan_for_sql_injection(url, html_content, headers):
    potential_vulnerabilities = []
    
    # Look for signs of SQL injection vulnerabilities
    soup = BeautifulSoup(html_content, "html.parser")
    forms = soup.find_all('form')
    
    # Check forms with database-related field names
    sql_related_names = ['id', 'user', 'username', 'password', 'email', 'query', 
                         'search', 'category', 'product', 'item', 'article']
    
    for form in forms:
        inputs = form.find_all('input')
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        
        sql_related_inputs = []
        for input_field in inputs:
            name = input_field.get('name', '')
            if any(sql_name in name.lower() for sql_name in sql_related_names):
                sql_related_inputs.append(name)
        
        if sql_related_inputs and method == 'get':
            potential_vulnerabilities.append({
                'form_action': action,
                'method': method,
                'sql_related_inputs': sql_related_inputs,
                'issue': 'Form with database-related fields using GET method'
            })
    
    # Check URL parameters for SQL injection possibilities
    parsed_url = urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    for param in query_params:
        if any(sql_name in param.lower() for sql_name in sql_related_names):
            potential_vulnerabilities.append({
                'parameter': param,
                'issue': 'URL parameter potentially used in database queries'
            })
    
    return potential_vulnerabilities

def check_outdated_software(html_content, headers):
    software_versions = []
    
    # Check HTTP headers for server information
    if 'Server' in headers:
        software_versions.append({
            'software': 'Server',
            'version': headers['Server'],
            'source': 'HTTP Header'
        })
    
    if 'X-Powered-By' in headers:
        software_versions.append({
            'software': 'X-Powered-By',
            'version': headers['X-Powered-By'],
            'source': 'HTTP Header'
        })
    
    # Look for common CMS indicators
    soup = BeautifulSoup(html_content, "html.parser")
    
    # WordPress detection
    wp_content = soup.find_all(attrs={"href": re.compile(r'wp-content|wp-includes')})
    if wp_content:
        # Try to find WordPress version
        wp_version_meta = soup.find('meta', {'name': 'generator'})
        version = wp_version_meta.get('content', 'Unknown version') if wp_version_meta else 'Detected (version unknown)'
        if 'WordPress' in version:
            software_versions.append({
                'software': 'WordPress',
                'version': version.replace('WordPress ', ''),
                'source': 'Meta Generator Tag'
            })
        else:
            software_versions.append({
                'software': 'WordPress',
                'version': 'Detected (version unknown)',
                'source': 'Resource paths'
            })
    
    # Drupal detection
    drupal_paths = soup.find_all(attrs={"href": re.compile(r'sites/all/modules|drupal.js')})
    if drupal_paths:
        software_versions.append({
            'software': 'Drupal',
            'version': 'Detected (version unknown)',
            'source': 'Resource paths'
        })
    
    # Joomla detection
    joomla_paths = soup.find_all(attrs={"href": re.compile(r'media/jui|media/system')})
    if joomla_paths:
        software_versions.append({
            'software': 'Joomla',
            'version': 'Detected (version unknown)',
            'source': 'Resource paths'
        })
    
    # JavaScript libraries
    js_libraries = {
        'jquery': r'jquery[.-](\d+\.\d+\.\d+)',
        'bootstrap': r'bootstrap[.-](\d+\.\d+\.\d+)',
        'angular': r'angular[.-](\d+\.\d+\.\d+)',
        'react': r'react[.-](\d+\.\d+\.\d+)'
    }
    
    scripts = soup.find_all('script', src=True)
    for script in scripts:
        src = script.get('src', '')
        for library, pattern in js_libraries.items():
            match = re.search(pattern, src)
            if match:
                software_versions.append({
                    'software': library.capitalize(),
                    'version': match.group(1),
                    'source': 'Script tag'
                })
    
    return software_versions

def scan_for_information_disclosure(html_content):
    sensitive_info = []
    
    # Check for comments that might contain sensitive information
    comments = re.findall(r'<!--(.*?)-->', html_content, re.DOTALL)
    for comment in comments:
        if any(keyword in comment.lower() for keyword in ['todo', 'fixme', 'password', 'admin', 'user', 'key', 'secret', 'config']):
            sensitive_info.append({
                'type': 'HTML Comment',
                'content': comment[:100] + ('...' if len(comment) > 100 else ''),
                'issue': 'Potentially sensitive information in HTML comment'
            })
    
    # Check for hardcoded API keys, tokens, etc.
    potential_keys = re.findall(r'[\'"`](api[_-]?key|token|secret|password|apikey|access[_-]?key)[\'"`]\s*[:=]\s*[\'"`]([a-zA-Z0-9]{16,})[\'"`]', html_content, re.IGNORECASE)
    for key_match in potential_keys:
        sensitive_info.append({
            'type': 'API Key/Token',
            'key_type': key_match[0],
            'issue': f'Potential hardcoded {key_match[0]} detected'
        })
    
    return sensitive_info

def check_ssl_tls_configuration(url):
    if not url.startswith('https://'):
        return {'issue': 'Not using HTTPS', 'severity': 'High'}
    
    # require additional libraries like 'cryptography' and 'OpenSSL'
    # For a complete implementation, we'd need more advanced SSL/TLS testing
    return {'status': 'HTTPS enabled - for detailed SSL/TLS analysis, use specialized tools like SSLyze/TestSSL'}

def perform_security_scan(url, html_content, headers):
    results = {
        'url': url,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'vulnerabilities': {
            'xss': scan_for_xss(url, html_content, headers),
            'sql_injection': scan_for_sql_injection(url, html_content, headers),
            'information_disclosure': scan_for_information_disclosure(html_content),
            'software_versions': check_outdated_software(html_content, headers),
            'https_check': check_ssl_tls_configuration(url)
        }
    }
    
    # Count total vulnerabilities
    total_vulns = sum(len(results['vulnerabilities'][key]) 
                      for key in ['xss', 'sql_injection', 'information_disclosure', 'software_versions'] 
                      if isinstance(results['vulnerabilities'][key], list))
    
    results['total_vulnerabilities'] = total_vulns
    return results

def generate_user_agents(num_agents=10):
    """Generate random modern browser User-Agents"""
    browsers = {
        'chrome': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.{}.{} Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.{}.{} Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.{}.{} Safari/537.36'
        ],
        'firefox': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{}.0) Gecko/20100101 Firefox/{}.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{}.0) Gecko/20100101 Firefox/{}.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:{}.0) Gecko/20100101 Firefox/{}.0'
        ],
        'edge': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.{}.{} Safari/537.36 Edg/{}.0.{}.{}'
        ]
    }
    
    user_agents = []
    for _ in range(num_agents):
        browser = random.choice(list(browsers.keys()))
        template = random.choice(browsers[browser])
        
        if browser == 'chrome':
            major = random.randint(90, 120)  # Recent Chrome versions
            minor = random.randint(0, 9999)
            patch = random.randint(0, 999)
            user_agents.append(template.format(major, minor, patch))
        elif browser == 'firefox':
            version = random.randint(90, 120)  # Recent Firefox versions
            user_agents.append(template.format(version, version))
        elif browser == 'edge':
            major = random.randint(90, 120)
            minor = random.randint(0, 9999)
            patch = random.randint(0, 999)
            edge_major = random.randint(90, 120)
            edge_minor = random.randint(0, 9999)
            edge_patch = random.randint(0, 999)
            user_agents.append(template.format(major, minor, patch, edge_major, edge_minor, edge_patch))
    
    return list(set(user_agents))  # Remove any duplicates

def load_or_generate_user_agents():
    print(f"\n{GREEN}User-Agent Configuration:{RESET}")
    print("1. Load from UserAgent.txt")
    print("2. Generate random User-Agents")
    choice = input("Choose an option (1/2): ").strip()
    
    if choice == "1":
        try:
            with open("UserAgent.txt", "r") as file:
                user_agents = [line.strip() for line in file if line.strip()]
                if user_agents:
                    print(f"{GREEN}Successfully loaded {len(user_agents)} User-Agents from file{RESET}")
                    return user_agents
                else:
                    print(f"{YELLOW}UserAgent.txt is empty, falling back to generation...{RESET}")
        except FileNotFoundError:
            print(f"{YELLOW}UserAgent.txt not found, falling back to generation...{RESET}")
    elif choice == "2":
        num_agents = int(input("How many User-Agents to generate? (default 10): ") or 10)
        user_agents = generate_user_agents(num_agents)
        print(f"{GREEN}Generated {len(user_agents)} unique User-Agents{RESET}")
        
        # Option to save generated User-Agents
        save_choice = input("Would you like to save these User-Agents to UserAgent.txt? (y/n): ").strip().lower()
        if save_choice == 'y':
            try:
                with open("UserAgent.txt", "w") as file:
                    for ua in user_agents:
                        file.write(ua + "\n")
                print(f"{GREEN}User-Agents saved to UserAgent.txt{RESET}")
            except Exception as e:
                print(f"{RED}Error saving User-Agents to file: {e}{RESET}")
        
        return user_agents
    else:
        print(f"{YELLOW}Invalid choice, falling back to generation...{RESET}")
    
    # Default fallback
    user_agents = generate_user_agents(10)
    print(f"{GREEN}Generated {len(user_agents)} default User-Agents{RESET}")
    return user_agents

def format_proxy(proxy_string):
    """Format proxy string to proper URL format with authentication if present"""
    try:
        # Check if proxy contains authentication credentials
        if ':' in proxy_string:
            parts = proxy_string.split(':')
            if len(parts) == 4:  # Format: ip:port:username:password
                ip, port, username, password = parts
                return f"http://{username}:{password}@{ip}:{port}"
            elif len(parts) == 2:  # Format: ip:port
                return f"http://{proxy_string}"
        return f"http://{proxy_string}"
    except Exception as e:
        print(f"{RED}Error formatting proxy {proxy_string}: {e}{RESET}")
        return None

def load_proxies():
    try:
        with open("proxies.txt", "r") as file:
            proxies = []
            for line in file:
                proxy = line.strip()
                if proxy:
                    formatted_proxy = format_proxy(proxy)
                    if formatted_proxy:
                        proxies.append(formatted_proxy)
            
            if proxies:
                print(f"{GREEN}Loaded {len(proxies)} proxies{RESET}")
                return proxies
    except FileNotFoundError:
        print(f"{RED}proxies.txt not found. Falling back to direct connection.{RESET}")
    return []

def configure_driver():
    options = Options()
    options.headless = True
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--log-level=3")
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    return driver


def create_folder(base_path, folder_name):
    folder_path = os.path.join(base_path, folder_name)
    os.makedirs(folder_path, exist_ok=True)
    return folder_path

def display_security_scan_summary(scan_results):
    print(f"\n{GREEN}Security Scan Results for {scan_results['url']}:{RESET}")
    
    # XSS vulnerabilities
    xss_count = len(scan_results['vulnerabilities']['xss'])
    if xss_count > 0:
        print(f"{RED}XSS Vulnerabilities:{RESET} {xss_count} potential issue(s) found")
    else:
        print(f"{GREEN}XSS Vulnerabilities:{RESET} None detected")
    
    # SQL Injection vulnerabilities
    sql_count = len(scan_results['vulnerabilities']['sql_injection'])
    if sql_count > 0:
        print(f"{RED}SQL Injection Vulnerabilities:{RESET} {sql_count} potential issue(s) found")
    else:
        print(f"{GREEN}SQL Injection Vulnerabilities:{RESET} None detected")
    
    # Information disclosure
    info_count = len(scan_results['vulnerabilities']['information_disclosure'])
    if info_count > 0:
        print(f"{RED}Information Disclosure Issues:{RESET} {info_count} instance(s) found")
    else:
        print(f"{GREEN}Information Disclosure:{RESET} None detected")
    
    # Software versions
    software_count = len(scan_results['vulnerabilities']['software_versions'])
    if software_count > 0:
        print(f"{YELLOW}Software Detected:{RESET} {software_count} component(s) identified")
        for sw in scan_results['vulnerabilities']['software_versions']:
            print(f"  - {sw['software']}: {sw['version']}")
    else:
        print(f"{GREEN}Software Detection:{RESET} No software components identified")
    
    # HTTPS check
    https_result = scan_results['vulnerabilities']['https_check']
    if 'issue' in https_result:
        print(f"{RED}HTTPS Check:{RESET} {https_result['issue']}")
    else:
        print(f"{GREEN}HTTPS Check:{RESET} {https_result['status']}")
    
    print(f"\nDetailed results saved to JSON file.")

def save_file(url, folder, user_agent, proxy=None, timeout=10, perform_scan=True):
    try:
        headers = {"User-Agent": user_agent}
        proxies = {"http": proxy, "https": proxy} if proxy else None
        
        if proxy:
            display_proxy = proxy.split('@')[-1] if '@' in proxy else proxy
            print(f"{YELLOW}Using proxy {display_proxy} to scrape: {url}{RESET}")
        else:
            print(f"{YELLOW}Using direct connection to scrape: {url}{RESET}")
            
        response = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)

        if response.status_code == 200:
            parsed_url = urlparse(url)
            filename = os.path.basename(parsed_url.path) or "index.html"
            filepath = os.path.join(folder, filename)

            with open(filepath, "wb") as f:
                f.write(response.content)

            print(f"{GREEN}Successfully downloaded:{RESET} {filepath}")
            logging.info(f"Downloaded: {filepath}")
            
            # Perform security scanning if requested
            if perform_scan and filename.endswith(('.html', '.htm', '.php', '.asp', '.aspx', '.jsp')) or not os.path.splitext(filename)[1]:
                print(f"{YELLOW}Performing security scan for: {url}{RESET}")
                html_content = response.text
                scan_results = perform_security_scan(url, html_content, response.headers)
                
                # Save scan results
                scan_filepath = os.path.join(folder, f"{os.path.splitext(filename)[0]}_security_scan.json")
                with open(scan_filepath, "w") as f:
                    json.dump(scan_results, f, indent=4)
                
                # Display summary
                display_security_scan_summary(scan_results)
            
            return True
        else:
            print(f"{RED}Failed to download:{RESET} {url} (Status Code: {response.status_code})")
            logging.error(f"Failed to download {url} (Status Code: {response.status_code})")
            return False
    except requests.Timeout:
        print(f"{RED}Proxy {proxy} timed out while scraping: {url}{RESET}")
        logging.error(f"Proxy timeout: {proxy}")
        return False
    except Exception as e:
        print(f"{RED}Error downloading {url}: {e}{RESET}")
        logging.error(f"Error downloading {url}: {e}")
        return False


def try_with_proxies(url, folder, user_agent, proxies, max_attempts=5, perform_scan=True):
    if not proxies:
        return save_file(url, folder, user_agent, perform_scan=perform_scan)
        
    attempts = 0
    tried_proxies = set()
    
    while attempts < max_attempts and len(tried_proxies) < len(proxies):
        proxy = random.choice([p for p in proxies if p not in tried_proxies])
        tried_proxies.add(proxy)
        
        if save_file(url, folder, user_agent, proxy, perform_scan=perform_scan):
            return True
        attempts += 1
        if attempts < max_attempts and len(tried_proxies) < len(proxies):
            print(f"{YELLOW}Switching to different proxy...{RESET}")
    
    if attempts == max_attempts:
        print(f"{YELLOW}Max proxy attempts reached, trying without proxy...{RESET}")
        return save_file(url, folder, user_agent, perform_scan=perform_scan)
    return False

def extract_assets(driver, url, folder, depth, visited, user_agents, proxies):
    if url in visited or depth < 0:
        return
    visited.add(url)

    print(f"\n{YELLOW}Scraping:{RESET} {url}")
    logging.info(f"Scraping: {url}")

    driver.get(url)
    time.sleep(2)
    soup = BeautifulSoup(driver.page_source, "html.parser")

    # Save main HTML
    user_agent = random.choice(user_agents)
    try_with_proxies(url, folder, user_agent, proxies)

    asset_types = {
        "css": [link.get("href") for link in soup.find_all("link", href=True) if ".css" in link.get("href")],
        "js": [script.get("src") for script in soup.find_all("script", src=True)],
        "images": [img.get("src") for img in soup.find_all("img", src=True)],
        "videos": [video.get("src") for video in soup.find_all("video", src=True)],
        "audios": [audio.get("src") for audio in soup.find_all("audio", src=True)],
        "fonts": [font.get("href") for font in soup.find_all("link", href=True) if "font" in font.get("href")]
    }

    # Download assets
    for asset_type, urls in asset_types.items():
        if urls:
            print(f"\n{GREEN}Processing {len(urls)} {asset_type} files...{RESET}")
            asset_folder = create_folder(folder, asset_type)

            for asset_url in urls:
                full_url = urljoin(url, asset_url)
                try_with_proxies(full_url, asset_folder, user_agent, proxies)

    # Recursively scrape links
    links = [a.get("href") for a in soup.find_all("a", href=True)]
    if links:
        print(f"\n{GREEN}Found {len(links)} links to process...{RESET}")
        for link in links:
            full_url = urljoin(url, link)
            if urlparse(full_url).netloc == urlparse(url).netloc:
                extract_assets(driver, full_url, folder, depth - 1, visited, user_agents, proxies)

def single_security_scan():
    print(f"\n{GREEN}Security Scanner - Single URL{RESET}")
    url = input("Enter the URL to scan: ").strip()
    
    user_agents = load_or_generate_user_agents()
    user_agent = random.choice(user_agents)
    
    proxies = load_proxies()
    proxy = random.choice(proxies) if proxies else None
    
    output_folder = create_folder("security_scans", "single_scans")
    
    print(f"\n{YELLOW}Starting security scan for: {url}{RESET}")
    try_with_proxies(url, output_folder, user_agent, proxies if proxies else [], perform_scan=True)
    print(f"\n{GREEN}Scan completed! Results saved in: {output_folder}{RESET}")

def batch_security_scan():
    print(f"\n{GREEN}Security Scanner - Batch Mode{RESET}")
    file_path = input("Enter the path to file containing URLs (one per line): ").strip()
    
    try:
        with open(file_path, "r") as file:
            urls = [line.strip() for line in file if line.strip()]
            
        if not urls:
            print(f"{RED}No valid URLs found in the file.{RESET}")
            return
            
        print(f"{GREEN}Found {len(urls)} URLs to scan.{RESET}")
        max_workers = int(input(f"Enter number of parallel scans (recommended 5-10): ") or 5)
        
        user_agents = load_or_generate_user_agents()
        proxies = load_proxies()
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_folder = create_folder("security_scans", f"batch_scan_{timestamp}")
        
        def scan_url(url):
            try:
                user_agent = random.choice(user_agents)
                url_folder = create_folder(output_folder, hashlib.md5(url.encode()).hexdigest()[:10])
                return try_with_proxies(url, url_folder, user_agent, proxies if proxies else [], perform_scan=True)
            except Exception as e:
                print(f"{RED}Error scanning {url}: {e}{RESET}")
                return False
        
        print(f"\n{YELLOW}Starting batch scan of {len(urls)} URLs with {max_workers} workers...{RESET}")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(scan_url, urls))
        
        success_count = sum(1 for r in results if r)
        print(f"\n{GREEN}Batch scan completed! {success_count}/{len(urls)} successful scans.{RESET}")
        print(f"{GREEN}Results saved in: {output_folder}{RESET}")
        
    except FileNotFoundError:
        print(f"{RED}File not found: {file_path}{RESET}")
    except Exception as e:
        print(f"{RED}Error during batch scan: {e}{RESET}")

def scrape_website():
    print(f"\n{GREEN}Loading configurations...{RESET}")
    user_agents = load_or_generate_user_agents()
    proxies = load_proxies()
    
    # Display configuration summary
    print(f"\n{GREEN}Configuration Summary:{RESET}")
    print(f"User-Agents: {len(user_agents)} available")
    print(f"Proxies: {len(proxies)} available")
    
    print(f"\n{GREEN}Please enter the following details:{RESET}")
    url = input("Enter the URL to scrape: ").strip()
    folder_name = input("Enter the folder name to save the website: ").strip()
    depth = int(input("Enter the depth for recursive crawling (0 for single page): "))

    base_folder = create_folder("scraped_sites", folder_name)
    print(f"\n{GREEN}Initializing Chrome driver...{RESET}")
    driver = configure_driver()

    try:
        visited = set()
        extract_assets(driver, url, base_folder, depth, visited, user_agents, proxies)
    except Exception as e:
        print(f"{RED}Error during scraping: {e}{RESET}")
        logging.error(f"Error during scraping: {e}")
    finally:
        driver.quit()

    print(f"\n{GREEN}Scraping completed! Files saved in: {base_folder}{RESET}")


def main():
    show_ascii_art()

    while True:
        print("\n1. Start Scraping")
        print("2. Start Security Scan (Single URL)")
        print("3. Batch Security Scan (from file)")
        print("4. Quit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            scrape_website()
        elif choice == "2":
            single_security_scan()
        elif choice == "3":
            batch_security_scan()
        elif choice == "4":
            print(f"{RED}Exiting... Goodbye!{RESET}")
            break
        else:
            print(f"{RED}Invalid choice. Please try again.{RESET}")


if __name__ == "__main__":
    main()
