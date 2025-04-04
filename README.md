<p align="center">
  <a href="#">
    <img src="https://img.shields.io/badge/ScorpionV3-GreenBugX-8A2BE2?style=for-the-badge&logo=insects&logoColor=white&labelColor=darkgreen&color=green&labelWidth=400&logoWidth=40" alt="Scrape!" style="transform: scale(1.5); margin: 10px 0;" />
  </a>
</p>

<p align="center">
  <a href="https://skillicons.dev">
    <img src="https://skillicons.dev/icons?i=git,py,vscode,selenium" />
  </a>
</p>

<p align="center">
  <a href="#">
    <img src="logo.png" width=200px/>
  </a>
</p>

# ScorpionV3

A powerful web scraping and security scanning tool designed for penetration testing and security analysis. This tool combines website scraping capabilities with vulnerability detection to help identify common security issues.

## Introduction

ScorpionV3 is a dual-purpose tool developed for security professionals, penetration testers, and web developers who need to analyze websites for both content and security vulnerabilities. It can crawl websites recursively, download assets, and scan for common security issues such as XSS vulnerabilities, SQL injection points, information disclosure, and outdated software.

This project was created to simplify the initial reconnaissance phase of security assessments and provide actionable insight into potential vulnerabilities.

## Features

- [x] Recursive website crawling
- [x] Asset extraction (CSS, JS, images, videos, etc.)
- [x] Proxy support
- [x] Random User-Agent rotation
- [x] Cross-Site Scripting (XSS) vulnerability detection
- [x] SQL Injection vulnerability detection
- [x] Information disclosure identification
- [x] Software version detection
- [x] HTTPS/SSL configuration checking
- [x] Security header analysis
- [x] Batch scanning of multiple URLs
- [x] Detailed vulnerability reporting
- [x] Customizable scan depth
- [ ] Authentication support
- [ ] Custom vulnerability rule definitions
- [ ] Export to PDF/HTML reports

## Installation

### Prerequisites

- Python 3.7+
- Chrome browser (for Selenium-based scraping)

### Step 1: Clone the repository

```bash
git clone https://github.com/greenbugx/ScorpionV3.git
cd WebScrapperv3
```

### Step 2: Create a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 3: Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure proxy list (optional)

Create a file named `proxies.txt` in the root directory and add your proxies (one per line) in the following format:
```
ip:port
ip:port:username:password
```

### Step 5: Configure User-Agents (optional)

Create a file named `UserAgent.txt` in the root directory and add your User-Agents (one per line).

## Usage

### Basic Usage

```bash
python main.py
```

### Main Menu Options

When you run the tool, you'll be presented with the following options:

1. **Start Scraping** - Scrape a website and save its assets
2. **Start Security Scan (Single URL)** - Perform a security scan on a single URL
3. **Batch Security Scan (from file)** - Scan multiple URLs from a list
4. **Quit** - Exit the program

### Scraping a Website

1. Select option 1 from the main menu
2. Enter the URL to scrape
3. Provide a folder name to save the scraped content
4. Specify the crawling depth (0 for single page, 1+ for recursive crawling)

### Single Security Scan

1. Select option 2 from the main menu
2. Enter the URL to scan
3. The tool will scan the URL and save results to the `security_scans/single_scans` directory

### Batch Security Scan

1. Create a text file with one URL per line
2. Select option 3 from the main menu
3. Enter the path to your URL list file
4. Specify the number of parallel scans to run
5. Results will be saved to the `security_scans/batch_scan_[timestamp]` directory

## Output

The tool generates the following outputs:

- **Scraped websites** - Saved in the `scraped_sites/[folder_name]` directory
- **Security scan results** - Saved as JSON files in the `security_scans/` directory
- **Log file** - All activities are logged in `scraper.log`

## Warning and Disclaimer

⚠️ **LEGAL WARNING**

This tool is provided for educational and professional security assessment purposes only. Unauthorized scanning of websites may violate computer crime laws and other regulations.

### Important Guidelines:

1. **Always obtain explicit permission** before scanning any website you don't own.
2. **Respect robots.txt** and website terms of service.
3. **Do not use this tool** to cause harm, disruption, or unauthorized access to systems.
4. **Use responsible scanning practices** - avoid excessive requests that could cause denial of service.
5. **You are solely responsible** for how you use this tool and any consequences thereof.

### Recommendations:

- Test on your own websites or dedicated security testing environments
- Use public test sites specifically designed for security testing
- Consider setting up local vulnerable applications like OWASP WebGoat or DVWA for practice

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Acknowledgments

- This tool uses [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) for HTML parsing
- [Selenium](https://www.selenium.dev/) is used for browser automation