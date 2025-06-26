# BlueAura-Scanner
An asynchronous security scanner powered by Python and Playwright for fast, dynamic vulnerability analysis of modern web apps.
# Advanced Web Security Scanner

This is a powerful, asynchronous web security scanner written in Python. It uses Playwright to perform dynamic, browser-based crawling and analysis, allowing it to test modern web applications that rely heavily on JavaScript.

The scanner is modular and capable of detecting a range of vulnerabilities, including:
-   SQL Injection (Error-based and Time-based)
-   Cross-Site Scripting (XSS) (Reflected and DOM-based)
-   Server-Side Request Forgery (SSRF) via out-of-band detection
-   Insecure Direct Object References (IDOR)
-   Missing Security Headers
-   Open Redirects
-   Sensitive Directory/File Exposure

## Requirements

To run this scanner, you will need the following:

-   **Python 3.7+**
-   A Linux, macOS, or Windows operating system.
-   Access to a command-line terminal.
-   The Python libraries listed in `requirements.txt`.
-   Browser binaries managed by Playwright.

## Installation

Follow these steps to set up the scanner and its dependencies.

**1. Clone the Repository:**
First, get a copy of the project on your local machine.
```bash
git clone <your-repository-url>
cd <your-repository-directory>
```

**2. Install Python Libraries:**
Install all the necessary Python packages using pip and the `requirements.txt` file.
```bash
pip install -r requirements.txt
```

**3. Install Playwright Browsers (Crucial Step):**
This command downloads the browser binaries (like Chromium, Firefox, and WebKit) that Playwright needs to run. The `--with-deps` flag also installs necessary operating system dependencies on Linux.
```bash
python -m playwright install --with-deps
```

## Configuration

The scanner's behavior is controlled by two YAML files:

1.  **`config.yml`**: This is the main configuration file.
    -   `target_url`: **(Required)** The starting URL for the scan.
    -   `modules`: A list of scanner modules to run (e.g., `sqli`, `xss`, `headers`).
    -   `max_crawl_depth`: How many links deep the crawler should go.
    -   `max_crawl_urls`: The maximum number of unique pages to scan.
    -   `auth`: Optional section to configure automated login for scanning authenticated parts of a site.

2.  **`payloads.yml`**: This file contains the attack payloads and wordlists used by the scanner modules. You can easily add or modify payloads here without changing the Python code.

***Disclaimer:** You should only run this tool against websites for which you have explicit, written permission to perform security testing.*

## Usage

To start a scan, run the `advanced_scanner.py` script from your terminal, pointing it to your configuration and payload files.

```bash
python advanced_scanner.py --config config.yml --payloads payloads.yml
```

**Optional Arguments:**
-   `--output <filename>`: Specify a custom name for the output report file.
-   `--debug`: Run in debug mode, which shows more verbose logging and runs the browser in non-headless mode (with a visible UI).

Once the scan is complete, a detailed HTML report will be generated in the same directory (e.g., `scan_report_example.com.html`).
