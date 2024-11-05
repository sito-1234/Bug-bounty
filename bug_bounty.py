import asyncio  # Supports asynchronous programming
import aiohttp  # Handles asynchronous HTTP requests
import json  # Handles JSON data
import os  # Interacts with the operating system
from bs4 import BeautifulSoup  # Parses HTML content
from selenium import webdriver  # Controls the browser for screenshot
from selenium.webdriver.chrome.options import Options  # Sets options for Chrome

# Define maximum rate of 10 requests per second
MAX_REQUESTS_PER_SECOND = 10
# Set the path to save JSON report and screenshots
REPORT_PATH = "scan_report.json"
SCREENSHOTS_PATH = "screenshots"  # Directory to save screenshots
# Path to payloads on GitHub or locally
PAYLOAD_PATH = "path/to/your/github/payloads"  # Update with actual path

# Custom user agent and headers
username = "<username>"  # Replace with your actual username
USER_AGENT = f"Intigriti-{username}-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
HEADERS = {
    "User-Agent": USER_AGENT,
    "X-Bug-Bounty": f"Intigriti-{sitohacker}"
}

# Ensure screenshot directory exists
if not os.path.exists(SCREENSHOTS_PATH):
    os.makedirs(SCREENSHOTS_PATH)

# Load payloads function
def load_payloads():
    payloads = {
        "SQL Injection": [],
        "NoSQL Injection": [],
        "SSRF": []
    }
    try:
        # Load payloads from text files
        for vuln_type in payloads.keys():
            with open(os.path.join(PAYLOAD_PATH, f"{vuln_type}_payloads.txt"), 'r') as file:
                payloads[vuln_type] = [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"Error loading payloads: {e}")
    return payloads

# Define vulnerability checking functions
def check_sql_injection(response_text):
    sql_errors = ["syntax error", "SQL syntax", "mysql_fetch"]
    return any(error in response_text for error in sql_errors)

def check_nosql_injection(response_text):
    nosql_errors = ["MongoDB", "CouchDB", "noSQL syntax"]
    return any(error in response_text for error in nosql_errors)

def check_ssrf(response_text):
    ssrf_indicators = ["127.0.0.1", "localhost", "169.254.169.254"]
    return any(indicator in response_text for indicator in ssrf_indicators)

# Function to take a screenshot using Selenium
def take_screenshot(url, screenshot_path):
    # Set up Chrome options for headless mode
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")

    # Initialize WebDriver
    driver = webdriver.Chrome(options=chrome_options)
    driver.get(url)  # Load the URL in headless browser
    driver.save_screenshot(screenshot_path)  # Save screenshot to specified path
    driver.quit()  # Close the browser

# Report generation function
def generate_report(domain, findings):
    report_data = {"domain": domain, "vulnerabilities": findings}
    with open(REPORT_PATH, "w") as f:
        json.dump(report_data, f, indent=4)
    print(f"Report saved as {REPORT_PATH}")

# Asynchronous vulnerability scanning function
async def scan_vulnerabilities(domain, payloads):
    findings = []

    async with aiohttp.ClientSession() as session:
        for vuln_type, vuln_payloads in payloads.items():
            for payload in vuln_payloads:
                url = f"http://{domain}"

                # Rate limiting
                await asyncio.sleep(1 / MAX_REQUESTS_PER_SECOND)

                try:
                    # Send GET request with payload as parameter and include custom headers
                    async with session.get(url, params={'q': payload}, headers=HEADERS) as response:

                        response_text = await response.text()

                        # Initialize variables to track vulnerability status and screenshot file
                        vulnerability_found = False
                        screenshot_file = ""

                        # Check for SQL Injection vulnerability
                        if vuln_type == "SQL Injection" and check_sql_injection(response_text):
                            vulnerability_found = True
                            findings.append({
                                "type": "SQL Injection",
                                "url": response.url,
                                "payload": payload,
                                "http_request": str(response.request_info),
                                "http_response": response_text[:200]
                            })

                        # Check for NoSQL Injection vulnerability
                        elif vuln_type == "NoSQL Injection" and check_nosql_injection(response_text):
                            vulnerability_found = True
                            findings.append({
                                "type": "NoSQL Injection",
                                "url": response.url,
                                "payload": payload,
                                "http_request": str(response.request_info),
                                "http_response": response_text[:200]
                            })

                        # Check for SSRF vulnerability
                        elif vuln_type == "SSRF" and check_ssrf(response_text):
                            vulnerability_found = True
                            findings.append({
                                "type": "SSRF",
                                "url": response.url,
                                "payload": payload,
                                "http_request": str(response.request_info),
                                "http_response": response_text[:200]
                            })

                        # Take a screenshot if vulnerability was found
                        if vulnerability_found:
                            screenshot_file = os.path.join(SCREENSHOTS_PATH, f"{vuln_type}_{payload}.png")
                            take_screenshot(url, screenshot_file)  # Capture screenshot

                            # Update findings with the screenshot path
                            findings[-1]["screenshot"] = screenshot_file

                except Exception as e:
                    print(f"Error: {e}")

    # Generate report after scanning
    generate_report(domain, findings)

# Main function to start the scan
async def perform_full_scan(domain):
    payloads = load_payloads()  # Load payloads
    await scan_vulnerabilities(domain, payloads)  # Scan with loaded payloads

# Run the scanner
if __name__ == "__main__":
    try:
        domain = input("Enter the domain to scan: ")
        asyncio.run(perform_full_scan(domain))  # Start the scan
    except KeyboardInterrupt:
        print("\nScan interrupted.")
