import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import sys

# --- CONFIGURATION ---
# In a real tool, use argparse for CLI arguments
TARGET_URL = "http://testphp.vulnweb.com"  # A safe testing ground provided by Acunetix
LINKS_TO_VISIT = []

class Scanner:
    def __init__(self, url, ignore_links=None):
        self.target_url = url
        self.target_links = []
        self.ignore_links = ignore_links or []
        self.session = requests.Session()

    def extract_links_from(self, url):
        """Crawls a URL and returns all href links found on the page."""
        response = self.session.get(url)
        return re.findall('(?:href=")(.*?)"', response.content.decode(errors="ignore"))

    def crawl(self, url=None):
        """Recursive crawler to find all sub-pages."""
        if url is None:
            url = self.target_url
            
        try:
            response = self.session.get(url)
        except requests.exceptions.ConnectionError:
            return

        soup = BeautifulSoup(response.content, "html.parser")
        
        # Find all links
        href_links = soup.find_all("a", href=True)
        
        for link in href_links:
            href = link.get("href")
            full_url = urljoin(url, href)

            # Only crawl internal links and avoid duplicates
            if self.target_url in full_url and full_url not in self.target_links:
                self.target_links.append(full_url)
                print(f"[+] Discovered link: {full_url}")
                self.crawl(full_url)

    def extract_forms(self, url):
        """Parses HTML to find all forms and their input fields."""
        try:
            response = self.session.get(url)
        except:
            return []
            
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")

    def submit_form(self, form, value, url):
        """Submits a form with a specific payload (value)."""
        action = form.get("action")
        post_url = urljoin(url, action)
        method = form.get("method")

        inputs_list = form.find_all("input")
        post_data = {}
        
        for input_tag in inputs_list:
            input_name = input_tag.get("name")
            input_type = input_tag.get("type")
            input_value = input_tag.get("value")
            
            if input_type == "text":
                input_value = value  # Inject payload here
            
            post_data[input_name] = input_value
        
        if method == "post":
            return self.session.post(post_url, data=post_data)
        return self.session.get(post_url, params=post_data)

    def run_scanner(self):
        """Main logic to crawl and then test every form found."""
        print(f"[*] Starting crawl on {self.target_url}...")
        self.crawl()
        
        print(f"\n[*] Found {len(self.target_links)} pages. Starting vulnerability scan...\n")
        
        for link in self.target_links:
            forms = self.extract_forms(link)
            for form in forms:
                print(f"[*] Testing form in {link}")
                
                # 1. Test for XSS
                is_xss_vulnerable = self.test_xss_in_form(form, link)
                if is_xss_vulnerable:
                    print(f"\n[!!!] XSS Discovered in {link}")
                    print(f"[*] Form Details: {form}\n")
                
                # 2. Test for SQL Injection
                is_sqli_vulnerable = self.test_sqli_in_form(form, link)
                if is_sqli_vulnerable:
                    print(f"\n[!!!] SQL Injection Discovered in {link}")
                    print(f"[*] Form Details: {form}\n")

    def test_xss_in_form(self, form, url):
        """Tests a form for Cross-Site Scripting (XSS)."""
        xss_payload = "<script>alert('XSS')</script>"
        response = self.submit_form(form, xss_payload, url)
        # If the payload comes back in the response text, it's likely vulnerable
        return xss_payload in response.content.decode(errors="ignore")

    def test_sqli_in_form(self, form, url):
        """Tests a form for SQL Injection."""
        sqli_payload = "'"
        response = self.submit_form(form, sqli_payload, url)
        
        # Common database errors to look for
        errors = {
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated"
        }
        
        for error in errors:
            if error in response.content.decode(errors="ignore").lower():
                return True
        return False

if __name__ == "__main__":
    # WARNING: Only scan websites you own or have permission to test.
    # 'testphp.vulnweb.com' is a safe playground.
    target_url = "http://testphp.vulnweb.com" 
    
    scanner = Scanner(target_url)
    scanner.run_scanner()