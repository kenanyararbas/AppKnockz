
import argparse
from lib.crawler import *
from lib.xsscan import xss_scanner
from lib.forms import *
from lib.sqlscanner import sql
#from lib.CommandInjection import *
from lib.LFI import *
from lib.headerinjection import *
from lib.CSRF import *

# Arguments and argument Parsers
parser = argparse.ArgumentParser(description="DAST Analysis tools -h for help")
parser.add_argument('-u', '--url', type=str, required=True)
parser.add_argument('-c', '--cookie', type=str)
parser.add_argument('-ht' '--httpheader', type=str)
parsed_args = parser.parse_args()
current_protocols = ["http://", "https://"]

# Global Variables


def get_all_element(url, element_type):
    """Given a `url`, it returns an instance based on the element type from the HTML content"""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all(element_type.lower())


def get_headers(url):
    """Given a 'url' it returns the http headers"""
    return requests.get(url).headers


def get_cookies(url):
    """Given a 'url' it returns the cookies"""
    session = requests.session()
    cookies = session.get(url).cookies
    cookie_dict = cookies.get_dict()
    print(cookie_dict)

def store_forms(crawler_urls):
    page_forms = []
    for url in crawler_urls:
        page_forms.extend(forms.get_forms(url=url))
    return page_forms


if __name__ == '__main__':
    crawler.scrape("http://testphp.vulnweb.com/index.php")
    scanner = xss_scanner(url=crawler.urls[0], cookies={"login": "test/test"})
    scan_sql = sql(url=crawler.urls[0], cookies={"login": "test/test"})
    scan_lfi = LFI(url=crawler.urls[0], cookies={"login": "test/test"})
    scan_header = headerinjection(url=crawler.urls[0], redirect="www.example.com")
    scan_csrf = CSRF(url=crawler.urls[0], cookies={"login":"test/test"})
    print("Starting XSS Test")
    for url in crawler.urls:
        scanner.main()
        scanner.set_url(url)
    print("Starting SQLi Test")
    for url in crawler.urls:
        scan_sql.main()
        scan_sql.set_url(url)
    print("Starting LFI Test")
    for url in crawler.urls:
        scan_lfi.main()
        scan_lfi.set_url(url)
    print("Starting Header Injection Test")
    for url in crawler.urls:
        scan_header.main()
        scan_header.set_url(url)
    print("Starting CSRF Recon")
    for url in crawler.urls:
        scan_csrf.main()
        scan_csrf.set_url(url)





