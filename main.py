import argparse
from lib.xsscan import xss_scanner
from lib.sqlscanner import sql
from lib.CommandInjection import *
from lib.LFI import *
from lib.SSRF import *
from lib.CSRF import *
import json
from lib.dirf import *
from lib.logger import *

# Arguments and argument Parsers
parser = argparse.ArgumentParser(description="DAST Analysis tools -h for help")
parser.add_argument('-u', '--url', type=str, required=True)
parser.add_argument('-c', '--cookie', type=json.loads)
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


if __name__ == '__main__':
    print_banner()
    print("AppKnockz : Crawling the target website")
    start = time.time()
    crawler.scrape(site="http://testphp.vulnweb.com/index.php", cookie={"login": "test%2Ftest"})
    end = time.time()
    print("AppKnockz : Crawling finished in {} seconds".format(end-start))

    """ initialization """
    xss = xss_scanner(url=crawler.urls[0], cookies=parsed_args.cookie, crawler=crawler.urls)
    sqli = sql(url=crawler.urls[0], cookies=parsed_args.cookie)
    cinj = CommandInjection(url=crawler.urls[0], cookies=parsed_args.cookie)
    csrf = CSRF(url=crawler.urls[0], cookies=parsed_args.cookie)
    local_file = LFI(url=crawler.urls[0], cookies=parsed_args.cookie)
    SSRF_scanner = SSRF(url=crawler.urls[0], cookies=parsed_args.cookie)
    dirfinder = dirf(crawler=crawler.urls, behaviours=[])
    form_list = asyncio.run(forms.async_get_forms(crawler=crawler.urls, cookies=parsed_args.cookie))

    """ initizalization end """
    dirfinder.main(crawler=crawler)
    sqli.main(form_list=form_list)
    xss.run_xss(form_list=form_list)
    local_file.main()
    cinj.main()
    csrf.main(form_list=form_list)
    SSRF_scanner.main(formlist=form_list)







