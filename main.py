import requests
import argparse
import sys
import asyncio
import pprint
from bs4 import BeautifulSoup as bs
from lib.crawler import *
from lib.xsscan import *
from lib.httpassist import httpassist

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


if __name__ == '__main__':
    #crawler.scrape(parsed_args.url)
    payload = "test payload"
    data = httpassist.post_method(url="http://testphp.vulnweb.com/index.php", payloads=payload, headers="")
    scanner = xss_scanner(response=data['context'], url="http://testphp.vulnweb.com/index.php")
    scanner.start_scan()


