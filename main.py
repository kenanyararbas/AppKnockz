from urllib.parse import urlparse
import requests
import argparse
import sys
import asyncio
import pprint
from bs4 import BeautifulSoup as bs

# Arguments and argument Parsers
parser = argparse.ArgumentParser(description="DAST Analysis tools -h for help")
parser.add_argument('-u', '--url', type=str, required=True)
parser.add_argument('-c', '--cookie', type=str)
parser.add_argument('-ht' '--httpheader', type=str)
parsed_args = parser.parse_args()
current_protocols = ["http://", "https://"]

# Global Variables
urls = []


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


""" Crawl (Spidering) the website recursively will be used with parameter existence in terms of sqli and other code
    injections
"""


def scrape(site):
    # getting the request from url
    r = requests.get(site)

    # converting the text
    s = bs(r.text, "html.parser")

    for i in s.find_all("a"):

        href = i.attrs['href']

        if href.startswith("/"):
            site = site + href

        else:
            site = (str(urlparse(site).scheme + "://" + urlparse(site).netloc) + "/" + href)
            print(site)

            if site not in urls:
                urls.append(site)
                print(site)
                # calling it self
                scrape(site)


if __name__ == '__main__':
    scrape(parsed_args.url)
