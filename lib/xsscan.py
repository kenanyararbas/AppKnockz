from urllib.parse import urlparse
from bs4 import BeautifulSoup as bs

string_terminators = []
payloads = open("payloads.txt", 'r')


class xss_scanner:

    def __init__(self, url, exploits):
        self.url = url
        self.exploits = exploits

    def start_scan(self):
        content = bs(self.body, "html.parser")
        forms = content.find_all("form", method=True)
        for form in forms:
            try:
                action = form["action"]
            except KeyError:
                action = self.url
            if form["method"].lower() == "post":
                pass


    def set_url(self, url):
        pass

    def parse_url(self):
        return urlparse(self.url)

    def start_test(self):
        pass


if __name__ == '__main__':
    print("This is code injection page")
