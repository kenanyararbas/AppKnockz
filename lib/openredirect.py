import asyncio
import urllib
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen
from urllib.error import HTTPError, URLError
from .logger import *

import aiohttp
import validators

""" You should suppLy an url like that test.com/file.php?redirc= in order to work that correctly"""


class openredirect:
    ''' Change the payloads according to your needs and please use a txt file :) '''

    payloads = ["//www.google.com/%2e%2e", "//example.com@google.com/%2f..",
                "///google.com/%2f..", "///example.com@google.com/%2f.."]

    def __init__(self, url, cookies=None, headers=None):
        self.url = url
        self.cookies = cookies if cookies is not None else ""
        self.headers = headers if headers is not None else {
            "User-Agent": "Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101"}

    def set_url(self, new_url):
        self.url = new_url

    def check_url(self,url):
        return validators.url(self.url)

    def contain_params(self,url):
        if self.check_url(url):
            parsed_url = urlparse(self.url)
            query = parsed_url.query
            parameters = parse_qs(query)
            if bool(parameters) is False and parameters is not None:
                return False
            else:
                return True

    def checker(self,url):
        try:
            response = urlopen(url)
        except HTTPError:
            return "not valid"
        except URLError as e:
            return "not valid"
        else:
            html = response.read()
            return "up"

    async def scan_url(self, payloads, session, url):
        if self.contain_params(url):
            parsed_url = urlparse(self.url)
            query = parsed_url.query
            parameters = parse_qs(query)

            for parameter in parameters:
                parameters[parameter] = parameters[parameter][0]

            for parameter in parameters:
                current_Value = parameters[parameter]
                for P in payloads:
                    parameters[parameter] = P
                    new_parts = list(parsed_url)
                    new_parts[4] = urllib.parse.urlencode(parameters)
                    build_url = urllib.parse.urlunparse(new_parts)
                try:
                    async with session.get(build_url) as resp:
                        header = resp.headers()
                        data = await resp.text(encoding="utf-8")

                    if "Location" in header and urllib.unquote(P).decode('utf8') in header['Location']:
                        return f'May be Vulnerable : {self.url} to this payload : {P}'
                    print(build_url)

                    parameters[parameter] = current_Value

                except (aiohttp.InvalidURL, TypeError, AttributeError, aiohttp.ClientConnectionError):
                    header = "Error"


    async def main(self, crawler):
        async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
            tasks = []
            for url in crawler.urls:
                self.set_url(new_url=url)
                task = asyncio.ensure_future(self.scan_url(payloads=openredirect.payloads, session=session, url=url))
                tasks.append(task)
            responses = await asyncio.gather(*tasks)
        return responses

    def run_oredirect(self,crawler):
        result = asyncio.run(self.main(crawler))
        for i in result:
            if i is not None:
                add_notification(i.replace("\n", ""), type="warning")


