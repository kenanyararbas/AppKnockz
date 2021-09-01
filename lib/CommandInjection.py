import urllib.parse
import aiohttp
import asyncio
from urllib.parse import parse_qs
import validators
from .crawler import *
import time


class CommandInjection:
    payloads = ["& ping -c 10 127.0.0.1 & ", "| ping -c 10 127.0.0.1"]
    possible_Responses = []
    test_String = "Appknockz"

    def __init__(self, url, cookies=None, headers=None, timeout=10):
        self.url = url
        self.cookies = cookies
        self.headers = headers
        self.timeout = timeout

    def set_url(self, new_url):
        self.url = new_url

    def check_url(self,url):
        return validators.url(url)

    def has_parameters(self, url):
        if self.check_url(url):
            parsed_url = urlparse(url)
            query = parsed_url.query
            parameters = parse_qs(query)
            if bool(parameters) is False and parameters is not None:
                return False
            else:
                return True
        else:
            print("Provided URL is not valid")
            exit(0)

    async def inject_url(self, async_session,url):
        if self.has_parameters(url):
            parsed_url = urlparse(url)
            parameters = parse_qs(parsed_url.query)
            # Data formatting
            for parameter in parameters:
                parameters[parameter] = parameters[parameter][0]

            for parameter in parameters:
                for P in CommandInjection.payloads:
                    current_value = parameters[parameter]
                    parameters[parameter] = P
                    new_values = list(parsed_url)
                    new_values[4] = urllib.parse.urlencode(parameters)
                    build_url = urllib.parse.urlunparse(new_values)

                    start = time.time()
                    async with async_session.get(build_url) as resp:
                        status_code = resp.status
                        data = await resp.text(encoding="utf-8")
                        end = time.time()
                        elapsed_time = end-start

                    if (status_code == 200 and CommandInjection.test_String in data) \
                            or elapsed_time >= self.timeout:
                        return f'There is code Injection at {url} triggered with {P} payload'
                parameters[parameter] = current_value

    async def async_inject_url(self, crawler):
        async with aiohttp.ClientSession(cookies=self.cookies) as sess:
            tasks = []
            for url in crawler.urls:
                task = asyncio.ensure_future(self.inject_url(sess,url=url))
                tasks.append(task)
            resp = await asyncio.gather(*tasks)
        return resp

    def main(self):
        response = asyncio.run(self.async_inject_url(crawler=crawler))
        for each_Response in response:
            if each_Response is not None:
                add_notification(notification=each_Response, type="critical")