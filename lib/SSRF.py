import re
import urllib.parse
import aiohttp
from .headerinjection import *
from urllib.parse import parse_qs,urlparse,urlunparse
from .forms import *
from .crawler import *

C_headers = {  # default headers
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip,deflate',
    'Connection': 'close',
    'DNT': '1',
    'Upgrade-Insecure-Requests': '1',
}

ssrf_Regex = "^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$"


class SSRF:

    def __init__(self, url, headers=C_headers, cookies=None , external_urls=None):
        self.url = url
        self.cookies = cookies
        self.headers = headers
        self.external_urls = external_urls

    def set_url(self, new_url):
        self.url = new_url

    def check_url(self):
        """ Checks if url contains a webpage or an ip address if so returns a boolean value to indicate that """
        isContain = False
        scheme = urlparse(self.url)
        queries = parse_qs(scheme.query)
        #data formatting
        for query in queries:
            queries[query] = queries[query][0]
        for query in queries:
            if re.match(ssrf_Regex, queries[query]):
                isContain = True
                print("External host passed through url parameter at {} with {} parameter and {} value"
                      .format(self.url, query, queries[query]))
        return isContain

    def check_forms(self,formlist):
        """ Checks if the webpage containt a form with a data field which is used to interact with external dom.
        if so return a boolean value to indicate that"""
        isInteract = False
        for each_req in formlist:
            for each_form in each_req:
                input_list = each_form['inputs']
                for each_input in input_list:
                    if each_input['value'] is not None:
                        if re.match(ssrf_Regex, each_input['value']):
                            print("External host passed through a form field at {} with a formfield like {}".format(self.url, input_list[each_input]))
                            isInteract = True
        return isInteract


    # Type can be url or form.Depend on that we adjust the request type
    async def make_request(self, external_urls,session , url):
        scheme = urlparse(url)
        queries = parse_qs(scheme.query)
        # data formatting
        for query in queries:
            queries[query] = queries[query][0]
        for query in queries:
            current_value = queries[query]
            for url in external_urls:
                queries[query] = url
                new_values = list(scheme)
                new_values[4] = urllib.parse.urlencode(queries)
                build_url = urllib.parse.urlunparse(new_values)
                try:
                    async with session.get(build_url) as data:
                        status = data.status
                except aiohttp.ClientConnectionError:
                    pass
                if status == 200:
                    print(f'Parameters fuzzed. Please check your external'
                          f' domain in order to obtain the response : {url}')
            queries[query] = current_value

    async def scan_SSRF(self,formlist):
        headers_check = headerinjection(url=self.url, redirect="example.com",
                                        cookies=self.cookies)
        if headers_check.inject():
            print("Header Inhection found at {} trying for SSRF ...".format(self.url))
        if self.check_url() or self.check_forms(formlist):
            print("IP or Hostname is passed through a parameter at {} sending request to your webserver..".format(self.url))
            async with aiohttp.ClientSession as session:
                tasks = []
                for url in crawler.urls:
                    task = asyncio.ensure_future(self.make_request(external_urls=["http://www.example.com"], session=session, url=url))
                    tasks.append(task)
                response = asyncio.gather(*tasks)
            for i in response:
                if i is not None:
                    print(i)

    def main(self,formlist):
        asyncio.run(self.scan_SSRF(formlist))



