import asyncio
import aiohttp
from urllib.parse import parse_qs, urlparse, urljoin
import validators
from .crawler import *

class dirf:
    mutated_urls = []
    def __init__(self, crawler, dirs, behaviours , cookies=None , isRecursive=False):
        # Crawler is URL's without query parameters (Only paths) and dirs are
        # The places that the scripts looks for
        # Behaviours are the status codes which is returned default by the system if the path is not exists
        self.crawler = crawler
        self.dirs = dirs
        self.behaviours = behaviours
        self.cookies = cookies

    def set_Recursive(self):
        self.isRecursive = not self.isRecursive

    def check_status(self, status_code):
        if status_code == 200 or (300 < status_code < 400):
            return True
        elif status_code == 403:
            print("403 Forbidden detected recommend to bypass the restriction with url bypasses")
            return False

    def has_parameters(self,url):
        if validators.url(url):
            parsed_url = urlparse(url)
            parameters = parse_qs(parsed_url.query)
            if bool(parameters) is False and parameters is not None:
                return False
            else:
                return True

    def mutator(self):
        url = crawler.urls[0]
        schema = urlparse(url)
        #queries = parse_qs(schema.query)
        method = schema.scheme
        netloc = schema.netloc
        for dir in self.dirs:
            build_url = method + "://" + netloc + "/" + dir
            dirf.mutated_urls.append(build_url)

    async def make_Requests(self, session, url):
        try:
            async with session.get(url) as data:
                status_code = data.status
                #response = await data.read()
            return {"url":url, "status_code":status_code}
        except aiohttp.ClientConnectionError:
            pass

    async def async_requests(self):
        async with aiohttp.ClientSession(cookies=self.cookies) as session:
            tasks = []
            for url in self.mutated_urls:
                task = self.make_Requests(session=session, url=url)
                tasks.append(task)
            response = await asyncio.gather(*tasks)
        return response

    def check_stats(self, response):
        for each_Response in response:
            if self.check_status(each_Response['status_code']):
                print("Sensitive endpoint found at {}".format(each_Response['url']))

    def main(self, crawler):
        self.mutator()
        response = asyncio.run(self.async_requests())
        self.check_stats(response)




if __name__ == '__main__':
    dirfinder = dirf(crawler=crawler.urls, dirs=[".idea", ".htaccess", ".git" , "CVS" , "_mmServerScripts"], behaviours=[])
    dirfinder.main()