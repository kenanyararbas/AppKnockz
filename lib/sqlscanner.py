import time
import Blinder
from .forms import *
from .crawler import *


class sql:
    payloads = ["'", '#', "' FOO"]
    value_terminators = ["'", "%00", "; SELECT NULL"]
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

    async def fuzz_url(self, url, async_session):
        if self.url not in sql.vulns:
            if url != "":
                url_scheme = self.identify_url()
                for term in sql.value_terminators:
                    link = url_scheme.scheme + "://" + url_scheme.netloc \
                           + url_scheme.path + "?" + url_scheme.query + term

                    try:
                        async with async_session.get(link) as resp:
                            context = await resp.text(encoding="utf-8")
                    except:
                        context = None

                    if context is not None:
                        content = bs(context, "html.parser")
                        vulnerability = is_vulnerable(content)
                        if vulnerability and self.url not in sql.vulns:
                            sql.vulns.append(self.url)
                            return f'SQL injection found at {self.url}'
                        elif not vulnerability and self.url not in sql.vulns:
                            self.crawled_urls.append(self.url)
                    else:
                        return f'Bad url provided {self.url}'

    async def async_fuzz_url(self):
        async with aiohttp.ClientSession(cookies=self.cookies) as s:
            tasks = []
            for url in crawler.urls:
                self.set_url(new_url=url)
                task = asyncio.ensure_future(self.fuzz_url(async_session=s, url=self.url))
                tasks.append(task)
                result = await asyncio.gather(*tasks)
            return result

    def fuzz_Forms(self, form_list):
        response = asyncio.run(forms.async_submit(formlist=form_list, payloads=sql.payloads, cookies=self.cookies))
        for each_response in response:
            vulnerability = is_vulnerable(each_response[0]['content'], type="str")
            if vulnerability and each_response[0]['url'] not in sql.vulns:
                print(f'SQL vulnerability found in a form instance on {each_response[0]["url"]}')

    def main(self, form_list):
        vuln_at_link = asyncio.run(self.async_fuzz_url())
        for each_link in vuln_at_link:
            if each_link is not None:
                print(each_link)
        print("Fuzzing forms for finding further vulnerable points ....")
        self.fuzz_Forms(form_list=form_list)
        for each_link in self.crawled_urls:
            is_blind(each_link)


def is_vulnerable(response, type="bs"):
    errors = [
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    ]
    if type == "str":
        decoded_object = response
    else:
        decoded_object = response.decode()
    for error in errors:
        if decoded_object.lower().find(error.lower()) > -1:
            return True
    return False


def is_blind(url):
    blindCheck = Blinder.blinder(url, sleep=2)
    if blindCheck.check_injection():
        print("Blind SQL Injection at {}".format(url))


