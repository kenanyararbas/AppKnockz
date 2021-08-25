import Blinder
from .forms import *
from .crawler import *
from .logger import *


class sql:

    with open('payloads/sql.txt') as sql_payloads:
        value_terminators = sql_payloads.readlines()
    # Will used for blind injection later on
    crawled_urls = []
    vulns = []

    def __init__(self, url, cookies=None):
        self.url = url
        self.cookies = cookies


    def identify_url(self, url):
        url_scheme = urlparse(url)
        return url_scheme

    def set_url(self, new_url):
        self.url = new_url

    async def fuzz_url(self, url, async_session):
        if url not in sql.vulns:
            if url != "":
                url_scheme = self.identify_url(url)
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
                        if vulnerability and url not in sql.vulns:
                            sql.vulns.append(url)
                            return f'SQL injection found at {link}'
                        elif not vulnerability and url not in sql.vulns:
                            self.crawled_urls.append(url)
                    else:
                        return f'Bad url provided {url}'

    async def async_fuzz_url(self):
        async with aiohttp.ClientSession(cookies=self.cookies) as s:
            tasks = []
            for url in crawler.urls:
                task = asyncio.ensure_future(self.fuzz_url(async_session=s, url=url))
                tasks.append(task)
            result = await asyncio.gather(*tasks)
        return result

    def fuzz_Forms(self, form_list):
        response = asyncio.run(forms.async_submit(formlist=form_list, payloads=sql.value_terminators, cookies=self.cookies))
        for each_response in response:
            vulnerability = is_vulnerable(each_response[0]['content'], type="str")
            if vulnerability and each_response[0]['url'] not in sql.vulns:
                notify = f'SQL vulnerability found in a form instance on {each_response[0]["url"]}'
                add_notification(notification=notify, type="critical")

    def main(self, form_list):
        vuln_at_link = asyncio.run(self.async_fuzz_url())
        for each_link in vuln_at_link:
            if each_link is not None:
                add_notification(notification=each_link,type="critical")

        info = "###### Fuzzing forms for finding further vulnerable points .. #####"
        add_notification(notification=info, type="information")

        self.fuzz_Forms(form_list=form_list)

        info = "##### Form fuzzing completed ..  ######"
        add_notification(notification=info , type="information")

        info = "#####  Trying for blind sql injections for the links which is not vulnerable yet !!! #####"
        add_notification(notification=info , type="information")

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
    blindCheck = Blinder.blinder(url, sleep=5)
    if blindCheck.check_injection():
        print("Blind SQL Injection at {}".format(url))


