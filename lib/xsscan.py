import urllib.parse
from urllib.parse import parse_qs
import validators
from .forms import *
import asyncio
import aiohttp
from .crawler import *
from .logger import add_notification

string_terminators = ["", "'", ";", "';", ]

payloads = ["<img src=X onerror=alert(1)/>", "<svg onload=alert('XSS')>", "<script>alert(1)</script>"]

unique_string = "Approx is knocking"

vulnerable_links = []

class xss_scanner:
    exploited_urls = []
    escape_chars = ["'", '">', ";"]

    def __init__(self, url, crawler, cookies=None, headers=None):
        self.url = url
        self.cookies = cookies,
        self.headers = headers,
        self.crawler = crawler

    def check_url(self):
        return validators.url(self.url)

    def set_url(self, new_url):
        self.url = new_url

    def in_attrs(self, highString):
        # If this method returns true try the payloads combined with escape sequences.
        value_Tags = ["li", "a", "button", "input"]
        reflecteds = []
        unique_value = highString
        formlist = forms.get_forms(self.url, self.cookies)
        for each_form in formlist:
            final = forms.submit(each_form, unique_value)
            if unique_value in final[0]:
                html_content = final[0]
                content_parser = bs(html_content, "html.parser")

                for tag in value_Tags:
                    reflecteds.extend(content_parser.find_all(tag))

                for reflection in reflecteds:
                    if reflection.get("value") is not None or reflection.get("href") is not None:
                        if reflection.get("value") == unique_value or unique_value in reflection.get("href"):
                            return True
        return False

    def has_parameters(self):
        #Non-async
        if self.check_url():
            parsed_url = urlparse(self.url)
            query = parsed_url.query
            parameters = parse_qs(query)
            if bool(parameters) is False and parameters is not None:
                return False
            else:
                return True

    async def reflected_xss(self, session):
        if self.has_parameters():
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
                    async with session.get(build_url) as data:
                        data = await data.text(encoding="utf-8")
                        if P in data:
                            return f'Reflected XSS found at {self.url} triggered with {P}'
                parameters[parameter] = current_Value

    async def reflected_main(self):
        async with aiohttp.ClientSession(cookies=self.cookies[0]) as session:
            tasks = []
            for url in self.crawler:
                self.set_url(url)
                task = asyncio.ensure_future(self.reflected_xss(session=session))
                tasks.append(task)
                response = await asyncio.gather(*tasks)
            for i in response:
                if i is not None:
                    add_notification(notification=i, type="critical")

    def run_xss(self, form_list):
        asyncio.run(self.reflected_main())
        response = asyncio.run(
            forms.async_submit(cookies=self.cookies[0], formlist=form_list, payloads=payloads))
        for each_page in response:
            for P in payloads:
                if P in each_page[0]['content']:
                    if each_page[0]['url'] not in vulnerable_links:
                        notify = f'XSS Found with a form instance {each_page[0]["url"]} with {P} payload'
                        add_notification(notification=notify, type="critical")
                        vulnerable_links.append(each_page[0]['url'])






