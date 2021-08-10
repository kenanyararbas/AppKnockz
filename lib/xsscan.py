import urllib.parse

from urllib.parse import urlparse, parse_qsl,parse_qs
from forms import *
import validators

string_terminators = ["", "'", ";", "';", ]

payloads = ["<script>alert(1)</script>"]

unique_string = "Approx is knocking"


class xss_scanner:
    exploited_urls = []
    escape_chars = ["'", '">', ";"]

    def __init__(self, url, cookies=None, headers=None):
        self.url = url
        self.cookies = cookies,
        self.headers = headers

    def check_url(self):
        return validators.url(self.url)


    def in_attrs(self, highString):
        # If this method returns true try the payloads combined with escape sequences.
        value_Tags = ["li", "a", "button", "input"]
        reflecteds = []
        unique_value = highString
        formlist = forms(self.url, self.cookies)
        for each_form in formlist:
            final = submit(each_form, unique_value)
            if unique_value in final[0]:
                html_content = final[0]
                content_parser = bs(html_content, "html.parser")

                for tag in value_Tags:
                    reflecteds.extend(content_parser.find_all(tag))

                for reflection in reflecteds:
                    if reflection.get("value") is not None and reflection.get("href") is not None:
                        if reflection.get("value") == unique_value or unique_value in reflection.get("href"):
                            return True
        return False

    def contain_params(self):
        if self.check_url():
            print(self.url)
            parsed_url = urlparse(self.url)
            query = parsed_url.query
            parameters = parse_qs(query)
            if bool(parameters) is False and parameters is not None:
                return False
            else:
                return True

    def reflected_xss(self):
        if self.contain_params():
            parsed_url = urlparse(self.url)
            query = parsed_url.query
            parameters = parse_qs(query)
            for parameter in parameters:
                value = parameters[parameter][0]
                parameters[parameter] = value
                current_Value = parameters[parameter]
                for P in payloads:
                    parameters[parameter] = P
                    new_parts = list(parsed_url)
                    new_parts[4] = urllib.parse.urlencode(parameters)
                    build_url = urllib.parse.urlunparse(new_parts)
                    data = requests.get(build_url).text
                    if P in data:
                        print("Reflected XSS found at {} triggered with {}".format(self.url, P))
                parameters[parameter] = current_Value

    def main(self):
        formslist = forms(self.url, self.cookies)
        for form in formslist:
            for P in payloads:
                response = submit(self.url, form, P , self.cookies)
                if P in response[0]:
                    print("XSS Found at {} endpoint triggered with {} payload".format(response[1], P))




if __name__ == '__main__':
    scanner = xss_scanner(url="http://testphp.vulnweb.com/search.php?test=query&dummy=test", cookies={"login": "test/test"})
    scanner.reflected_xss()
