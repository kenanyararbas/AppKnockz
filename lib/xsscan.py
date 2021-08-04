from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import requests
import re

string_terminators = ["", "'", ";", "';", ]
payloads = ["<script>alert(1)</script>"]
unique_string = "webappxss94949494"


class xss_scanner:

    def __init__(self, url, cookies=None, headers=None):
        self.url = url
        self.cookies = cookies,
        self.headers = headers

    def create_session(self):
        if self.cookies is not None:
            session = requests.session()
            return session

    def search_reflections(self):
        tags = []
        formlist = self.forms()
        request = self.submit(formlist, unique_string)
        response = bs(request.content, "html.parser")
        results = response.find_all(text=re.compile(unique_string))
        for tag in results:
            print(tag.parent.attrs["id"])
            tag.append({"id": tag.parent.attrs[id]})
        return tags

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
        for form in form_specs:
            target_url = urljoin(self.url, form["action"])
            inputs = form["inputs"]
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

            if form["method"] == "post":
                if self.cookies is not None:
                    return requests.post(target_url, data=data, cookies=self.cookies[0])
                else:
                    return requests.post(target_url, data=data)
            else:
                if self.cookies is not None:
                    return requests.get(target_url, params=data, cookies=self.cookies[0])
                else:
                    return requests.get(target_url, params=data)

    def main(self):
        form_list = self.forms()
        for P in payloads:
            response = self.submit(form_list, P)
            if P in response.content.decode("utf-8"):
                print("XSS Found! at {} with the payload of {}".format(self.url,P))
            else:
                continue


if __name__ == '__main__':
    scanner = xss_scanner(url="http://testphp.vulnweb.com/", cookies={"login": "test/test"})
    scanner.main()
