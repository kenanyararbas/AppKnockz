from bs4 import BeautifulSoup as bs
import requests
from urllib.parse import urljoin


class forms:
    @classmethod
    def get_forms(self, url, cookies=None):
        returned_forms = []
        # This function is standing for enumerating the forms existed on the given URL
        if cookies is not None:
            try:
                content = bs(requests.get(url, cookies=cookies).content.decode(), "html.parser")
            except UnicodeDecodeError:
                content = None
                pass
        else:
            content = bs(requests.get(url).content, "html.parser")

        if content is not None:
            form_Content = content.find_all("form")

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
                returned_forms.append(form_specs)
        return returned_forms

    @classmethod
    def submit(self, url, form_specs, payload, cookies=None, isDecoded=False):
        cookies = cookies
        isDecoded = isDecoded
        data = {}
        target_url = urljoin(url, form_specs["action"])
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

        if isDecoded:
            if form_specs["method"] == "post":
                if cookies is not None:
                    response = requests.post(target_url, data=data, cookies=cookies).content.decode()
                else:
                    response = requests.post(target_url, data=data).content.decode()
            else:
                if cookies is not None:
                    response = requests.get(target_url, params=data, cookies=cookies).content.decode()
                else:
                    response = requests.get(target_url, params=data).content.decode()
        else:
            if form_specs["method"] == "post":
                if cookies is not None:
                    response = requests.post(target_url, data=data, cookies=cookies).content
                else:
                    response = requests.post(target_url, data=data).content
            else:
                if cookies is not None:
                    response = requests.get(target_url, params=data, cookies=cookies).content
                else:
                    response = requests.get(target_url, params=data).content

        return response, target_url
