import re
import requests
from .forms import forms
import random
import string

tokenPattern = r'^[\w\-_+=/]{14,256}$'
commonNames = ['csrf', 'auth', 'token', 'verify', 'hash']
C_headers = {  # default headers
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip,deflate',
    'Connection': 'close',
    'DNT': '1',
    'Upgrade-Insecure-Requests': '1',
}
tolerable_difference = 0

class CSRF:

    actions = []

    def __init__(self, url, headers=C_headers, cookies=None):
        self.url = url
        self.headers = headers
        self.cookies = cookies

    def set_url(self,new_url):
        self.url = new_url

    def extractHeaders(self, req_headers):
        headers = req_headers.replace('\\n', '\n')
        sorted_headers = {}
        matches = re.findall(r'(.*):\s(.*)', headers)
        for match in matches:
            header = match[0]
            value = match[1]
            try:
                if value[-1] == ',':
                    value = value[:-1]
                sorted_headers[header] = value
            except IndexError:
                pass
        return sorted_headers

    def isProtected(self, parsed):
        protected = False
        if self.url not in CSRF.actions:
            for oneForm in parsed:
                inputs = oneForm['inputs']
                for inp in inputs:
                    name = inp['name']
                    kind = inp['type']
                    value = inp['value']
                    if value is not None:
                        if re.match(tokenPattern, value):
                            print(oneForm)
                            protected = True
            return protected

    def isDynamic(self, url, method_header ,data = None, cookies = None):
        isDynamic = False
        response = requests.post(url=url, headers=method_header, data=data, cookies=cookies)
        content_length = len(response.text)
        response2 = requests.post(url=url, headers=method_header, data=data, cookies=cookies)
        content_length2 = len(response2.text)
        if content_length != content_length2:
            tolerable_difference = abs(content_length-content_length2)
        else:
            tolerable_difference = 0
        if tolerable_difference > 0:
            isDynamic = True
        return isDynamic

    def manipulator(self, url, mode, inputs):
        final_inputs = {}
        for input_ in inputs:
            value = input_["Value"]
            if value is not None:
                if re.match(tokenPattern, value):
                    if mode == "remove":
                        new_value = ""
                        final_inputs[input_] = new_value
                    elif mode == "change":
                        value_length = len(value)
                        random_Value = ''.join(random.choices(string.ascii_uppercase + string.digits, k = value_length))
                        final_inputs[input_] = random_Value

    def main(self):
        if not self.isProtected(forms.get_forms(url=self.url, cookies=self.cookies)):
            CSRF.actions.append(self.url)
        else:
            print(forms.get_forms(url=self.url,cookies=self.cookies))
            print("CSRF token pattern detected , website probably takes action against CSRF at {}".format(self.url))



"""if __name__ == '__main__':
    formlist = forms.get_forms("https://www.netsparker.com/blog/web-security/protecting-website-using-anti-csrf-token/", cookies={"login":"test/test"})
    CSRFCheck = CSRF(url="http://testphp.vulnweb.com/artists.php?artist=1", cookies={"login":"test/test"})
    CSRFCheck.main()"""