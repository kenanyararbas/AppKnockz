import re
import requests
from forms import forms

tokenPattern = r'^[\w\-_+=/]{14,256}$'
commonNames = ['csrf', 'auth', 'token', 'verify', 'hash']
headers = {  # default headers
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip,deflate',
    'Connection': 'close',
    'DNT': '1',
    'Upgrade-Insecure-Requests': '1',
}


class CSRF:

    def __init__(self, url, headers=headers, cookies=None):
        self.url = url
        self.headers = headers
        self.cookies = cookies

    def extractHeaders(self, req_headers):
        req_headers = req_headers.replace('\\n', '\n')
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
        print(parsed)
        for oneForm in parsed:
            inputs = oneForm['inputs']
            for inp in inputs:
                name = inp['name']
                kind = inp['type']
                value = inp['value']
                if value is not None:
                    if re.match(tokenPattern, value):
                        protected = True
        return protected

    def isDynamic(self, url, headers, data, cookies):
        isDynamic = False
        response = requests.post(url=url, headers=headers, data=data, cookies=cookies)
        content_length = len(response.text)
        response2 = requests.post(url=url, headers=headers, data=data, cookies=cookies)
        content_length2 = len(response2.text)
        if content_length != content_length2:
            tolerable_difference = abs(content_length-content_length2)
        else:
            tolerable_difference = 0
        if tolerable_difference > 0:
            isDynamic = True
        return isDynamic


if __name__ == '__main__':
    formlist = forms.get_forms("https://www.netsparker.com/blog/web-security/protecting-website-using-anti-csrf-token/", cookies={"login":"test/test"})
    CSRFCheck = CSRF(url="https://www.netsparker.com/blog/web-security/protecting-website-using-anti-csrf-token/",cookies={"login":"test/test"})
    print(CSRFCheck.isProtected(parsed=formlist))