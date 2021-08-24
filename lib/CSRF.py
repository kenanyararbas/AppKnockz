import re
from .forms import forms
import random
import string
from .crawler import *
import asyncio

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

    def set_url(self, new_url):
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
                            protected = True
            return protected

    def isDynamic(self, url, method_header, data=None, cookies=None):
        isDynamic = False
        response = requests.post(url=url, headers=method_header, data=data, cookies=cookies)
        content_length = len(response.text)
        response2 = requests.post(url=url, headers=method_header, data=data, cookies=cookies)
        content_length2 = len(response2.text)
        if content_length != content_length2:
            tolerable_difference = abs(content_length - content_length2)
        else:
            tolerable_difference = 0
        if tolerable_difference > 0:
            isDynamic = True
        return isDynamic

    def manipulator(self, mode, formlist):
        final_inputs = {}
        for form in formlist:

            if form['method'].lower() == "post":
                response1 = requests.post(self.url, data=form,cookies=self.cookies)
            else:
                response1 = requests.get(self.url, params=form, cookies=self.cookies)

            inputs = form['inputs']
            for each_input in inputs:
                value = each_input['value']
                if value is not None:
                    if re.match(tokenPattern, value):
                        if mode == "remove":
                            new_value = ""
                            inputs[each_input] = new_value
                        elif mode == "change":
                            value_length = len(value)
                            random_Value = ''.join(
                                random.choices(string.ascii_uppercase + string.digits, k=value_length))
                            each_input['value'] = random_Value
                            if form['method'].lower() == "post":
                                if self.isDynamic(url=self.url, method_header=C_headers, data=form, cookies=self.cookies):
                                    print("Web page is not dynamic (Tolerable value is {})".format(tolerable_difference))
                            print(form)
                            response2 = requests.post(self.url, data=form, cookies=self.cookies)
                            print("Tolerable difference is calculated as : {}".format(tolerable_difference))
                            if (len(response1.content) - len(response2.content)) > tolerable_difference:
                                print("Probably a CSRF Indicator found at {}".format(self.url))




    def main(self,form_list):
        for each_form in form_list:
            if len(each_form) > 0:
                self.set_url(each_form[0]['url'])
            if not self.isProtected(each_form):
                CSRF.actions.append(self.url)
            else:
                print("CSRF token pattern detected , website probably takes action against CSRF at {}".format(self.url))
                for each_request in form_list:
                    self.manipulator(mode="change", formlist=each_request)


if __name__ == '__main__':
    crawler.scrape(site="http://testphp.vulnweb.com/index.php", cookie={'login':'test/test'})
    CSRFCheck = CSRF(url="http://testphp.vulnweb.com/artists.php?artist=1", cookies={'login':'test/test'})
    CSRFCheck.main()
