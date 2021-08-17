import re
import urllib.parse
from headerinjection import *
from urllib.parse import parse_qs,urlparse,urlunparse
from forms import *

C_headers = {  # default headers
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip,deflate',
    'Connection': 'close',
    'DNT': '1',
    'Upgrade-Insecure-Requests': '1',
}

ssrf_Regex = "^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$"


class SSRF:

    def __init__(self, url, headers, cookies=None , external_urls=None):
        self.url = url
        self.cookies = cookies
        self.headers = headers
        self.external_urls = external_urls

    def set_url(self, new_url):
        self.url = new_url

    def check_url(self):
        """ Checks if url contains a webpage or an ip address if so returns a boolean value to indicate that """
        isContain = False
        scheme = urlparse(self.url)
        queries = parse_qs(scheme.query)
        #data formatting
        for query in queries:
            queries[query] = queries[query][0]
        for query in queries:
            if re.match(ssrf_Regex,queries[query]):
                isContain = True
                print("External host passed through url parameter at {} with {} parameter and {} value"
                      .format(self.url, query, queries[query]))
        return isContain

    def check_forms(self):
        """ Checks if the webpage containt a form with a data field which is used to interact with external dom.
        if so return a boolean value to indicate that"""
        isInteract = False
        formlist = forms.get_forms(self.url, cookies=self.cookies)
        for each_form in formlist:
            input_list = each_form['inputs']
            for each_input in input_list:
                if re.match(ssrf_Regex,input_list[each_input]):
                    print("External host passed through a form field at {} with a formfield like {}".format(self.url, input_list[each_input]))
                    isInteract = True
        return isInteract


    # Type can be url or form.Depend on that we adjust the request type
    def make_request(self, external_urls):
        scheme = urlparse(self.url)
        queries = parse_qs(scheme.query)
        # data formatting
        for query in queries:
            queries[query] = queries[query][0]
        for query in queries:
            current_value = queries[query]
            for url in external_urls:
                queries[query] = url
                print(queries)
                new_values = list(scheme)
                new_values[4] = urllib.parse.urlencode(queries)
                build_url = urllib.parse.urlunparse(new_values)
                response = requests.get(build_url)
                if response.status_code == 200:
                    print("Parameters fuzzed. Please check your external domain in order to obtain "
                          "the response")
            queries[query] = current_value

    def scan_SSRF(self):
        headers_check = headerinjection(url=self.url, redirect="example.com",
                                        cookies=self.cookies)
        if headers_check.inject():
            print("Header Inhection found at {} trying for SSRF ...".format(self.url))
        if self.check_url() or self.check_forms():
            print("IP or Hostname is passed through a parameter at {} sending request to your webserver..".format(self.url))
            self.make_request(external_urls=["http://www.example.com"])



if __name__ == '__main__':
    SSRF_scanner = SSRF(url="http://testphp.vulnweb.com/index.php?query=http://www.evil.com/&query2=http://www.firstcase.com:8080/1/", headers=C_headers, cookies={"login":"test/test"})
    #SSRF_scanner.make_request(external_urls=["http://example.com" , "http://www.google.com"])
    SSRF_scanner.scan_SSRF()


