from bs4 import BeautifulSoup as bs
import mechanize


string_terminators = ["", "'" , ";", "';" , ]
payloads = ['<script>alert(1)</script>']


class xss_scanner:

    def __init__(self, url, response):
        self.url = url
        self.response = response

    def update_response(self,new_response):
        self.response = new_response

    def start_scan(self):
        keys = {}
        content = bs(self.response, "html.parser")
        forms = content.find_all("form", method=True)
        for form in forms:
            inputs = form.find_all("input")
            for input in inputs:
                print(input["name"])





if __name__ == '__main__':
    print("This is code injection page")
