from urllib.parse import urlparse

string_terminators = []
payloads = open("payloads.txt", 'r')


class codeInjection:

    def __init__(self, url, exploits, injection):
        self.url = url
        self.exploits = exploits
        self.injection = injection

    def set_type(self, ):
        pass

    def set_url(self, url):
        pass

    def parse_url(self):
        return urlparse(self.url)

    def start_test(self):
        pass


if __name__ == '__main__':
    print("This is code injection page")
