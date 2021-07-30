import requests
from bs4 import BeautifulSoup as bs


class httpassist:

    @classmethod
    def post_method(self, url, headers, payloads, ):
        """ Payloads may contain both the string terminators and payloads. Should arrange later"""
        hd = headers
        data = payloads
        rq = requests.post(url=url, data=data, headers=hd)
        print(rq.text)

    @classmethod
    def get_method(self, url, payloads, headers):
        hd = headers
        data = payloads
        rq = requests.get(url=url, data=data, headers=hd)
        print(rq.text)
