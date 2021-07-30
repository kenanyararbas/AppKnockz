import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urlparse


class crawler:
    urls = []

    @classmethod
    def scrape(self, site):
        """ Crawl (Spider) the website recursively will be used with parameter existence in terms of SQLi and other code
            injections
        """
        # getting the request from url
        r = requests.get(site)

        # converting the text
        s = bs(r.text, "html.parser")

        for i in s.find_all("a"):

            href = i.attrs['href']

            if href.startswith("/"):
                site = site + href

            else:
                site = (str(urlparse(site).scheme + "://" + urlparse(site).netloc) + "/" + href)

                if site not in crawler.urls:
                    crawler.urls.append(site)
                    print(site)
                    # calling it self
                    crawler.scrape(site)
