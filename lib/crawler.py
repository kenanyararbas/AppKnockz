import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urlparse


class crawler:
    urls = []

    @classmethod
    def scrape(self, site, cookie=None):
        if cookie is not None:
            print(cookie)
            session = requests.session()
            r = session.get(site, cookies=cookie)
        else:
            r = requests.get(site)

        """ 
            Crawl (Spider) the website recursively will be used with parameter existence in terms of SQLi and other code
        injections
        """

        # converting the text
        s = bs(r.text, "html.parser")

        for i in s.find_all("a"):

            href = i.attrs['href']

            if href.startswith("/"):
                site = site + href

            elif href.startswith("mailto:") or href.startswith("http://") or href.startswith("https://"):
                continue

            else:
                site = (str(urlparse(site).scheme + "://" + urlparse(site).netloc) + "/" + href)

                if site not in crawler.urls:
                    crawler.urls.append(site)
                    # calling it self
                    crawler.scrape(site, cookie=cookie)

if __name__ == '__main__':
    result = crawler.scrape(site="http://testphp.vulnweb.com/userinfo.php", cookie={"login": "test/test"})
    for i in crawler.urls:
        print(i)