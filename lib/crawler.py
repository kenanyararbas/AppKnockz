import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urlparse
from .logger import *


class crawler:
    urls = []

    @classmethod
    def scrape(self, site, cookie=None, mode="Normal"):
        if cookie is not None:
            session = requests.session()
            r = session.get(site, cookies=cookie)
        else:
            r = requests.get(site)

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

                    if mode == "Verbose":
                        notification = f' Path identified ; {site}'
                        add_notification(notification, type="informational")

                    else:
                        crawler.urls.append(site)

                    # calling it self
                    crawler.scrape(site, cookie=cookie)

