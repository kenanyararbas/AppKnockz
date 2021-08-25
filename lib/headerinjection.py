import validators
import requests


def is_redirected(status_code):
    if status_code == 301:
        return True
    elif status_code == 302:
        return True
    elif status_code == 303:
        return True
    elif status_code == 307:
        return True
    elif status_code == 308:
        return True
    else:
        return False


class headerinjection:
    vuln_list = []
    headers = ["X-Forwarded-For", "Origin", "X-HTTP-Host-Override", "X-Forwarded-Server", "X-Host", "Forwarded"]

    def __init__(self, url , redirect, cookies=None):
        self.url = url
        self.redirect = redirect
        self.cookies = cookies

    def check_url(self):
        return validators.url(self.url)

    def set_url(self, new_url):
        self.url = new_url

    def inject(self):
        if validators.url(self.url):
            Location = "127.0.0.1"
            for header in headerinjection.headers:
                req_header = {header: self.redirect}
                if self.cookies is not None:
                    response = requests.get(self.url, headers=req_header, allow_redirects=False, cookies=self.cookies)
                else:
                    response = requests.get(self.url, headers=req_header, allow_redirects=False)
                if is_redirected(response.status_code):
                    Location = response.headers["Location"]
                    try:
                        Body = response.content.decode()
                        if Location == self.redirect or Body.find(self.redirect) > -1:
                            print("Header Injection found at {} , injection this header: {} and redirecting that page : {}".format(self.url,header,Location))
                            headerinjection.vuln_list.append({self.url: Location})
                            return True
                    except UnicodeDecodeError:
                        pass
                else:
                    return False
        else:
            print("Provided url is not valid")

    def main(self):
        self.inject()



if __name__ == '__main__':
    injector = headerinjection(url="http://testphp.vulnweb.com/index.php", redirect="vulnerable-website.com")
    injector.inject()
