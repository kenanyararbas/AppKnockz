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

    headers = ["X-Forwarded-For", "Origin", "X-HTTP-Host-Override", "X-Forwarded-Server", "X-Host", "Forwarded"]
    internal_hosts = ["127.0.0.1", "::1", "localhost", "2130706433", "017700000001" , "127.1"]

    def __init__(self, url , redirect):
        self.url = url
        self.redirect = redirect

    def check_url(self):
        return validators.url(self.url)

    def inject(self):
        vuln_list = []
        if validators.url(self.url):
            Location = ""
            for header in headerinjection.headers:
                req_header = {header: self.redirect}
                response = requests.get(self.url, headers=req_header, allow_redirects=False)
                if is_redirected(response.status_code):
                    Location = response.headers["Location"]
                Body = response.content.decode()
                if Location == self.redirect or Body.find(self.redirect) > -1:
                    vuln_list.append({self.url:Location})
                    return vuln_list
            return False
        else:
            print("Provided url is not valid")


if __name__ == '__main__':
    injector = headerinjection(url="http://testphp.vulnweb.com/index.php" , redirect="vulnerable-website.com")
    injector.inject()
