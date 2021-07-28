import requests
import argparse
import sys
import asyncio
import pprint

parser = argparse.ArgumentParser(description="DAST Analysis tools -h for help")
parser.add_argument('-u', '--url', type=str, required=True)
parser.add_argument('-c', '--cookie', type=str)
parser.add_argument('-ht' '--httpheader', type=str)
parsed_args = parser.parse_args()
enumarated_protocols = ["ftp://", "smtp://", "http://", "https://"]
current_protocols = ["http://", "https://"]

def add_protocol(protocol):
    if current_protocols.append(protocol):
        sys.stdout.write("Protocol Added:{}".format(protocol))
        return True
    else:
        sys.stdout.write("Error while processing the protocol:{}".format(protocol))
        return False

def get_site():
    if parsed_args.url:
        site = parsed_args.url
        for i in protocols:
            final_url = i+site
            returned = requests.request(url=final_url, method="GET")
            pprint.pprint(returned.headers)
    else:
        print("No such argument")

if __name__ == '__main__':
    get_site()
