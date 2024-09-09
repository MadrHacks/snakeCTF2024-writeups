# Cloudflared [_snakeCTF 2024 Quals_]

**Category**: network

## Description

I started self-hosting some of my web projects on my old PC,
each with a different domain name.
I asked a friend what he thought about that,
and he said he could only see one.
Can you guess which one it is?

## Solution

### Understanding the capture

The packet capture illustrates the flow of traffic to and from the server. The capture is divided into several segments:

- **Packets 1 to 36:** This segment contains traffic involving the router's API, where it is evident that external ports are opened through port forwarding initiated by the home server.

- **Packets 37 to 120:** This section contains traffic with Cloudflare's API. For each of the two zones, the following actions are performed:

  - A new zone with a domain name is created.
  - An "A" record is added using the router's WAN IP, with proxying enabled.
  - A rule is set to forward Cloudflare traffic to a custom TCP port.

- **Packets 121 to 1954:** These packets record traffic between a client and the services running on the home server.

### What are used for the endpoints?

By examining the router's IP address (`192.168.88.1`), the router can be identified as a MikroTik device.

The Cloudflare server is identified based on the "cloudflare" value in the server HTTP header of an HTTP response, such as seen in packet **46**.

The home server is a generic Linux server, hosting various Docker containers for different services.

### Port forwarding/destination NAT

By examining the router traffic, it is evident that the home server configures several TCP port forwarding rules through the router:

- &nbsp; &nbsp; **80** on the router forwarded to &nbsp; &nbsp; **80** on the server
- **5225** on the router forwarded to **6260** on the server
- **5367** on the router forwarded to **6969** on the server

### Cloudflare API

From the traffic exchanged with Cloudflare's API, two zones are created by the home server:

- Domain: `youtube-mod.com`, IP: `188.111.114.104`, TCP port: **1178**.
- Domain: `whatsapp-but-better.com`, IP: `188.114.111.104`, TCP port: **5225**.

### Extracting the flag

The service running on the home server's port **6260** was identified as being accessed via `whatsapp-but-better.com`. Upon analysing the traffic and cross-referencing port mappings (`whatsapp-but-better.com:80 -> 188.114.111.104:5225 -> 192.168.88.254:6260`), the service was recognized as a web application resembling WhatsApp.

By exporting HTTP objects, including HTML and CSS files, from the `pcap` file using Wireshark and opening them in a web browser, it was found that the flag is displayed within messages from the contact "MadrHacks", as shown in the [screenshot](./images/whatsapp-but-better.png). The flag is revealed character by character within the messages exchanged.
