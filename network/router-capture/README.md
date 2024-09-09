# router-capture [_snakeCTF 2024 Quals_]

**Category**: network

## Description

We are developing a new router with military grade security.
So, we have captured wifi and wan traffic from the router.
Try to break our encryption.

## Solution

## Traffic Analysis

The Wi-Fi traffic is encrypted using WEP, but its key cannot be bruteforced in a reasonable time.
The wan traffic is primarily composed of TLS packets, but a small percentage of the packets are unencrypted http packets.

## Analysis of the http packets

By utilizing the display filter `http && !tls` in Wireshark, only the unencrypted http packets can be observed, totalling 76 packets.
Therefore, the packets can be manually analysed.
It can be observed that a TR-069 session exists between `10.255.255.35` and `10.24.34.7`.
By analysing the packets, it becomes apparent that the ACS is sending a request to the CPE to change the Wi-Fi password, which is transmitted in plain text.

## Utilizing the key

With the passkey, the WEP traffic in the Wi-Fi capture can be decrypted.
It can be observed that the packets solely consist of SMTP and IMAP packets, suggesting that the flag may be present in one of the emails.
By analysing each email, the flag is discovered in one of the attachments of an email from Bob to Alice.
