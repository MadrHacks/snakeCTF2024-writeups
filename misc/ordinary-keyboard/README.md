# ordinary-keyboard [_snakeCTF 2024 Quals_]

**Category**: misc

## Description

Just your usual keyboard challenge.

Try to parse this.

## Solution

### Understanding the capture

The capture contains the traffic between a host and two USB HID devices. The first device has two endpoints (excluding endpoint 0) and the second one has only one endpoint.

### Usage of the endpoints

By examining the HID Report Descriptor of the devices, it can be observed that the first device is a keyboard (3.4.1) and a mouse (3.4.2), while the second one is a keyboard (3.5.1). \
It can be assumed that the flag will be transferred using one of the keyboards.

### First keyboard

The first keyboard is a conventional Logitech keyboard. Its traffic can be easily parsed using a Wireshark keyboard dissector. \
However, after parsing it, it appears that no useful information is contained within.

### Second keyboard

The second keyboard cannot be parsed by most dissectors, as it does not adhere to the standard keyboard report descriptor used in the industry. \
Therefore, in order to understand the format of the payload, the report descriptor needs to be examined.

### Report descriptor

The report descriptor comprises 1 byte for the report id, 23 bytes for key presses, and 1 byte for the modifier keys. \
By automating the extraction of the key presses and the modifier keys, the typed content can be obtained.
After extracting all the typed content as plain text, a base32 encoded string is revealed. \
Decoding the base32 string yields the flag.

Here is the [solver script](./attachments/solve.py).
