#!/usr/bin/env python

import re
import sys
import struct
import base64

import pyshark

from pathlib import Path


FLAG_REGEX = re.compile(r"[a-zA-Z]+\{[a-zA-Z0-9_]+\}")
BASE32_REGEX = re.compile(r"^[A-Z2-7]{8,}={0,7}")


LEFT_SHIFT = 0b00000010
RIGHT_SHIFT = 0b00100000
# 1 byte report id, 23 byte array, 1 byte modifiers bitmap
paylod_struct = struct.Struct("<B"+"B"*23+"B")
# key code translation table
# source: https://www.usb.org/sites/default/files/documents/hut1_12v2.pdf page 53-59
key_codes: dict[int, tuple[str, str]] = {
    0x04: ("a", "A"),
    0x05: ("b", "B"),
    0x06: ("c", "C"),
    0x07: ("d", "D"),
    0x08: ("e", "E"),
    0x09: ("f", "F"),
    0x0A: ("g", "G"),
    0x0B: ("h", "H"),
    0x0C: ("i", "I"),
    0x0D: ("j", "J"),
    0x0E: ("k", "K"),
    0x0F: ("l", "L"),
    0x10: ("m", "M"),
    0x11: ("n", "N"),
    0x12: ("o", "O"),
    0x13: ("p", "P"),
    0x14: ("q", "Q"),
    0x15: ("r", "R"),
    0x16: ("s", "S"),
    0x17: ("t", "T"),
    0x18: ("u", "U"),
    0x19: ("v", "V"),
    0x1A: ("w", "W"),
    0x1B: ("x", "X"),
    0x1C: ("y", "Y"),
    0x1D: ("z", "Z"),
    0x1E: ("1", "!"),
    0x1F: ("2", "@"),
    0x20: ("3", "#"),
    0x21: ("4", "$"),
    0x22: ("5", "%"),
    0x23: ("6", "^"),
    0x24: ("7", "&"),
    0x25: ("8", "*"),
    0x26: ("9", "("),
    0x27: ("0", ")"),
    0x2C: (" ", " "),
    0x2D: ("-", "_"),
    0x2E: ("=", "+"),
    0x2F: ("[", "{"),
    0x30: ("]", "}"),
    0x33: (";", ":"),
    0x34: ("'", "\""),
    0x36: (",", "<"),
    0x37: (".", ">"),
    0x38: ("/", "?"),
    0x28: ("\n", "\n"),
    0x58: ("\n", "\n"),
}


def extract_text(cap: pyshark.FileCapture) -> str:
    text = ""
    for pkt in cap:
        # extract the payload from the packet
        payload = bytes.fromhex(pkt.data.usbhid_data.replace(":", ""))

        # unpack the payload
        report_id, *data, modifiers = paylod_struct.unpack(payload)

        if report_id != 1:
            continue

        for key in data:
            if key:
                shift = 1 if modifiers & (LEFT_SHIFT | RIGHT_SHIFT) else 0
                text += key_codes.get(key, ("", ""))[shift]
    
    return text


def main(file_path: Path):
    cap = pyshark.FileCapture(
        file_path,
        display_filter='usbhid.data && usb.src == "3.5.1"',  # filter for usbhid data packets
    )

    text = extract_text(cap)

    # check for base32 encoded text
    for line in text.split("\n"):
        if BASE32_REGEX.search(line):
            enc_segment = BASE32_REGEX.search(line).group()
            flag = base64.b32decode(enc_segment).decode()
            # check if the flag is in the correct format
            if FLAG_REGEX.match(flag):
                print(flag)
                break


if __name__ == "__main__":
    pcap_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./output")

    pcap_path = pcap_dir / "capture.pcap"

    main(pcap_path)
