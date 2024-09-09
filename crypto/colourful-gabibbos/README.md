# Colourful Gabibbos [_snakeCTF 2024 Quals_]

**Category**: crypto

## Challenge Description

I managed to get my hands on two secret images from the Gabibbos, but they're encrypted. Can you help me decrypt them?

The first one was straightforward, it turned out to be a photo of a well-known member, but the second one is a bit more difficult.

## Solution

The encryption is done by creating a map for each colour in the image and then encrypting the image by applying the map to each pixel.
Using the provided plaintext-ciphertext pair, the map used to encrypt the images can be recovered.

Since the map is generated using the `random` python module,
the internal state of the random generator is recoverable
and so is the map used to encrypt the flag and recover the original image.

```Python
#!/usr/bin/env python3

import os
import sys

from PIL import Image
import randcrack


def reconstruct_map():
    og = Image.open(os.path.join(dir, 'og.png'))
    en = Image.open(os.path.join(dir, 'og_enc.png'))
    randoms = []
    pixels = list(og.getdata())
    k = {}
    for i, p in enumerate(pixels):
        if p in k:
            continue
        k[p] = en.getpixel((i % og.width, i // og.width))

    pixels = list(k.items())
    pixels.sort(key=lambda x: x[0])

    for _, t in pixels:
        r = t[0] | t[1] << 8 | t[2] << 16 | t[3] << 24
        randoms.append(r)
    return randoms


def find_key(r):
    k = {}
    p = 0
    while p < 256:
        x = r.predict_getrandbits(8)
        while x in k:
            x = r.predict_getrandbits(8)
        k[x] = p
        p += 1
    return k


def decrypt_image(image, r):
    k = find_key(r)
    n = Image.new(image.mode, image.size, 0)
    for x in range(image.size[0]):
        for y in range(image.size[1]):
            n.putpixel((x, y), k[image.getpixel((x, y))])

    return n


def check_image(im):
    for i in range(256):
        if im.getpixel((i, 49)) != i:
            return False
    return True


def main():
    randoms = reconstruct_map()

    r = randcrack.RandCrack()
    for n in randoms[-624:]:
        r.submit(n)

    n = decrypt_image(Image.open(os.path.join(dir, 'flag_enc.png')), r)
    n.save(os.path.join(dir, 'flag.png'))


if __name__ == '__main__':
    dir = sys.argv[1]
    main()
```
