import time
from datetime import datetime

from auth import *
from pwn import remote, args

p = remote(args.HOST, args.PORT, ssl=args.SSL)
if args.TEAM_TOKEN:
    p.sendlineafter(b"enter your team token: ", args.TEAM_TOKEN.encode())


def get_payload(id, ex):
    payload = b'3\n' + hex(id)[2:].encode() + b'\n1\n' + str(ex).encode() + b'\na\n1\n'
    return payload


def get_tokens(n):
    token = []
    for i in range(n):
        p.recvuntil(b'Use this token to recieve you prehistoric money\n')
        t = p.recvline().decode().strip()
        t = load_dict(t)
        token.append(t["signature"])
    return token


def fast_get_batch_1():
    payload = b''.join([get_payload(0, 1 << i) for i in range(64)])
    p.send(payload)
    return get_tokens(64)


def fast_get_batch_2():
    payload = b''.join([get_payload(1 << i, 1 << i) for i in range(64)])
    p.send(payload)
    return get_tokens(64)


def forge_token(secret, id, qt, offset):
    data = {"id": id, "ex": 10, "qt": qt, "rs": 1, "time": int(time.time() + offset)}

    salt = (secret ^ (data["time"] // 10 * data["ex"])) + int(data["id"], 16)
    return dump_dict({"data": data, "signature": hash(f"{data['qt']}_{salt}")})


def get_time_offset():
    p.sendlineafter(b"Insert choice:", b"1")
    p.recvuntil(b"time is ")
    t = int(datetime.strptime(p.recvline().strip().decode(), '%Y-%m-%d %H:%M:%S').timestamp())
    print(f'time offset: {t - int(time.time())}')
    return t - int(time.time())


def main():
    p.sendlineafter(b"Insert choice:", b"1")
    p.sendlineafter(b":", b"a")
    p.sendlineafter(b":", b"a")

    p.sendlineafter(b"Insert choice:", b"1")
    p.recvuntil(b"ID: ")
    id = p.recvline().strip().decode()
    print("id:", id)

    os = get_time_offset()

    print("waiting")
    while int((time.time() + os) // 10) % 2 != 0:
        time.sleep(1)

    time.sleep(2)

    b1 = fast_get_batch_1()
    print("waiting pt 2")
    while int((time.time() + os) // 10) % 2 != 1:
        time.sleep(1)

    time.sleep(2)

    b2 = fast_get_batch_2()

    secret = 0
    for i, (x, y) in enumerate(zip(b1, b2)):
        if x == y:
            secret |= 1 << i

    print("secret:", secret)

    t = forge_token(
        secret,
        id,
        9999999999999999999999999999999999999999999999999999999999999999999999999,
        os
    )

    print("created token:", t)
    p.sendlineafter(b"Insert choice:", b"4")
    p.sendlineafter(b":", t.encode())
    p.sendlineafter(b"Insert choice:", b"5")
    print(p.recvline().strip().decode())
    p.close()


if __name__ == "__main__":
    main()
