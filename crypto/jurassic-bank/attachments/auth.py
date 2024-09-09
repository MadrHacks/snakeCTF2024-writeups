import hashlib
import json
from base64 import b64encode, b64decode
import random

secret = random.getrandbits(64)
expired_tokens = []
hash = lambda a: b64encode(hashlib.sha256(a.encode()).digest()).decode()


def dump_dict(d):
    return b64encode(json.dumps(d).encode()).decode()


def load_dict(d):
    return json.loads(b64decode(d.encode()).decode())


def generate_token(data):
    salt = (secret ^ (data["time"] // 10 * data["ex"])) + int(data["id"], 16)
    return dump_dict({'data': data, 'signature': hash(f"{data['qt']}_{salt}")})


def check_token(data, signature):
    if signature in expired_tokens:
        return False
    expired_tokens.append(signature)

    salt = (secret ^ (data["time"] // 10 * data["ex"])) + int(data["id"], 16)
    return hash(f"{data['qt']}_{salt}") == signature


def decode_token(token):
    try:
        token = load_dict(token)
        if not check_token(token['data'], token['signature']):
            return None
        return token['data']
    except:
        return None
