# Jurassic bank [_snakeCTF 2024 Quals_]

**Category**: crypto

## Challenge Description

Dinosaurs went extinct because they didn't care much about their future, our bank, though, has provided the best way to save money since the Jurassic!

Jurassic Bank, since 170 million years ago.

## Solution

### Step 1: Tokens always find a way

The algorithm used to generate the token is the following:

```Python

def generate_token(data):
    salt = (secret ^ (data["time"] // 10 * data["ex"])) + int(data["id"], 16)
    return dump_dict({'data': data, 'signature': hash(f"{data['qt']}_{salt}")})

```

The user can control directly the 'ex' and 'id' fields of the token and indirectly the 'time' by waiting.

The goal is to recover the secret used to generate the token,
to forge a token with enough money to transfer to buy the flag.

### Step 2: Recover the salt

The base idea is to create two tokens with different times, ex and id trying to generate the same salt.

For example, if 2 tokens are generated with (time = 0, id = 0, ex = 0) and (time = 10, id = 1, ex = 1):

- if secret = 1, then:  
   salt1 = (1 ^ (0 // 10 _ 0)) + 0 = 1  
   salt2 = (1 ^ (1 // 10 _ 1)) + 1 = 1
- if secret = 0, then:  
   salt1 = (0 ^ (0 // 10 _ 0)) + 0 = 0  
   salt2 = (0 ^ (10 // 10 _ 1)) + 1 = 1

In the first case the token will be the same, in the second case the token will be different.
This allows to recover the secret.

### Step 3: Forge the token

Building on the previous step, all the bits of the flag can be recovered.
And then forging a token with a big number as the amount to transfer will allow to buy the flag.

[Solver.py](./attachments/solve.py)
