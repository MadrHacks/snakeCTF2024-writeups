# Robotank (Cryptography part) [_snakeCTF 2024 Quals_]

**Category**: Misc

## Description

_RoboTank_ is back! And he's stronger than ever!

Last year only **one** team was able to pwn our favourite tank,
but this year nobody, nobody will win!

Why? Try and pwn our RoboTank while a team of experts is constantly changing
the server's parameters **every 5 minutes**.

Watch out! We think someone is corrupting them!
Follow the live stream on YouTube: `REDACTED`

What are those cards? Mmmh, it seems _Minesweeper_, but slightly different.

Since it's our game, we make the rules

- Do not go outside the arena
- Do not harm _RoboTank_
- Each card will contain a tuple **(x,y)** where **x** is the number of
  adjacent bombs and **y** is the number of adjacent pieces of flag.
- Do not create multiple CTFd accounts to solve RoboTank, otherwise
  you **will** be banned!
- If you hit a `bomb` you will be stuck for 5 minutes.

Have fun!

### Hints

- The server and the client are using the same signature scheme
- The client is perfectly working. The issue is given by the corrupted parameter received from the server (the prime)
- Most of the cryptographic information can be found here: `_ZN106_$LT$robotank..signature..algorithm..SIG$u20$as$u20$robotank..signature..algorithm..SignatureAlgorithm$GT$4init17hae59a45858c84018E`

## Solution (Crypto part)

By assuming the reversing part as already done, the cryptography part requires to fill the missing 72 bits of the prime received from the Server and to compute the discrete logarithm to compute the Server's secret key which gives the possibility to easily forge valid signatures acting as the Server even being the Client.

### Analysis

By launching the client an error is displayed: `Modular inverse does not exist, maybe your parameters are corrupted, it seems that the last 72 bits of your prime are not correct`.
Moreover, the Client and the Server are using the same signature scheme which creates the parameters in the following way:

- Chooses a prime $p$ (weak prime);
- Computes a prime $q = p \mod{18446744069414584321} = p \mod{2^{64} - 2^{32} + 1}$
- Chooses a secret key $x$ less than $q$
- Computes the public key as $g^x \mod{p}$ with $g = 3$.

### Recovering the last 72 bits

Thanks to the Goldilock prime $2^{64} - 2^{32} + 1$ it's easy to recover the last 64 bits. The main issue is that there are still 8 bits missing which are needed to recover the others.

The Server signs all the messages sent to the Client, which means that it is possible to verify the signatures if the correct parameters are found. By visiting the `/params` endpoint, the Server sends the public key too.

The missing 8 bits can be exhaustively searched meaning that multiple primes $\tilde{p}$ should be tested. For each generated prime $\tilde{p}$, compute the discrete logarithm of the public key (with base $g = 3$) and recover (if possible) the Server's secret key. If the found parameters are correct, it should be possible to verify the signature received by the Server. Therefore, the signature verification will act as the oracle to determine whether the correct parameters have been recovered or not.

#### The Goldilock prime

The Goldilock prime gives the possibility to speed up the computation of modular operation. In particular, performing the modular operation with the Goldilock prime is equivalent to a series of shifting operations which are very efficient on hardware.

Let $\delta$ be s.t. $\delta = 2^{64} - 2^{32} +1$.

It is true and easily verifiable that:

$2^{2k} \equiv 2^k -1 \mod{\delta}$

$2^{3k} \equiv -1 \mod{\delta}$

Hence, if a number $x$ is represented by $4k$ bits (where $k = 32$ in this setting), it can be easily reduced modulo $\delta$ by splitting $x$ in its $LSB$ (the least significant bits), $ISB$ (the intermediary significant bits), $MSB$ (the most significant bits).

$x = x_{LSB} + 2^{2k}x_{ISB} + 2^{3k}x_{MSB} \mod{\delta} = x_{LSB} + (2^k-1)x_{ISB} - x_{MSB} \mod{\delta}$

Refer to [this article](https://github.com/ingonyama-zk/papers/blob/main/goldilocks_ntt_trick.pdf) for additional information.

### Exploit

The Server gives the prime with the last 72 bits corrupted and $q = p \mod{\delta}$.

1. Extract $\tilde{p}_{LSB}$ that are the least significant 64 bits which are fully corrupted.
2. Extract $\tilde{p}_{ISB}$ that are the intermediary 32 bits. Here, the last 8 bits are corrupted too.
3. Extract $\tilde{p}_{MSB}$ that are the most significant 32 bits.

Now, the exhaustive search of the missing 8 bits in $\tilde{p}_{ISB}$ must be performed.

For each possible 8 bits value $m$:

1. $`\overline{p}_{ISB} = \tilde{p}_{ISB} \oplus m`$
2. Compute $`t = (2^k-1)\overline{p}_{ISB} = (2^{32} - 1) \overline{p}_{ISB}`$
3. The formula given in the previous section can be rewritten in the following way: $`q = \tilde{p}_{LSB} + t - \tilde{p}_{MSB}`$

4. Obtain $\tilde{p}_{LSB}$ from the previous formula: $`\tilde{p}_{LSB} = q - t + \tilde{p}_{MSB}`$
5. Recreate the value $\tilde{p}$ by combining the correct parts:
   $`\tilde{p} = 2^{96}\tilde{p}_{MSB} + 2^{64}\overline{p}_{ISB} + \tilde{p}_{LSB}`$
6. If $\tilde{p}$ is prime, and the discrete logarithm of the Server's public key
   can be easily computed it is possible to check if the obtained parameters are correct or not by using the `verify signature procedure` as oracle.

Once the correct $p$ and secret key are found, it is possible to forge signatures impersonating the Server. This gives the possibility to send actions to `RoboTank` (`\action` endpoint).

Now it is possible to send the following actions:

- `rfid`
- `photo`
- short, medium, long `forward`
- short, medium, long `backward`
- short, medium, long `left`
- short, medium, long `right`

Thanks to those actions it is possible to move the Robot inside the arena and play a _Minesweeper_ like game.
