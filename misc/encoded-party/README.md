# Encoded party [_snakeCTF 2024 Quals_]

**Category**: misc

## Description

Traffic exchanged via USB, first from a keyboard and then from a DJ console, is captured and stored in `party_info.pcap` \
The goal is to get the flag written using the DJ console, according to the dictionary written by the keyboard.

## Solution

### Understanding the Capture

It is observed that in **packet 43**, a new USB device is connected.

In **packet 44**, the `idVendor` field reveals the vendor as **Adafruit**, identifying the device as a **Raspberry Pi Pico**.

USB keystrokes that made up the dictionary were recorded between **packets 119** and **4472**.

In **packet 4508**, the `bString` field of the string descriptor of a new device shows the value **'DDJ-400'**. This indicates that the new device is a **Pioneer DJ console**, specifically the **DDJ-400**.

From **packet 4551** the **DDJ-400** start transmitting the hidden flag.

### Identifying the Endpoints

The **Raspberry Pi Pico** is programmed to function as a **Human Interface Device (HID)**, emulating a keyboard. This device automatically types a dictionary that maps **Base32 characters** to corresponding keys on the **DDJ-400** console.

The **DDJ-400** is a DJ controller by Pioneer. It features jog wheels, a mixer, and performance pads. It sends **MIDI** signals to control digital music on a connected computer.

Subsequently, packets from the DJ console are transferred. By consulting the [Pioneer documentation](https://www.pioneerdj.com/-/media/pioneerdj/software-info/controller/ddj-400/ddj-400_midi_message_list_e1.pdf) for the DDJ-400, the pressed keys can be interpreted.

It is assumed that the flag will be entered and transferred via one of these USB devices.

### Keyboard Decoding

Upon analysing the traffic from the keyboard, it is revealed that the keyboard sends a dictionary mapping **alphabet characters** to keys on the **DDJ-400**.\
A [Python script](./attachments/keyboard_decoding.py) can be written or adapted to parse the PCAP file, extracting USB keyboard events and interpreting the **HID report data** to build this dictionary.

```
A -> LOAD
B -> PLAY
C -> CUE
D -> BEAT SYNC
E -> LOOP IN/4BEAT
F -> LOOP OUT
G -> RELOOP/EXIT
H -> SHIFT
I -> PAD1 HOT CUE MODE
J -> PAD1 BEAT LOOP MODE
K -> PAD1 BEAT JUMP MODE
L -> PAD1 SAMPLER MODE
M -> PAD2 HOT CUE MODE
N -> PAD2 BEAT LOOP MODE
O -> PAD2 BEAT JUMP MODE
P -> PAD2 SAMPLER MODE
Q -> PAD3 HOT CUE MODE
R -> PAD3 BEAT LOOP MODE
S -> PAD3 BEAT JUMP MODE
T -> PAD3 SAMPLER MODE
U -> PAD4 HOT CUE MODE
V -> PAD4 BEAT LOOP MODE
W -> PAD4 BEAT JUMP MODE
X -> PAD4 SAMPLER MODE
Y -> PAD5 HOT CUE MODE
Z -> PAD5 BEAT LOOP MODE
= -> PAD5 BEAT JUMP MODE
2 -> PAD6 HOT CUE MODE
3 -> PAD6 BEAT LOOP MODE
4 -> PAD6 BEAT JUMP MODE
5 -> PAD6 SAMPLER MODE
6 -> PAD7 HOT CUE MODE
7 -> PAD7 BEAT LOOP MODE
```

### DDJ-400 Decoding

Using the official [Pioneer documentation](https://www.pioneerdj.com/-/media/pioneerdj/software-info/controller/ddj-400/ddj-400_midi_message_list_e1.pdf), a [Python script](./attachments/ddj-400_decoding.py) can be written to decode the keys pressed on the DJ console by inspecting the values in the **MIDI Event field** and comparing them with the one in the documentation.

```
     DECK_1-DECK_2
A -> 0x9646-0x9647 -> LOAD
B -> 0x900b-0x910b -> PLAY
C -> 0x900c-0x910c -> CUE
D -> 0x9058-0x9158 -> BEAT SYNC
E -> 0x9010-0x9110 -> LOOP IN/4BEAT
F -> 0x9011-0x9111 -> LOOP OUT
G -> 0x904d-0x914d -> RELOOP/EXIT
H -> 0x903f-0x913f -> SHIFT
I -> 0x9700-0x9900 -> PAD1 HOT CUE MODE
J -> 0x9760-0x9960 -> PAD1 BEAT LOOP MODE
K -> 0x9720-0x9920 -> PAD1 BEAT JUMP MODE
L -> 0x9730-0x9930 -> PAD1 SAMPLER MODE
M -> 0x9701-0x9901 -> PAD2 HOT CUE MODE
N -> 0x9761-0x9961 -> PAD2 BEAT LOOP MODE
O -> 0x9721-0x9921 -> PAD2 BEAT JUMP MODE
P -> 0x9731-0x9931 -> PAD2 SAMPLER MODE
Q -> 0x9702-0x9902 -> PAD3 HOT CUE MODE
R -> 0x9762-0x9962 -> PAD3 BEAT LOOP MODE
S -> 0x9722-0x9922 -> PAD3 BEAT JUMP MODE
T -> 0x9732-0x9932 -> PAD3 SAMPLER MODE
U -> 0x9703-0x9903 -> PAD4 HOT CUE MODE
V -> 0x9763-0x9963 -> PAD4 BEAT LOOP MODE
W -> 0x9723-0x9923 -> PAD4 BEAT JUMP MODE
X -> 0x9733-0x9933 -> PAD4 SAMPLER MODE
Y -> 0x9704-0x9904 -> PAD5 HOT CUE MODE
Z -> 0x9764-0x9964 -> PAD5 BEAT LOOP MODE
= -> 0x9724-0x9924 -> PAD5 BEAT JUMP MODE
2 -> 0x9705-0x9905 -> PAD6 HOT CUE MODE
3 -> 0x9765-0x9965 -> PAD6 BEAT LOOP MODE
4 -> 0x9725-0x9925 -> PAD6 BEAT JUMP MODE
5 -> 0x9735-0x9935 -> PAD6 SAMPLER MODE
6 -> 0x9706-0x9906 -> PAD7 HOT CUE MODE
7 -> 0x9766-0x9966 -> PAD7 BEAT LOOP MODE
```

### Extracting the flag

After processing the output of the second script, it becomes apparent that the result is encoded.\
To decode the flag from **Base32**, the following Python script can be used:

```python
from base64 import b32decode
print(b32decode(flag_base32.encode()).decode('utf-8'))
```
