import os
import random
import platform
import ctypes


# only works on linux
libc = ctypes.cdll.LoadLibrary("libc.so.6")
#libc = ctypes.cdll.LoadLibrary("libc.{}".format("so.6" if platform.uname()[0] != "Darwin" else "dylib"))

with open("./rev_simpleencryptor/flag.enc", "rb") as f:
    flag_data = f.read()

flag_size = len(flag_data)
seed = int.from_bytes(flag_data[:4], byteorder="little")
print(f'{seed=}')
libc.srand(seed)


flag = ''

for i in range(4, flag_size):
    rnd1 = libc.rand()
    rnd2 = libc.rand()
    rnd2 = rnd2 & 7;

    flag_byte = flag_data[i]
    flag_byte = flag_byte >> rnd2 | flag_byte << (8 - rnd2)
    flag_byte = (flag_byte & 0xFF) ^ (rnd1 & 0xFF)
    flag = flag + chr(flag_byte)

print(flag)

