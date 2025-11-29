#! /usr/bin/env python3

import math


def int_to_bytes_auto(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8  # số byte tối thiểu
    return n.to_bytes(length, "big")


file = "encrypted"

with open(file, "rb") as f:
    data = f.read()

ss = int.from_bytes(data, "big")  # đưa về int

o = ((6, 0, 7), (8, 2, 1), (5, 4, 3))

# đảo ngược o
index_o = {}
for hi in range(3):
    for lo in range(3):
        v = o[hi][lo]  # digit ở hệ 9
        index_o[v] = (hi, lo)  # Ngược: digit -> (hi, lo)

# Tách từng digit base-9
digits9 = []
x = ss
while x > 0:
    x, d = divmod(x, 9)
    digits9.append(d)

digits9 = digits9[::-1]

# từ digit base-9 -> (hi,lo)
his = []
los = []
for v in digits9:
    hi, lo = index_o[v]  # Map ngược
    his.append(hi)
    los.append(lo)

# Ghép digit base-3
digits3 = his + los[::-1]

# Từ digit base-3 -> số nguyên base-10
s = 0
for d in digits3:
    s = s * 3 + d

b = int_to_bytes_auto(s)
flag = b.decode()

print(flag)
