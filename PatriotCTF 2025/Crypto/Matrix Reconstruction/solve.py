#! /usr/bin/env python3

nums = open("keystream_leak.txt", "r").read().splitlines()
nums = list(map(int, nums))
cypher = list(open("cipher.txt", "rb").read())
flag = [(num & 255) ^ b for num, b in zip(nums, cypher)]
print(bytes(flag))
