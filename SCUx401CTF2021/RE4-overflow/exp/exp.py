from Crypto.Cipher import ARC4
from binascii import a2b_hex, b2a_hex
from pytea import *

table = [24, 12, 18, 15, 11, 30, 27, 1, 19, 9, 23, 28, 22, 20, 4, 6, 26, 3, 31, 14, 25, 5, 0, 13, 8, 17, 7, 10, 2, 29, 16, 21]
enc = a2b_hex('7DB937E43FF10A83F555CA5C32D47D47180C21130D15F15B138B357B725D6237')
flag = bytearray()
for i in range(len(table)):
    flag.append(enc[table.index(i)])
flag = ARC4.new(key=a2b_hex('26148D621EF74844918AF182D63976B6')).decrypt(flag)
flag = TEA(key=a2b_hex('94FA3E5538D57F71937A85076E96FBC5')).Decrypt(flag)
print(flag)