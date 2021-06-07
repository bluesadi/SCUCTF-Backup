shellcode = ''
for c in 'Input:':
    shellcode += '4'
    shellcode += str(ord(c)).zfill(3)
shellcode += '6'
for i in range(1,28):
    shellcode += '1'
    shellcode += str(i - 1).zfill(2)
    shellcode += str(i).zfill(2)
xorarr = [41,61,76,34,58,14,5,98,39,84,64,63,69,14,52,86,13,78,75,87,80,65,79,69,76,2,76]
for i in range(27):
    shellcode += '2'
    shellcode += str(i).zfill(2)
    shellcode += str(xorarr[i]).zfill(2)
result = [93, 88, 52, 69, 67, 98, 135, 24, 89, 56, 196, 84, 123, 143, 90, 223, 76, 201, 206, 36, 43, 201, 7, 14, 203, 124, 212]
for i in range(27):
    shellcode += '5'
    shellcode += str(i).zfill(2)
    shellcode += str(result[i]).zfill(3)

shellcode += '78'
for c in 'OK':
    shellcode += '4'
    shellcode += str(ord(c)).zfill(3)

print(shellcode)