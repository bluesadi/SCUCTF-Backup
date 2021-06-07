import idautils
from ida_bytes import patch_bytes
from idc import *

maze_list = []  #100个迷宫函数的地址
avoid_list = [] #100个迷宫函数中call exit的地址
retn_list = [] #100个迷宫函数的返回地址

for func_addr in idautils.Functions():
    func = idaapi.get_func(func_addr)
    ea = func_addr
    func_name = get_func_name(ea)
    if 'maze' in func_name:
        avoid = []
        while ea < func.end_ea:
            disasm = idc.GetDisasm(ea)
            if 'rdrand' in disasm:
                patch_bytes(ea - 1, b'\x90\x90\x90\x90\x90\x90') #去除rdrand指令
            if 'call' in disasm and 'exit' in disasm: #将call exit指令的地址添加到avoid_list
                avoid.append(ea + 0x400000)
            ea = idc.next_head(ea)
        maze_list.append(func.start_ea + 0x400000)
        avoid_list.append(avoid)
        retn_list.append(func.end_ea + 0x400000 - 1) #注意这里func.end_ea的值实际上是函数末尾地址+1，所以需要-1得到真正的末尾地址

print(f'maze_list={maze_list}\navoid_list={avoid_list}\nretn_list={retn_list}\n')