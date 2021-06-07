import angr
import claripy

proj = angr.Project('./overflow', load_options={'auto_load_libs': False})
input_addr = 0x6029A0

table = claripy.BVS('table', 32 * 8)
state = proj.factory.blank_state(addr=0x400EEA)
for i in range(32):
    state.mem[input_addr + i].byte = i
simgr = proj.factory.simgr(state)
simgr.explore(find=0x401EF0)
found = simgr.found[0]
table = '['
for i in range(32):
    table += str(found.mem[input_addr + i].byte.concrete)
    table += ', ' if i != 31 else ']'
print(table)