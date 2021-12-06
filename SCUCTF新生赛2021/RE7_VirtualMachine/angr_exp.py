import angr

proj = angr.Project('RE7_VirtualMachine.exe', load_options={'auto_load_libs': False})
proj.hook(addr=0x00413210, hook=angr.SIM_PROCEDURES['stubs']['Nop']())      # __CheckForDebuggerJustMyCode
proj.hook(addr=0x004131E0, hook=angr.SIM_PROCEDURES['stubs']['Nop']())      # j___RTC_CheckEsp
proj.hook(addr=0x00411037, hook=angr.SIM_PROCEDURES['libc']['scanf']())
proj.hook(addr=0x004110E6, hook=angr.SIM_PROCEDURES['libc']['printf']())
proj.hook_symbol('putchar', angr.SIM_PROCEDURES['libc']['putchar']())
proj.hook_symbol('exit', angr.SIM_PROCEDURES['libc']['exit']())
proj.hook_symbol('puts', angr.SIM_PROCEDURES['libc']['puts']())
proj.hook_symbol('memset', angr.SIM_PROCEDURES['libc']['memset']())
proj.hook_symbol('strlen', angr.SIM_PROCEDURES['libc']['strlen']())
proj.hook_symbol('malloc', angr.SIM_PROCEDURES['libc']['malloc']())

state = proj.factory.blank_state(addr=proj.loader.find_symbol('main_0'))
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

simgr = proj.factory.simgr(state)
while len(simgr.active):
    print(simgr)
    for active in simgr.active:
        print(active.posix.dumps(1))
        if b'Correct' in active.posix.dumps(1):
            print(active.posix.dumps(0))
            exit(0)
    simgr.step()