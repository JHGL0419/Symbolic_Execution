import angr
import parsing

"""
DLL 주소는 DLL의 aslr 옵션으로 인하여 booting할 때마다 load되는 base주소가 바뀌기 때문에 계속 세팅해주어야 함.
범용 레지스터와 flag레지스터만 테스트 해봄. FPU같은 레지스터는 없어보임.
mscvrt.dll의 EnterCriticalSection에서 ntdll.dll의 RtlEnterCriticalSection으로 넘어갈 때, 주소가 이상함.

"""

load_options = {"auto_load_libs":False, "force_load_libs":['msvcrt.dll', 'ntdll.dll', 'kernel32.dll', 'kernelbase.dll'],
                 "lib_opts":{'msvcrt.dll':{'base_addr':0x00007FFC08440000}, 'kernel32.dll':{'base_addr':0x00007FFC08740000}, 'ntdll.dll':{'base_addr':0x00007FFC08E50000}, 'kernelbase.dll':{'base_addr':0x00007FFC06A60000}}}

proj = angr.Project("./bin/ctype.exe", load_options=load_options)


print(proj.loader.all_pe_objects)

entry_state = proj.factory.entry_state()
# entry_state.mem[0x7ffc084b7398].uint64_t = 0x00007FFC08E7FAA0   # ntdll.dll RtlEnterCriticalSection로 안넘어가서 추가. 부팅할 때마다 바꿔주기.

list_1 = parsing.parse_regs("./regs.txt", entry_state)
list_2 = parsing.parse_mem("./mem.txt", entry_state)

parsing.parse_mem_minidump("./ctype.DMP", 0x140010000, 0x1000,entry_state)
parsing.parse_mem_minidump("./ctype.DMP", 0x140011000, 0x4000,entry_state)
parsing.parse_mem_minidump("./ctype.DMP", 0x140015000, 0x1000,entry_state)
parsing.parse_mem_minidump("./ctype.DMP", 0x140010000, 0x1000,entry_state)
parsing.parse_mem_minidump("./ctype.DMP", 0x140010000, 0x1000,entry_state)


# print(entry_state.regs.rax)
# print(entry_state.regs.rbx)
# print(entry_state.regs.rcx)
# print(entry_state.regs.rdx)
# print(entry_state.regs.rbp)
# print(entry_state.regs.rsp)
# print(entry_state.regs.rsi)
# print(entry_state.regs.rdi)
# print(entry_state.regs.r8)
# print(entry_state.regs.r9)
# print(entry_state.regs.r10)
# print(entry_state.regs.r11)
# print(entry_state.regs.r12)
# print(entry_state.regs.r13)
# print(entry_state.regs.r14)
# print(entry_state.regs.r15)
# print(entry_state.regs.rip)
# print(entry_state.regs.rflags)

print("entry_state")
print(entry_state)
# simgr = proj.factory.simgr(entry_state)

print("Address: 0x140015030")
print(entry_state.mem[0x140015030].uint64_t)
# print(entry_state.mem[0x140015030].uint64_t)
# simgr.explore(find=0x00007FFC0847B07D)   # scanf안에서 무언가 오류. 값 바꿔서 그런거는 아님.

# proj.factory.block(simgr.found[0].addr).pp()
# print(simgr.found[0].mem[0x7ffc084b7398].uint64_t)
# simgr = proj.factory.simgr(simgr.found[0])
# simgr.step()
# print(hex(simgr.active[0].addr))
# proj.factory.block(simgr.active[0].addr).pp()

# simgr.explore(find=0x140001610)

# if simgr.found:
#     print("found:")
#     found_state = simgr.found[0]
#     proj.factory.block(found_state.addr).pp()
# #    print("mem[140015030]:" + str(found_state.mem[0x140015030].uint64_t))
#     print(found_state.mem[0x140015030].uint64_t)
#     print(found_state.regs.rax)
#     print(found_state.regs.rbx)
#     print(found_state.regs.rcx)
#     print(found_state.regs.rdx)
#     print(found_state.regs.rbp)
#     print(found_state.regs.rsp)
#     print(found_state.regs.rsi)
#     print(found_state.regs.rdi)
#     print(found_state.regs.r8)
#     print(found_state.regs.r9)
#     print(found_state.regs.r10)
#     print(found_state.regs.r11)
#     print(found_state.regs.r12)
#     print(found_state.regs.r13)
#     print(found_state.regs.r14)
#     print(found_state.regs.r15)
#     print(found_state.regs.rip)
#     print(found_state.regs.rflags)
#     print(found_state)
