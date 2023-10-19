import angr
from parsing import *

"""
DLL 주소는 DLL의 aslr 옵션으로 인하여 booting할 때마다 load되는 base주소가 바뀌기 때문에 계속 세팅해주어야 함.
범용 레지스터와 flag레지스터만 테스트 해봄. FPU같은 레지스터는 없어보임.
mscvrt.dll의 EnterCriticalSection에서 ntdll.dll의 RtlEnterCriticalSection으로 넘어갈 때, 주소가 이상함.

"""

load_options = {"auto_load_libs":False, "force_load_libs":['msvcrt.dll', 'ntdll.dll', 'kernel32.dll', 'kernelbase.dll'],
                 "lib_opts":{'msvcrt.dll':{'base_addr':0x00007FFC21DC0000}, 'kernel32.dll':{'base_addr':0x00007FFC21880000}, 'ntdll.dll':{'base_addr':0x00007FFC22550000}, 'kernelbase.dll':{'base_addr':0x00007FFC200A0000}}}

proj = angr.Project("./bin/ctype.exe", load_options=load_options)


print(proj.loader.all_pe_objects)

entry_state = proj.factory.entry_state()
# entry_state.mem[0x7ffc084b7398].uint64_t = 0x00007FFC08E7FAA0   # ntdll.dll RtlEnterCriticalSection로 안넘어가서 추가. 부팅할 때마다 바꿔주기.

list_1 = parse_regs("./regs.txt", entry_state)      # register는 minidump.py에 아직 구현 안된듯.
list_2 = parse_mem("./mem.txt", entry_state)        # stack인데 밑에 처럼 바꾸는게 나을 듯.

# memory load. segment 별로 해줘야 함.
# main_object
parse_dump("./ctype.DMP", 0x140010000, 0x1000, entry_state)  # .data
parse_dump("./ctype.DMP", 0x140011000, 0x2000, entry_state)  # .rdata
parse_dump("./ctype.DMP", 0x140015000, 0x2000, entry_state)  # .bss
# 0x49000 대략 40초 정도 걸린 듯.
# parse_dump("./ctype.DMP", 0x14001a000, 0x49000,entry_state) 

# dll도 위처럼 추가해주면 될 듯.
"""
dll 들어갈 공간...
"""
print("dll : msvcrt.dll")
parse_dump("./ctype.DMP", 0x7FFC21E36000, 0x19000, entry_state) # .rdata
parse_dump("./ctype.DMP", 0x7FFC21E4F000, 0x8000, entry_state) # .data

print("dll : ntdll.dll")
parse_dump("./ctype.DMP", 0x7FFC2266C000, 0x49000, entry_state)
parse_dump("./ctype.DMP", 0x7FFC226B5000, 0xC000, entry_state)


# print("entry_state")
# print(entry_state)
# simgr = proj.factory.simgr(entry_state)

# print("Address: 0x140015030")
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
#     print(found_state)
