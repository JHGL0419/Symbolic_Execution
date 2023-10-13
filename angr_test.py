import angr
import claripy
import parsing

"""
DLL 주소는 DLL의 aslr 옵션으로 인하여 booting할 때마다 load되는 base주소가 바뀌기 때문에 계속 세팅해주어야 함.
범용 레지스터와 flag레지스터만 테스트 해봄. FPU같은 레지스터는 없어보임.
flag 레지스터는 바로 저장하는 게 아니라는데... cc_op, cc_dep1를 이용한다함...
"""

load_options = {"auto_load_libs":False, "force_load_libs":['msvcrt.dll', 'ntdll.dll', 'kernel32.dll'],
                 "lib_opts":{'msvcrt.dll':{'base_addr':0x00007FFC08440000}, 'kernel32.dll':{'base_addr':0x00007FFC08740000}, 'ntdll.dll':{'base_addr':0x00007FFC08E50000}, 'kernelbase.dll':{'base_addr':0x00007FFC06A60000}}}
proj = angr.Project("./bin/ctype.exe", load_options=load_options)
# proj = angr.Project("./bin/ctype.exe", use_sim_procedures=True)
password_0 = claripy.BVS("password0", 64)

print(proj.loader.all_pe_objects)

entry_state = proj.factory.entry_state()

list_1 = parsing.parse_regs("./regs.txt", entry_state)
list_2 = parsing.parse_mem("./mem.txt", entry_state)

print(entry_state.regs.rax)
print(entry_state.regs.rbx)
print(entry_state.regs.rcx)
print(entry_state.regs.rdx)
print(entry_state.regs.rbp)
print(entry_state.regs.rsp)
print(entry_state.regs.rsi)
print(entry_state.regs.rdi)
print(entry_state.regs.r8)
print(entry_state.regs.r9)
print(entry_state.regs.r10)
print(entry_state.regs.r11)
print(entry_state.regs.r12)
print(entry_state.regs.r13)
print(entry_state.regs.r14)
print(entry_state.regs.r15)
print(entry_state.regs.rip)
print(entry_state.regs.rflags)

simgr = proj.factory.simgr(entry_state)
simgr.explore(find=0x00000001400014)   # scanf안에서 무언가 오류. 값 바꿔서 그런거는 아님.

if simgr.found:
    found_state = simgr.found[0]
    print(found_state.regs.rax)
    print(found_state)
    solution0 = found_state.solver.eval(password_0)
    print(solution0)

