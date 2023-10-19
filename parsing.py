import angr 
import os
from minidump.minidumpfile import MinidumpFile
from minidump.common_structs import hexdump
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE

"""
 register구조를 살펴보니
   OF  DF  IF  TF | SF  ZF  0   AF  |  0   PF  0   CF
    1   0   0   0    1   1  0    1     0    1  0    1    (1인 것만 set가능 한 듯.) 0xfff로 바꿨을 때 8d5나옴.
 보통 1bit자리에는 1이 들어가는데 angr에서는 0으로 정한듯. 
 (아무 용도 없이 reserved된 자리라서 상관없는 듯.)

def want_bit(i, num):
    masking = 2**(num-1)
    i = i & masking
    i = i >> (num-1)
    
    return i
"""

# hex값인지 check
def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

# dbg에서 가져온 dll에 대한 force_load_libs, lib_opts 값 return
def parse_dlls(filename):
    f = open(filename, "r", encoding="UTF-8")
    dll_list = []
    dll_addr = {}
    while 1:
        str = f.readline()
        if not str:
            break
        s = str.split()
        if len(s) < 4:
            break

        if not ".dll" in s[3]:
            continue
        
        base_addr = {"base_addr" : int(s[0], 16)}
        dll_list.append(s[3])
        dll_addr[s[3]] = base_addr
        # print(f"{s[3]} : {s[0]}")
        print("parse_dlls")


    f.close()
    return dll_list, dll_addr

# register값 parsing (x64)
def parse_regs(filename, state):
    f = open(filename, "r", encoding="UTF-8")
    dict = {}
    
    while 1:
        str = f.readline()
        if not str:
            break
        s = str.split()
        list = ["RAX", "RBX", "RCX", "RDX", "RBP", "RSP", "RSI", "RDI",
                "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP", "RFLAGS"]
        if s[0] in list:
            dict[s[0]] = int(s[2],16)    
    
    # WHILE후 dict에서 꺼내주기.    
    state.regs.rax = dict["RAX"]
    state.regs.rbx = dict["RBX"]
    state.regs.rcx = dict["RCX"]
    state.regs.rdx = dict["RDX"]
    state.regs.rbp = dict["RBP"]
    state.regs.rsp = dict["RSP"]
    state.regs.rsi = dict["RSI"]
    state.regs.rdi = dict["RDI"]
    state.regs.r8 = dict["R8"]
    state.regs.r9 = dict["R9"]
    state.regs.r10 = dict["R10"]
    state.regs.r11 = dict["R11"]
    state.regs.r12 = dict["R12"]
    state.regs.r13 = dict["R13"]
    state.regs.r14 = dict["R14"]
    state.regs.r15 = dict["R15"]
    state.regs.rip = dict["RIP"]
    state.regs.flags = dict["RFLAGS"]

    f.close()
    return dict

# register값 parsing (x32)
def parse_regs_32(filename, state):
    f = open(filename, "r", encoding="UTF-8")
    dict = {}
    
    while 1:
        str = f.readline()
        if not str:
            break
        s = str.split()
        list = ["EAX", "EBX", "ECX", "EDX", "EBP", "ESP", "ESI", "EDI",
                 "EIP", "EFLAGS"]
        if s[0] in list:
            dict[s[0]] = int(s[2],16)    
    
    # WHILE후 dict에서 꺼내주기.    
    state.regs.eax = dict["EAX"]
    state.regs.ebx = dict["EBX"]
    state.regs.ecx = dict["ECX"]
    state.regs.edx = dict["EDX"]
    state.regs.ebp = dict["EBP"]
    state.regs.esp = dict["ESP"]
    state.regs.esi = dict["ESI"]
    state.regs.edi = dict["EDI"]
    state.regs.rip = dict["EIP"]
    state.regs.flags = dict["EFLAGS"]

    f.close()
    return dict

# txt로 parsing할 시 사용
def parse_mem_text(filename, state):
    dict = {}
    f = open(filename, "r", encoding="UTF-8")
    while 1:
        str = f.readline()
        if not str:
            break
        
        s = str.split()
        
        dict[s[0]] = int(s[1],16)
        # print(int(s[0],16))
        state.mem[int(s[0],16)].uint64_t = int(s[1],16)
        # print(state.mem[int(s[0],16)].uint64_t)
    
    f.close()

    return dict 

# .DMP파일로 parsing할 시 사용
def parse_mem_minidump(filename, seg_addr, seg_size, state):
    res_list = mem_dump(filename, seg_addr, seg_size)
    
    for str in res_list:
        # if str == "\n":
        #     continue

        split_str = str.split()
        # print(split_str)

        base_addr = split_str[0].split("(")[0]
        if not is_hex(base_addr):
            continue

        for i in range(0, 16):
            address = int(base_addr,16) + i
            value = int(split_str[i+1], 16)
            # print(f"addr: {hex(address)}, value: {hex(value)}", end=" ")
            state.mem[address].uint64_t = value
            
    # 종료 후 file 삭제.
    print(f"Success memory load [addr: {hex(seg_addr)}, size: {hex(seg_size)}]")

# alias parse_mem_minidump
def parse_dump(filename, seg_addr, seg_size, state):
    parse_mem_minidump(filename, seg_addr, seg_size, state)

# minudump 사용 위한 함수
def mem_dump(filename, seg_addr, seg_size):
    mf = MinidumpFile.parse(filename)
    reader = mf.get_reader()

    buff_reader = reader.get_buffered_reader()
    buff_reader.move(seg_addr)
    data = buff_reader.peek(seg_size)
    res = hexdump(data, start=seg_addr)
    res_list = res.split("\n")

    return res_list

def reg_dump(filename, state):
    mf = MinidumpFile.parse(filename)
    threads = mf.threads.threads    # thread list
    target_thread = None
    # 현재 ip를 가지는 애를 찾기 => state의 ip이용
    ip = 0x1400013f0
    arch = ""
    # x64
    if mf.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
        arch = "x64"
        for t in threads:
            if ip == t.ContextObject.Rip:
                target_thread = t
    
    # x32
    elif mf.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.INTEL:
        arch = "x32"
        for t in threads:
            if ip == t.ContextObject.Eip:
                target_thread = t
    
    if target_thread is None:
        raise Exception("target_thread is None...")
    
    context = target_thread.ContextObject
    regs = state.regs

    if arch == "x64":
        regs.rax = context.Rax
        regs.rbx = context.Rbx
        regs.rcx = context.Rcx
        regs.rdx = context.Rdx
        regs.rsp = context.Rsp
        regs.rbp = context.Rbp
        regs.rsi = context.Rsi
        regs.rdi = context.Rdi
        regs.r8 = context.R8
        regs.r9 = context.R9
        regs.r10 = context.R10
        regs.r11 = context.R11
        regs.r12 = context.R12
        regs.r13 = context.R13
        regs.r14 = context.R14
        regs.r15 = context.R15
        regs.rip = context.Rip
        regs.flags = context.EFlags

    else:
        regs.eax = context.Eax
        regs.ebx = context.Ebx
        regs.ecx = context.Ecx
        regs.edx = context.Edx
        regs.esp = context.Esp
        regs.ebp = context.Ebp
        regs.esi = context.Esi
        regs.edi = context.Edi
        regs.e8 = context.E8
        regs.e9 = context.E9
        regs.e10 = context.E10
        regs.e11 = context.E11
        regs.e12 = context.E12
        regs.e13 = context.E13
        regs.e14 = context.E14
        regs.e15 = context.E15
        regs.eip = context.Eip
        regs.flags = context.EFlags
    
    print("Load regs done.")
    

# for debugging.
def printAllRegs(state):
    print(state.regs.rax)
    print(state.regs.rbx)
    print(state.regs.rcx)
    print(state.regs.rdx)
    print(state.regs.rbp)
    print(state.regs.rsp)
    print(state.regs.rsi)
    print(state.regs.rdi)
    print(state.regs.r8)
    print(state.regs.r9)
    print(state.regs.r10)
    print(state.regs.r11)
    print(state.regs.r12)
    print(state.regs.r13)
    print(state.regs.r14)
    print(state.regs.r15)
    print(state.regs.rip)
    print(state.regs.rflags)
