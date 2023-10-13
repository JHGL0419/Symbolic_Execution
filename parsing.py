import angr 

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
    
def parse_regs(filename,state):
    f = open(filename, "r", encoding="UTF-8")
    dict = {}
    
    while 1:
        str = f.readline()
        if not str:
            break
        s = str.split()
        if(s[0] == "RAX"):
            # print("RAX")
            # # print(hex(int(s[2],16)))
            dict["RAX"] = int(s[2],16)
            state.regs.rax = int(s[2],16)
        elif(s[0] == "RBX"):
            # print("RBX")
            # # print(hex(int(s[2],16)))
            dict["RBX"] = int(s[2],16)
            state.regs.rbx = int(s[2],16)
        elif(s[0] == "RFLAGS"):
            # print("RFLAGS")
            # # print(hex(int(s[2],16)))
            dict["RFLAGS"] = int(s[2],16)
            state.regs.cc_dep1 = int(s[2],16)
        elif(s[0] == "RCX"):
            # print("RCX")
            # # print(hex(int(s[2],16)))
            dict["RCX"] = int(s[2],16)
            state.regs.rcx = int(s[2],16)
        elif(s[0] == "RDX"):
            # print("RDX")
            # # print(hex(int(s[2],16)))
            dict["RDX"] = int(s[2],16)
            state.regs.rdx = int(s[2],16)
        elif(s[0] == "RBP"):
            # print("RBP")
            # # print(hex(int(s[2],16)))
            dict["RBP"] = int(s[2],16)
            state.regs.rbp = int(s[2],16)
        elif(s[0] == "RSP"):
            # print("RSP")
            # # print(hex(int(s[2],16)))
            dict["RSP"] = int(s[2],16)
            state.regs.rsp = int(s[2],16)
        elif(s[0] == "RSI"):
            # print("RSI")
            # # print(hex(int(s[2],16)))
            dict["RSI"] = int(s[2],16)
            state.regs.rsi = int(s[2],16)
        elif(s[0] == "RDI"):
            # print("RDI")
            # # print(hex(int(s[2],16)))
            dict["RDI"] = int(s[2],16)
            state.regs.rdi = int(s[2],16)
        elif(s[0] == "R8"):
            # print("R8")
            # # print(hex(int(s[2],16)))
            dict["R8"] = int(s[2],16)
            state.regs.r8 = int(s[2],16)
        elif(s[0] == "R9"):
            # print("R9")
            # # print(hex(int(s[2],16)))
            dict["R9"] = int(s[2],16)
            state.regs.r9 = int(s[2],16)
        elif(s[0] == "R10"):
            # print("R10")
            # # print(hex(int(s[2],16)))
            dict["R10"] = int(s[2],16)
            state.regs.r10 = int(s[2],16)
        elif(s[0] == "R11"):
            # print("R11")
            # # print(hex(int(s[2],16)))
            dict["R11"] = int(s[2],16)
            state.regs.r11 = int(s[2],16)
        elif(s[0] == "R12"):
            # print("R12")
            # # print(hex(int(s[2],16)))
            dict["R12"] = int(s[2],16)
            state.regs.r12 = int(s[2],16)
        elif(s[0] == "R13"):
            # print("R13")
            # # print(hex(int(s[2],16)))
            dict["R13"] = int(s[2],16)
            state.regs.r13 = int(s[2],16)
        elif(s[0] == "R14"):
            # print("R14")
            # # print(hex(int(s[2],16)))
            dict["R14"] = int(s[2],16)
            state.regs.r14 = int(s[2],16)
        elif(s[0] == "R15"):
            # print("R15")
            # # print(hex(int(s[2],16)))
            dict["R15"] = int(s[2],16)
            state.regs.r15 = int(s[2],16)
        elif(s[0] == "RIP"):
            # print("RIP")
            # # print(hex(int(s[2],16)))
            dict["RIP"] = int(s[2],16)
            state.regs.rip = int(s[2],16)
    # print(dict)

    # # print(want_bit(dict["RFLAGS"], 1))
    # # print(want_bit(dict["RFLAGS"], 3))
    # # print(want_bit(dict["RFLAGS"], 5))
    # # print(want_bit(dict["RFLAGS"], 7))
    # # print(want_bit(dict["RFLAGS"], 8))
    # # print(want_bit(dict["RFLAGS"], 9))
    # # print(want_bit(dict["RFLAGS"], 10))
    # # print(want_bit(dict["RFLAGS"], 11))
    # # print(want_bit(dict["RFLAGS"], 12))
    
    return dict

def parse_mem(filename, state):
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
        print(state.mem[int(s[0],16)].uint64_t)
    
    return dict